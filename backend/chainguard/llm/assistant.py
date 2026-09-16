"""AI security consultant — the dashboard's AI chat panel.

Unlike ``explain.py`` (one fixed paragraph per flagged package), this is a
conversational agent that can *look things up*: it is given read-only tools over
stored scan results, per-package evidence, vulnerability reachability, the model
card and the server's recent log lines, and uses them to answer questions such as
"why was this package flagged?", "is this a false positive?" or "what should I
fix first?".

The same principles as the explanation layer hold:

* **It never changes a verdict or a stored result.** Every tool is read-only.
* **It is optional.** No API key means the endpoint reports itself unavailable;
  scanning is unaffected.
* **Only analysis output is sent, never package source.** Tools return the
  findings the analyser already extracted (signal codes, file:line, short
  evidence snippets), trimmed to keep each tool result small.
"""

from __future__ import annotations

import collections
import json
import logging
import threading
import time
from typing import Any, Iterator, Optional

from chainguard.config import get_settings
from chainguard.logging_setup import get_logger

logger = get_logger(__name__)

MAX_TOOL_ROUNDS = 12


# --------------------------------------------------------------------------- #
# In-memory log buffer, so the assistant can read recent server logs.
# --------------------------------------------------------------------------- #

class LogBuffer(logging.Handler):
    """Keeps the most recent log records in a bounded ring buffer."""

    def __init__(self, capacity: int = 3000) -> None:
        super().__init__(level=logging.DEBUG)
        self._records: collections.deque[dict[str, Any]] = collections.deque(maxlen=capacity)
        self._lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 — a bad format string must not break logging
            message = str(record.msg)
        entry = {
            "time": time.strftime("%H:%M:%S", time.localtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": message[:2000],
        }
        with self._lock:
            self._records.append(entry)

    def query(self, min_level: str = "INFO", contains: Optional[str] = None, limit: int = 100) -> list[dict[str, Any]]:
        threshold = logging.getLevelName(min_level.upper())
        if not isinstance(threshold, int):
            threshold = logging.INFO
        needle = contains.lower() if contains else None
        with self._lock:
            records = list(self._records)
        matched = [
            r for r in records
            if logging.getLevelName(r["level"]) >= threshold
            and (needle is None or needle in r["message"].lower() or needle in r["logger"].lower())
        ]
        return matched[-max(1, min(limit, 500)):]


LOG_BUFFER = LogBuffer()
_INSTALLED = False


def install_log_buffer() -> None:
    """Attach the buffer to the root logger and uvicorn's loggers (idempotent)."""
    global _INSTALLED
    if _INSTALLED:
        return
    logging.getLogger().addHandler(LOG_BUFFER)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        if not lg.propagate:
            lg.addHandler(LOG_BUFFER)
    _INSTALLED = True


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #

def _load_scan(scan_id: str) -> Optional[dict[str, Any]]:
    # Imported lazily: the API module imports this one.
    from chainguard.api.jobs import result_payload
    from chainguard.api.jobs import registry
    from chainguard.models.db import load_scan

    job = registry.get(scan_id)
    if job is not None and job.result is not None:
        return result_payload(job.result)
    return load_scan(scan_id)


def _latest_scan_id() -> Optional[str]:
    from chainguard.models.db import list_scans

    scans = list_scans(1)
    return scans[0]["scan_id"] if scans else None


def _brief_package(p: dict[str, Any]) -> dict[str, Any]:
    strong = [s["code"] for s in p.get("signals", []) if s.get("severity") in ("critical", "high")]
    return {
        "name": p["name"],
        "version": p["version"],
        "verdict": p.get("verdict"),
        "malice_score": round(p.get("malice_score") or 0, 3),
        "depth": p.get("depth"),
        "is_direct": p.get("is_direct"),
        "files_analysed": p.get("files_analysed"),
        "top_contributors": (p.get("top_contributors") or [])[:5],
        "critical_or_high_signals": strong[:8],
        "signal_count": len(p.get("signals") or []),
        "typosquat_target": p.get("typosquat_target"),
        "confirmed_exfiltration_flows": len(p.get("exfiltration") or []),
    }


def tool_list_scans(limit: int = 10) -> Any:
    from chainguard.models.db import list_scans

    return {"scans": list_scans(max(1, min(int(limit), 50)))}


def tool_get_scan_summary(scan_id: Optional[str] = None) -> Any:
    scan_id = scan_id or _latest_scan_id()
    if not scan_id:
        return {"error": "No scans stored yet."}
    data = _load_scan(scan_id)
    if data is None:
        return {"error": f"No completed scan with id {scan_id}."}
    packages = data.get("packages") or []
    flagged = sorted(
        (p for p in packages if p.get("verdict") in ("malicious", "suspicious")),
        key=lambda p: -(p.get("malice_score") or 0),
    )
    unanalysed = [f"{p['name']}@{p['version']}" for p in packages if p.get("analysis_error") or not p.get("files_analysed")]
    return {
        "scan_id": scan_id,
        "target": data.get("target"),
        "ecosystem": data.get("ecosystem"),
        "duration_seconds": data.get("duration_seconds"),
        "model_source": data.get("model_source"),
        "summary": data.get("summary"),
        "warnings": (data.get("warnings") or [])[:20],
        "errors": (data.get("errors") or [])[:20],
        "flagged_packages": [_brief_package(p) for p in flagged[:40]],
        "flagged_total": len(flagged),
        "not_inspected_total": len(unanalysed),
        "not_inspected_sample": unanalysed[:20],
        "remediation_top": (data.get("remediation") or [])[:8],
    }


def tool_get_package_details(package: str, scan_id: Optional[str] = None) -> Any:
    scan_id = scan_id or _latest_scan_id()
    data = _load_scan(scan_id) if scan_id else None
    if data is None:
        return {"error": f"No completed scan with id {scan_id}."}
    wanted = package.strip().lower()
    name, version = wanted, ""
    # A version separator is an "@" that is not the leading scope marker.
    if "@" in wanted[1:]:
        at = wanted.rindex("@")
        name, version = wanted[:at], wanted[at + 1:]
    for p in data.get("packages") or []:
        if p["name"].lower() == name and (not version or p["version"].lower() == version):
            detail = dict(p)
            detail["signals"] = [
                {k: s.get(k) for k in ("code", "severity", "category", "detail", "file", "line", "occurrences", "evidence")}
                for s in (p.get("signals") or [])[:40]
            ]
            vulns = p.get("vulnerabilities") or []
            detail["vulnerabilities"] = [
                {k: v.get(k) for k in ("id", "cve_id", "severity", "cvss_score", "summary", "reachable",
                                       "reachability_verdict", "reachability_reason", "fixed_version", "call_path")}
                for v in vulns[:25]
            ]
            detail["vulnerability_total"] = len(vulns)
            return {"scan_id": scan_id, "package": detail}
    return {"error": f"Package '{package}' is not in scan {scan_id}."}


def tool_list_vulnerabilities(scan_id: Optional[str] = None, reachable: Optional[bool] = None, limit: int = 40) -> Any:
    scan_id = scan_id or _latest_scan_id()
    data = _load_scan(scan_id) if scan_id else None
    if data is None:
        return {"error": f"No completed scan with id {scan_id}."}
    rows = []
    for p in data.get("packages") or []:
        for v in p.get("vulnerabilities") or []:
            if reachable is not None and bool(v.get("reachable")) != reachable:
                continue
            rows.append({
                "package": f"{p['name']}@{p['version']}",
                "id": v.get("cve_id") or v.get("id"),
                "severity": v.get("severity"),
                "cvss": v.get("cvss_score"),
                "reachable": v.get("reachable"),
                "verdict": v.get("reachability_verdict"),
                "reason": v.get("reachability_reason"),
                "call_path_length": len(v.get("call_path") or []),
                "fixed_version": v.get("fixed_version"),
            })
    rows.sort(key=lambda r: (not r["reachable"], -(r["cvss"] or 0)))
    return {"scan_id": scan_id, "total": len(rows), "vulnerabilities": rows[: max(1, min(int(limit), 150))]}


def tool_get_model_card() -> Any:
    from chainguard.api.jobs import registry

    classifier = registry.classifier
    if not classifier.is_trained or classifier.metadata is None:
        return {"trained": False, "detector": "rules-baseline"}
    card = {"trained": True, **classifier.metadata.to_dict()}
    slim = {k: v for k, v in card.items() if k not in ("curves", "per_fold")}
    if isinstance(slim.get("feature_importances"), list):
        slim["feature_importances"] = slim["feature_importances"][:20]
    for key in ("cv_metrics", "metrics"):
        if isinstance(slim.get(key), dict):
            slim[key] = {k: v for k, v in slim[key].items() if k != "per_fold"}
    return slim


def tool_read_logs(min_level: str = "INFO", contains: Optional[str] = None, limit: int = 80) -> Any:
    records = LOG_BUFFER.query(min_level=min_level, contains=contains, limit=int(limit))
    return {"count": len(records), "records": records}


def tool_get_scan_status(scan_id: str) -> Any:
    from chainguard.api.jobs import registry

    job = registry.get(scan_id)
    if job is None:
        return {"error": f"No running or in-memory scan with id {scan_id} (it may be in history)."}
    return job.to_dict()


def _brief_review(p: dict[str, Any]) -> Optional[dict[str, Any]]:
    review = p.get("ai_review")
    if not review:
        return None
    return {k: review.get(k) for k in ("verdict", "confidence", "reasoning", "recommendation")}


def tool_package_history(package: str, ecosystem: Optional[str] = None) -> Any:
    """Every stored scan that contained a package, newest first."""
    from chainguard.models.db import list_scans

    wanted = package.strip().lower()
    if "@" in wanted[1:]:
        wanted = wanted[: wanted.rindex("@")]
    hits = []
    for scan in list_scans(200):
        data = _load_scan(scan["scan_id"])
        for p in (data or {}).get("packages") or []:
            if p["name"].lower() != wanted:
                continue
            if ecosystem and p.get("ecosystem", "").lower() != ecosystem.lower():
                continue
            vulns = p.get("vulnerabilities") or []
            hits.append({
                "scan_id": scan["scan_id"],
                "scanned_at": scan.get("created_at"),
                "scan_target": scan.get("target"),
                "version": p["version"],
                "ecosystem": p.get("ecosystem"),
                "final_verdict": p.get("verdict"),
                "classifier_verdict": p.get("model_verdict") or p.get("verdict"),
                "malice_score": round(p.get("malice_score") or 0, 3),
                "ai_review": _brief_review(p),
                "strong_signals": [s["code"] for s in p.get("signals") or []
                                   if s.get("severity") in ("critical", "high")][:8],
                "not_inspected_reason": p.get("analysis_error")
                or (None if p.get("files_analysed") else "no analysable files"),
                "vulnerabilities": len(vulns),
                "reachable_vulnerabilities": sum(1 for v in vulns if v.get("reachable")),
                "explanation": p.get("explanation"),
            })
    if not hits:
        return {"package": package, "found": False,
                "message": "This package does not appear in any stored scan. Use check_package to analyse it now."}
    return {"package": package, "found": True, "occurrences": hits[:25]}


def tool_check_package(name: str, ecosystem: str, version: str = "latest") -> Any:
    """Download and analyse one package right now (static only), with known CVEs."""
    import asyncio

    from chainguard.api.jobs import registry
    from chainguard.models.db import save_scan
    from chainguard.models.package import Ecosystem
    from chainguard.scanner import Scanner

    eco = Ecosystem.NPM if ecosystem.strip().lower() == "npm" else Ecosystem.PYPI
    scanner = Scanner(classifier=registry.classifier)
    result = asyncio.run(scanner.scan_package(name.strip(), (version or "latest").strip(), eco))
    try:
        save_scan(result)
    except Exception:  # noqa: BLE001 — history is a convenience here
        logger.debug("Could not store consultant package check")
    if not result.packages:
        return {"error": f"No result for {name}"}
    p = result.packages[0].model_dump(mode="json")
    vulns = p.get("vulnerabilities") or []
    return {
        "scan_id": result.scan_id,
        "package": f"{p['name']}@{p['version']}",
        "ecosystem": p["ecosystem"],
        "could_not_inspect": p.get("analysis_error"),
        "files_analysed": p.get("files_analysed"),
        "final_verdict": p.get("verdict"),
        "classifier_verdict": p.get("model_verdict"),
        "malice_score": round(p.get("malice_score") or 0, 3),
        "ai_review": _brief_review(p),
        "typosquat_target": p.get("typosquat_target"),
        "signals": [{k: s.get(k) for k in ("code", "severity", "detail", "file", "line", "evidence")}
                    for s in (p.get("signals") or [])[:15]],
        "top_contributors": p.get("top_contributors"),
        "exfiltration_flows": p.get("exfiltration"),
        "known_vulnerabilities": [
            {k: v.get(k) for k in ("id", "cve_id", "severity", "cvss_score", "summary", "fixed_version")}
            for v in vulns[:20]
        ],
        "vulnerability_total": len(vulns),
        "note": "Single-package check: reachability needs the application's source, so these "
                "vulnerabilities are present in the version, not proven reachable.",
    }


TOOL_HANDLERS = {
    "list_scans": tool_list_scans,
    "get_scan_summary": tool_get_scan_summary,
    "get_package_details": tool_get_package_details,
    "package_history": tool_package_history,
    "check_package": tool_check_package,
    "list_vulnerabilities": tool_list_vulnerabilities,
    "get_model_card": tool_get_model_card,
    "read_logs": tool_read_logs,
    "get_scan_status": tool_get_scan_status,
}


def _fn(name: str, description: str, properties: dict[str, Any], required: Optional[list[str]] = None) -> dict[str, Any]:
    return {
        "type": "function",
        "name": name,
        "description": description,
        "parameters": {"type": "object", "properties": properties, "required": required or []},
    }


TOOLS: list[dict[str, Any]] = [
    _fn("list_scans",
        "List recently stored scans (newest first) with headline counts: packages, malicious/suspicious, "
        "total and reachable vulnerabilities, duration.",
        {"limit": {"type": "integer", "description": "Max scans, 1-50"}}),
    _fn("get_scan_summary",
        "Overview of one scan: counts, warnings/errors (coverage gaps), flagged packages with classifier "
        "score, AI review, top feature contributors and strongest signals, packages that could not be "
        "inspected, top remediation actions. Omit scan_id for the most recent scan.",
        {"scan_id": {"type": "string"}}),
    _fn("get_package_details",
        "Full evidence for one package within one scan: every signal with file:line and snippet, feature "
        "contributors, AI review, explanation, traced exfiltration flows, vulnerabilities with reachability "
        "and call paths. Accepts 'name' or 'name@version' (scoped npm names work). Omit scan_id for the "
        "most recent scan.",
        {"package": {"type": "string"}, "scan_id": {"type": "string"}}, ["package"]),
    _fn("package_history",
        "What happened to a package across ALL stored scans: each scan it appeared in, version, final and "
        "classifier verdict, AI review, strong signals, whether it could not be inspected (and why), "
        "vulnerabilities. Use for 'what happened to X' questions.",
        {"package": {"type": "string"}, "ecosystem": {"type": "string", "enum": ["npm", "PyPI"]}}, ["package"]),
    _fn("check_package",
        "Analyse any npm or PyPI package right now: downloads it (never executes it), runs static analysis, "
        "the classifier and AI review, and looks up known vulnerabilities. Use for 'can I use X?' or "
        "'is X safe?' when it is not in a scan or a specific version is asked about. Takes 5-60 seconds.",
        {"name": {"type": "string"}, "ecosystem": {"type": "string", "enum": ["npm", "PyPI"]},
         "version": {"type": "string", "description": "Exact version, or 'latest'"}},
        ["name", "ecosystem"]),
    _fn("list_vulnerabilities",
        "Known vulnerabilities in a scan, reachable first then by CVSS, with reachability verdict and "
        "reason. Filter with reachable=true/false.",
        {"scan_id": {"type": "string"}, "reachable": {"type": "boolean"}, "limit": {"type": "integer"}}),
    _fn("get_model_card",
        "The trained classifier's metadata: algorithm, dataset, cross-validated precision/recall/F1/PR-AUC, "
        "confusion matrix, baseline comparison, feature importances, methodology notes.", {}),
    _fn("read_logs",
        "Recent ChainGuard server log lines (in memory, since the API started): scan progress, download "
        "failures, timeouts, AI review failures, errors. Filter by minimum level and a case-insensitive "
        "substring such as a package name.",
        {"min_level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR"]},
         "contains": {"type": "string"},
         "limit": {"type": "integer", "description": "Max lines, up to 500"}}),
    _fn("get_scan_status", "Live progress of a scan that is still running (stage, percent, message, error).",
        {"scan_id": {"type": "string"}}, ["scan_id"]),
]


SYSTEM_PROMPT = """You are ChainGuard's AI security consultant. A developer talks to you like a trusted colleague about their dependencies and scans: "what happened to this package?", "can I use X?", "is this flag real?", "what should I fix first?", "why did my scan fail?". Give clear, practical advice grounded in real data.

How ChainGuard works:
- Detection is hybrid. Every package is downloaded and statically analysed (never executed): signals such as install hooks, eval/dynamic execution, process spawning, network access, credential/sensitive-path access, obfuscation, typosquat similarity and composite exfiltration patterns. A gradient-boosting classifier trained on ~2,450 packages (898 real malware samples; benign includes real application dependency trees) scores each one: >=0.60 malicious, >=0.30 suspicious. GPT then reviews flagged packages and its verdict is final ("final_verdict"/"verdict"); "classifier_verdict"/"model_verdict" is the first-stage result. Point out when the two disagree.
- Confirmed exfiltration flows come from a Python data-flow tracer proving a credential read reaches a network send, with exposure: install_time, import_time, call_reachable, call_not_reachable, unknown.
- Vulnerabilities come from OSV. For Python projects a call graph proves whether the vulnerable function is called (with a call path). npm reachability is import-level only ("assumed_reachable"). Single-package checks cannot assess reachability.
- "Not inspected" means the package could not be downloaded or had no analysable files: NOT confirmed clean. Large trees may hit the package ceiling.
- The classifier still leans on package size; a flag with no critical/high code evidence deserves scepticism.

How to work:
- Look things up with tools before answering; never guess names, scores or counts. For "what happened to X" use package_history, and read_logs filtered by the package name for errors or timeouts. For "can I use X" / "is X safe", check stored scans first, then use check_package for a fresh analysis when needed. If the user doesn't name a scan, use the most recent one.
- Answer the actual question first in one sentence (e.g. "Yes, `left-pad@1.3.0` looks safe to use." / "Don't install this: it sends your SSH keys to a webhook."), then the evidence (signal codes, file:line, AI review, CVEs with fixed versions), then what to do.
- For "can I use X": weigh malicious-code evidence, known vulnerabilities (and whether a fixed version exists), and whether it could be inspected. Recommend a specific safe version when one exists.
- Be honest about uncertainty and limits (static analysis, import-level npm reachability, not-inspected packages).
- Apart from check_package you are read-only: you cannot change verdicts, delete scans or edit files. Tell the user exactly what to do instead.
- Keep answers concise and skimmable: short paragraphs or brief bullets, package names and IDs in `code`."""


def assistant_available() -> bool:
    return bool(get_settings().llm_available)


def _event(kind: str, **payload: Any) -> str:
    return json.dumps({"type": kind, **payload}, default=str) + "\n"


def _run_tool(name: str, raw_args: str) -> tuple[str, bool]:
    handler = TOOL_HANDLERS.get(name)
    if handler is None:
        return json.dumps({"error": f"Unknown tool {name}"}), True
    try:
        args = json.loads(raw_args or "{}")
    except json.JSONDecodeError:
        return json.dumps({"error": "INVALID_JSON", "arguments": raw_args}), True
    if not isinstance(args, dict):
        return json.dumps({"error": "Arguments must be a JSON object"}), True
    args = {k: v for k, v in args.items() if v is not None}
    try:
        result = handler(**args)
    except TypeError as exc:
        return json.dumps({"error": f"Bad arguments for {name}: {exc}"}), True
    except Exception as exc:  # noqa: BLE001 — surface tool failures to the model
        logger.exception("Assistant tool %s failed", name)
        return json.dumps({"error": f"{type(exc).__name__}: {exc}"}), True
    text = json.dumps(result, default=str)
    if len(text) > 60_000:
        text = text[:60_000] + " ... [truncated]"
    return text, False


def run_chat(history: list[dict[str, str]], scan_id: Optional[str] = None) -> Iterator[str]:
    """Run one consultant turn, yielding newline-delimited JSON events.

    Event types: ``tool`` (a tool call started), ``tool_result`` (it finished),
    ``text`` (streamed answer text), ``error`` and ``done``.
    """
    from chainguard.llm.review import openai_client

    client = openai_client()
    if client is None:
        yield _event("error", message="Add OPENAI_API_KEY to the .env file in the repository root and restart the API.")
        yield _event("done")
        return

    import openai

    settings = get_settings()
    conversation: list[Any] = []
    for turn in history[-30:]:
        role = turn.get("role")
        content = (turn.get("content") or "").strip()
        if role in ("user", "assistant") and content:
            conversation.append({"role": role, "content": content})
    if not conversation or conversation[-1]["role"] != "user":
        yield _event("error", message="The last message must be from the user.")
        yield _event("done")
        return
    if scan_id:
        conversation[-1] = {
            "role": "user",
            "content": f"{conversation[-1]['content']}\n\n(Context: the user is currently viewing scan `{scan_id}`.)",
        }

    try:
        for _ in range(MAX_TOOL_ROUNDS):
            stream = client.responses.create(
                model=settings.llm_model,
                instructions=SYSTEM_PROMPT,
                input=conversation,
                tools=TOOLS,
                stream=True,
            )
            response = None
            for event in stream:
                if event.type == "response.output_text.delta":
                    yield _event("text", delta=event.delta)
                elif event.type == "response.completed":
                    response = event.response
                elif event.type in ("response.failed", "error"):
                    failure = getattr(getattr(event, "response", None), "error", None)
                    yield _event("error", message=f"OpenAI error: {failure or getattr(event, 'message', '')}")
            if response is None:
                break

            calls = [item for item in response.output if item.type == "function_call"]
            if not calls:
                break

            conversation += response.output
            for call in calls:
                try:
                    shown = json.loads(call.arguments or "{}")
                except json.JSONDecodeError:
                    shown = {}
                yield _event("tool", id=call.call_id, name=call.name, input=shown)
                output, is_error = _run_tool(call.name, call.arguments)
                yield _event("tool_result", id=call.call_id, name=call.name, is_error=is_error, size=len(output))
                conversation.append({"type": "function_call_output", "call_id": call.call_id, "output": output})
        else:
            yield _event("error", message="Stopped after too many tool calls.")
    except openai.AuthenticationError:
        yield _event("error", message="The OpenAI API key was rejected. Check OPENAI_API_KEY in .env.")
    except openai.RateLimitError:
        yield _event("error", message="Rate limited by the OpenAI API (or out of credit). Try again shortly.")
    except openai.APIConnectionError:
        yield _event("error", message="Could not reach the OpenAI API. Check the network connection.")
    except openai.APIStatusError as exc:
        logger.warning("Assistant API error: %s", exc)
        yield _event("error", message=f"OpenAI API error ({exc.status_code}): {exc.message}")
    except Exception as exc:  # noqa: BLE001 — never crash the stream silently
        logger.exception("Assistant failed")
        yield _event("error", message=f"Assistant error: {exc}")
    yield _event("done")
