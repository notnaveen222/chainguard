"""Interactive analysis assistant — the dashboard's AI chat panel.

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

MODEL = "claude-opus-5"
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


TOOL_HANDLERS = {
    "list_scans": tool_list_scans,
    "get_scan_summary": tool_get_scan_summary,
    "get_package_details": tool_get_package_details,
    "list_vulnerabilities": tool_list_vulnerabilities,
    "get_model_card": tool_get_model_card,
    "read_logs": tool_read_logs,
    "get_scan_status": tool_get_scan_status,
}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "list_scans",
        "description": "List recently stored scans (newest first) with their headline counts: packages, malicious/suspicious, total and reachable vulnerabilities, duration.",
        "input_schema": {"type": "object", "properties": {"limit": {"type": "integer", "description": "Max scans, 1-50"}}},
    },
    {
        "name": "get_scan_summary",
        "description": "Overview of one scan: summary counts, warnings/errors (coverage gaps), flagged packages with their score, top model feature contributors and strongest signals, packages that could not be inspected, and the top remediation actions. Omit scan_id for the most recent scan.",
        "input_schema": {"type": "object", "properties": {"scan_id": {"type": "string"}}},
    },
    {
        "name": "get_package_details",
        "description": "Full evidence for one package in a scan: every signal with file:line and snippet, model feature contributors, the generated explanation, confirmed credential-exfiltration flows, and its vulnerabilities with reachability verdicts and call paths. Accepts 'name' or 'name@version' (scoped npm names like '@radix-ui/rect' work).",
        "input_schema": {
            "type": "object",
            "properties": {"package": {"type": "string"}, "scan_id": {"type": "string"}},
            "required": ["package"],
        },
    },
    {
        "name": "list_vulnerabilities",
        "description": "Known vulnerabilities in a scan, reachable first then by CVSS, with the reachability verdict and reason. Filter with reachable=true/false.",
        "input_schema": {
            "type": "object",
            "properties": {"scan_id": {"type": "string"}, "reachable": {"type": "boolean"}, "limit": {"type": "integer"}},
        },
    },
    {
        "name": "get_model_card",
        "description": "The trained classifier's metadata: algorithm, dataset size, cross-validated precision/recall/F1/PR-AUC, confusion matrix, rules-baseline comparison, top feature importances, ablation and methodology notes.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "read_logs",
        "description": "Recent ChainGuard server log lines (in-memory, since the API started). Filter by minimum level (DEBUG, INFO, WARNING, ERROR) and a case-insensitive substring.",
        "input_schema": {
            "type": "object",
            "properties": {
                "min_level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR"]},
                "contains": {"type": "string"},
                "limit": {"type": "integer", "description": "Max lines, up to 500"},
            },
        },
    },
    {
        "name": "get_scan_status",
        "description": "Live progress of a scan that is still running (stage, percent, message, error).",
        "input_schema": {"type": "object", "properties": {"scan_id": {"type": "string"}}, "required": ["scan_id"]},
    },
]
for _tool in TOOLS:
    _tool["eager_input_streaming"] = True


SYSTEM_PROMPT = """You are the analysis assistant built into ChainGuard, a software supply chain security tool. You help a developer understand a scan of their project, judge whether findings are real, and decide what to change.

How ChainGuard works, so you can interpret its output:
- Malicious-package detection: packages are downloaded and statically analysed (never executed). The analyser emits signals (install hooks, eval/dynamic execution, process spawning, network access, credential/sensitive path access, obfuscation, typosquat similarity, composite exfiltration patterns). 58 numeric features derived from those signals plus package structure and metadata feed a calibrated gradient-boosting classifier. Score >= 0.60 is "malicious", >= 0.30 "suspicious". "top_contributors" are the features that pushed that package's score most.
- Confirmed exfiltration flows come from a separate intra-procedural data-flow tracer (Python only) that proves a credential read reaches a network send, with an exposure verdict (install_time, import_time, call_reachable, call_not_reachable, unknown).
- Vulnerabilities come from OSV. Reachability: for Python projects, a call graph of the application proves whether the vulnerable function is called and gives a call path. For npm projects reachability is import-level only ("assumed_reachable" means the package is imported but symbol use was not verified) — say so when it matters.
- Known limitations to keep in mind when judging a result: the classifier was trained on ~2,450 packages (898 real malicious samples; benign packages include real application dependency trees, added because the original benign sample of large popular packages made the model over-flag small utilities). Structure features (file_count, total_bytes, avg_file_bytes) still carry weight, so a flag driven mainly by those with no critical/high code signals deserves scepticism — check the evidence. Scans run before the model was retrained may show such false positives. Large dependency trees can hit the package ceiling and some packages cannot be downloaded ("not inspected" means NOT confirmed clean). Samples scanned from the malware vault are part of the training corpus.

How to work:
- Use the tools to look at the actual data before answering; don't guess at package names, scores or counts. If the user doesn't name a scan, use the most recent one.
- Ground every claim in the evidence you retrieved (signal codes, file:line, feature contributors, reachability reason, log lines) and be direct about confidence: distinguish "this is clearly malicious", "this looks like a false positive, because...", and "not enough evidence".
- When asked what to change, give concrete, prioritised actions: dependency upgrades from the remediation plan, packages to remove or pin, threshold or configuration changes, re-running with a source directory, or model/dataset improvements — and say what each would fix.
- For errors or stuck scans, read the logs and explain the cause plainly.
- You are read-only: you cannot change verdicts, rerun scans or edit files. Say what the user should do instead.
- Keep answers concise and skimmable: short paragraphs or brief bullet lists, package names and IDs in `code`."""


# --------------------------------------------------------------------------- #
# Chat loop (streams events for the dashboard)
# --------------------------------------------------------------------------- #

def assistant_available() -> bool:
    return bool(get_settings().resolved_api_key)


def _event(kind: str, **payload: Any) -> str:
    return json.dumps({"type": kind, **payload}, default=str) + "\n"


def _run_tool(name: str, args: Any) -> tuple[str, bool]:
    handler = TOOL_HANDLERS.get(name)
    if handler is None:
        return json.dumps({"error": f"Unknown tool {name}"}), True
    if not isinstance(args, dict):
        return json.dumps({"INVALID_JSON": json.dumps(args, default=str)}), True
    try:
        result = handler(**args)
    except TypeError as exc:
        return json.dumps({"error": f"Bad arguments for {name}: {exc}"}), True
    except Exception as exc:  # noqa: BLE001 — surface tool failures to the model
        logger.exception("Assistant tool %s failed", name)
        return json.dumps({"error": f"{type(exc).__name__}: {exc}"}), True
    text = json.dumps(result, default=str)
    if len(text) > 60_000:
        text = text[:60_000] + ' ... [truncated]"'
    return text, False


def run_chat(history: list[dict[str, str]], scan_id: Optional[str] = None) -> Iterator[str]:
    """Run one assistant turn, yielding newline-delimited JSON events.

    Event types: ``tool`` (a tool call started), ``tool_result`` (it finished),
    ``text`` (streamed answer text), ``error`` and ``done``.
    """
    import anthropic

    settings = get_settings()
    client = anthropic.Anthropic(api_key=settings.resolved_api_key)

    messages: list[dict[str, Any]] = []
    for turn in history[-30:]:
        role = turn.get("role")
        content = (turn.get("content") or "").strip()
        if role in ("user", "assistant") and content:
            messages.append({"role": role, "content": content})
    if not messages or messages[-1]["role"] != "user":
        yield _event("error", message="The last message must be from the user.")
        return
    if scan_id:
        messages[-1] = {
            "role": "user",
            "content": f"{messages[-1]['content']}\n\n(Context: the user is currently viewing scan `{scan_id}`.)",
        }

    json_retries = 0
    rounds = 0
    try:
        while rounds < MAX_TOOL_ROUNDS:
            try:
                with client.beta.messages.stream(
                    model=MODEL,
                    max_tokens=32000,
                    system=[{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
                    tools=TOOLS,
                    messages=messages,
                    thinking={"type": "adaptive"},
                    output_config={"effort": "medium"},
                    betas=["server-side-fallback-2026-07-01"],
                    fallbacks="default",
                ) as stream:
                    for event in stream:
                        if event.type == "text":
                            yield _event("text", delta=event.text)
                    response = stream.get_final_message()
                json_retries = 0
            except ValueError:
                json_retries += 1
                if json_retries > 2:
                    raise
                continue

            if response.stop_reason == "pause_turn":
                messages.append({"role": "assistant", "content": response.content})
                continue
            if response.stop_reason == "refusal":
                yield _event("error", message="The model declined to answer this request.")
                break

            tool_uses = [b for b in response.content if b.type == "tool_use"]
            if not tool_uses:
                if response.stop_reason == "max_tokens":
                    yield _event("error", message="The answer hit the length limit and was cut off.")
                break
            if response.stop_reason == "max_tokens":
                yield _event("error", message="A tool request was cut off; try a narrower question.")
                break

            results = []
            for block in tool_uses:
                yield _event("tool", id=block.id, name=block.name, input=block.input)
                content, is_error = _run_tool(block.name, block.input)
                yield _event("tool_result", id=block.id, name=block.name, is_error=is_error, size=len(content))
                results.append({"type": "tool_result", "tool_use_id": block.id, "content": content, "is_error": is_error})
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": results})
            rounds += 1
        else:
            yield _event("error", message="Stopped after too many tool calls.")
    except anthropic.AuthenticationError:
        yield _event("error", message="The Anthropic API key was rejected. Check ANTHROPIC_API_KEY in .env.")
    except anthropic.RateLimitError:
        yield _event("error", message="Rate limited by the Anthropic API. Try again in a moment.")
    except anthropic.APIConnectionError:
        yield _event("error", message="Could not reach the Anthropic API. Check the network connection.")
    except anthropic.APIStatusError as exc:
        logger.warning("Assistant API error: %s", exc)
        yield _event("error", message=f"Anthropic API error ({exc.status_code}): {exc.message}")
    except Exception as exc:  # noqa: BLE001 — never crash the stream silently
        logger.exception("Assistant failed")
        yield _event("error", message=f"Assistant error: {exc}")
    yield _event("done")
