"""Hybrid verdicts: GPT reviews packages the classifier flagged.

Detection is two-stage:

1. **Screening (every package).** Static analysis extracts evidence and the
   trained classifier scores it. This is fast, free, offline and measured
   (grouped cross-validation plus held-out real applications — see the model card).
2. **Review (flagged/suspicious packages only).** GPT reads the same evidence the
   classifier saw — signals with file:line and snippets, the features that drove
   the score, traced exfiltration flows, typosquat similarity — and returns a
   final verdict with confidence, reasoning and a recommendation.

Only a small fraction of any dependency tree reaches stage 2, so the LLM cost
scales with suspicious packages, not project size. The classifier's own verdict
is kept (``PackageFinding.model_verdict``), so a reviewer can always see where
the two stages disagreed. Every failure (no key, network, rate limit, malformed
output) leaves the classifier verdict in place.

Only extracted evidence is sent — never package source archives.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from pydantic import BaseModel

from chainguard.config import get_settings
from chainguard.logging_setup import get_logger

logger = get_logger(__name__)


class AIReview(BaseModel):
    verdict: str  # malicious | suspicious | benign
    confidence: str  # high | medium | low
    reasoning: str
    recommendation: str
    model: str = ""


_INSTRUCTIONS = """You are a senior software supply chain security analyst reviewing a package that an ML classifier flagged during a dependency scan.

You receive the static-analysis evidence for one package: signals (with severity, file:line and code snippets), the classifier's score and the features that drove it, traced credential-exfiltration data flows, and name-similarity findings. The package was never executed.

Decide the final verdict:
- "malicious": the evidence shows behaviour whose purpose is harmful (credential or data theft, exfiltration to attacker endpoints, backdoors, droppers/downloaders, obfuscated payload execution, destructive actions), or a typosquat carrying such behaviour.
- "suspicious": genuinely concerning behaviour that could be legitimate but needs a human to check.
- "benign": the evidence is explained by normal library behaviour (build tooling, native addon install scripts, telemetry to the vendor's own domain, minified bundles, reading config/env for its own settings, small utility packages) and nothing indicates harmful intent.

Rules:
- Judge the behaviour, not the package's size or popularity. The classifier is known to over-weight package size; a flag driven mainly by size/metadata features with no harmful code evidence is usually benign.
- Well-known, widely used packages can still be compromised: if the evidence shows real exfiltration or payload execution, say malicious regardless of the name.
- Use only the evidence given; do not invent behaviour. If the evidence is thin or ambiguous, choose "suspicious" with low confidence rather than guessing.
- reasoning: 2-4 plain sentences citing the specific evidence (file names, behaviours).
- recommendation: one concrete sentence for the developer (e.g. remove it and rotate credentials, pin a known-good version, safe to keep)."""

_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["malicious", "suspicious", "benign"]},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "reasoning": {"type": "string"},
        "recommendation": {"type": "string"},
    },
    "required": ["verdict", "confidence", "reasoning", "recommendation"],
    "additionalProperties": False,
}


def openai_client() -> Optional[Any]:
    """An OpenAI client when a key is configured, else None."""
    settings = get_settings()
    if not settings.llm_available:
        return None
    try:
        from openai import OpenAI  # noqa: PLC0415 — optional dependency
    except ImportError:
        logger.debug("openai package not installed; AI layer disabled")
        return None
    return OpenAI(api_key=settings.resolved_api_key, max_retries=2, timeout=60)


def _evidence(finding: Any) -> str:
    lines = [
        f"Package: {finding.name}@{finding.version} ({finding.ecosystem})",
        f"Classifier: {finding.verdict} (score {finding.malice_score:.3f})",
        f"Files analysed: {finding.files_analysed}; direct dependency: {finding.is_direct}",
    ]
    if finding.typosquat_target:
        lines.append(f"Name resembles popular package: {finding.typosquat_target}")
    if finding.top_contributors:
        lines.append("Features that drove the score: " + ", ".join(
            f"{name} ({value})" for name, value in finding.top_contributors))
    lines.append("\nSignals:")
    for s in finding.signals[:15]:
        where = f" [{s.file}{':' + str(s.line) if s.line else ''}]" if s.file else ""
        lines.append(f"- ({s.severity.value}) {s.code}: {s.title}{where}")
        if s.detail:
            lines.append(f"    {s.detail[:300]}")
        if s.evidence:
            lines.append(f"    snippet: {s.evidence[:200]}")
    for flow in finding.exfiltration[:5]:
        lines.append(
            f"\nTraced data flow: {flow.source_evidence} (line {flow.source_line}) -> "
            f"{flow.sink_target} (line {flow.sink_line}) in {flow.file}; exposure: {flow.verdict}"
        )
    return "\n".join(lines)


def review_package(finding: Any, client: Any) -> Optional[AIReview]:
    """Ask GPT for a verdict on one flagged package. Returns None on any failure."""
    settings = get_settings()
    try:
        response = client.responses.create(
            model=settings.llm_model,
            instructions=_INSTRUCTIONS,
            input=_evidence(finding),
            max_output_tokens=settings.llm_max_tokens,
            text={"format": {"type": "json_schema", "name": "package_review", "schema": _SCHEMA, "strict": True}},
        )
        data = json.loads(response.output_text)
        return AIReview(model=settings.llm_model, **data)
    except Exception as exc:  # noqa: BLE001 — the classifier verdict stands
        logger.warning("AI review unavailable for %s@%s (%s)", finding.name, finding.version, exc)
        return None
