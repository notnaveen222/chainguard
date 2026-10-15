"""Jev review: typed verdict probabilities from TypeSafe's System One model.

Jev is the counterpart to ``review.py``'s GPT review. Both read the same
extracted evidence for a flagged package; they differ in what they return:

* GPT returns a verdict plus a written explanation, one generated-text call.
* Jev returns a *distribution* over ``malicious | suspicious | benign`` and three
  yes/no probabilities, in one parallel pass, with no prose.

Jev's answer is **recorded, never applied**: ``PackageFinding.jev_review`` sits
beside ``ai_review`` so the two can be compared, and the final verdict is still
decided by the classifier and (when configured) the GPT review. Every failure
(no key, SDK missing, network, rate limit) returns ``None`` and leaves the scan
untouched. Only extracted evidence is sent, never package source archives.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from pydantic import BaseModel, Field

from chainguard.config import get_settings
from chainguard.logging_setup import get_logger

logger = get_logger(__name__)


class JevReview(BaseModel):
    verdict: str  # malicious | suspicious | benign
    #: Jev's confidence in the selected verdict (0-1): how concentrated the
    #: distribution is, not a guarantee of correctness.
    confidence: float
    probabilities: dict[str, float] = Field(default_factory=dict)
    #: P(yes) for each supporting question.
    exfiltration: float = 0.0
    payload_execution: float = 0.0
    normal_behaviour: float = 0.0
    model: str = ""
    latency_ms: Optional[int] = None


_VERDICT_CRITERIA = {
    "malicious": (
        "The evidence shows behaviour whose purpose is harmful: credential or data theft, "
        "exfiltration to attacker endpoints, backdoors, droppers/downloaders, obfuscated payload "
        "execution, destructive actions, or a typosquat carrying such behaviour."
    ),
    "suspicious": (
        "Genuinely concerning behaviour that could be legitimate but needs a human to check, or "
        "the evidence is thin or ambiguous."
    ),
    "benign": (
        "The evidence is explained by normal library behaviour (build tooling, native addon install "
        "scripts, telemetry to the vendor's own domain, minified bundles, reading config/env for its "
        "own settings, small utility packages) and nothing indicates harmful intent."
    ),
}

_CONTEXT = (
    "State describes one software package that an ML classifier flagged during a dependency scan. "
    "It was never executed; only static-analysis evidence is given. Judge the behaviour, not the "
    "package's size or popularity (the classifier over-weights size). A well-known package can still "
    "be compromised if the evidence shows real exfiltration or payload execution."
)


def jev_client() -> Optional[Any]:
    """A TypeSafe client when a key is configured and the SDK is installed, else None."""
    settings = get_settings()
    if not settings.jev_available:
        return None
    try:
        from typesafe_sdk import TypeSafeClient  # noqa: PLC0415 — optional dependency
    except ImportError:
        logger.debug("typesafe-sdk not installed; Jev layer disabled")
        return None
    return TypeSafeClient(
        api_key=settings.resolved_typesafe_key,
        model=settings.jev_model,
        timeout=settings.jev_timeout_seconds,
    )


def _state(finding: Any) -> dict[str, Any]:
    """The same evidence GPT sees, as named JSON fields."""
    return {
        "context": _CONTEXT,
        "package": {
            "name": finding.name,
            "version": finding.version,
            "ecosystem": finding.ecosystem,
            "files_analysed": finding.files_analysed,
            "direct_dependency": finding.is_direct,
        },
        "classifier": {"verdict": finding.model_verdict or finding.verdict, "score": round(finding.malice_score, 3)},
        "typosquat_of": finding.typosquat_target,
        "score_drivers": [f"{name} ({value})" for name, value in finding.top_contributors],
        "signals": [
            {
                "severity": getattr(s.severity, "value", str(s.severity)),
                "code": s.code,
                "title": s.title,
                "location": f"{s.file}:{s.line}" if s.file and s.line else (s.file or None),
                "detail": (s.detail or "")[:300],
                "snippet": (s.evidence or "")[:200],
            }
            for s in finding.signals[:15]
        ],
        "traced_flows": [
            {
                "source": flow.source_evidence,
                "sink": flow.sink_target,
                "file": flow.file,
                "exposure": flow.verdict,
            }
            for flow in finding.exfiltration[:5]
        ],
    }


def _questions() -> dict[str, Any]:
    from typesafe_sdk import Choice, Noul  # noqa: PLC0415 — optional dependency

    return {
        "verdict": Choice(
            instructions="What is the right final verdict for this package, given the evidence?",
            criteria=_VERDICT_CRITERIA,
        ),
        "exfiltration": Noul(
            instructions="Does the evidence show the package stealing credentials or sending data to an external endpoint?",
        ),
        "payload_execution": Noul(
            instructions="Does the evidence show the package downloading, decoding or running a hidden payload?",
        ),
        "normal_behaviour": Noul(
            instructions="Is all of the flagged behaviour explained by normal library behaviour?",
        ),
    }


def review_package_jev(finding: Any, client: Any) -> Optional[JevReview]:
    """Ask Jev for typed verdict probabilities. Returns None on any failure."""
    settings = get_settings()
    try:
        questions = _questions()
        started = time.perf_counter()
        response = client.system_one(state=_state(finding), questions=questions)
        latency_ms = round((time.perf_counter() - started) * 1000)
        verdict = response.answers["verdict"]
        return JevReview(
            verdict=verdict.choice,
            confidence=round(verdict.confidence, 4),
            probabilities={k: round(v, 4) for k, v in verdict.probabilities.items()},
            exfiltration=round(response.answers["exfiltration"].noul, 4),
            payload_execution=round(response.answers["payload_execution"].noul, 4),
            normal_behaviour=round(response.answers["normal_behaviour"].noul, 4),
            model=getattr(response, "model", None) or settings.jev_model,
            latency_ms=latency_ms,
        )
    except Exception as exc:  # noqa: BLE001 — Jev is advisory, the scan must not fail
        logger.warning("Jev review unavailable for %s@%s (%s)", finding.name, finding.version, exc)
        return None
