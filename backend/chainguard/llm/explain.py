"""Optional natural-language explanation layer.

**Disabled by default, and the system is fully functional without it.**

The classifier is the system of record: it is measurable, runs offline, and
produces the verdict. This layer only *renders* that verdict in prose, taking the
evidence the analyser already collected and turning it into a paragraph a
developer can act on.

The separation is deliberate (BUILD_LOG D-003). An LLM cannot be evaluated with a
confusion matrix, so making it the detector would leave "how do you know it
works?" unanswerable. Making it the explainer costs nothing and adds real value
when a key is available.

Design constraints, all of which follow from the LLM being a presentation layer:

* **It never changes a verdict.** The score and the flag come from the
  classifier. The model is given the evidence and asked to explain it, not to
  re-decide.
* **Every failure degrades to the deterministic summary.** No key, no network, a
  rate limit, a malformed response — all return the locally-generated text. A
  scan must never fail because an optional feature was unavailable.
* **Only evidence is sent, never package source.** The prompt carries signal
  codes, file paths and short snippets the analyser already extracted. Shipping
  whole packages to a third party would be a data-egress decision nobody asked
  for, and would be slow and expensive besides.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from chainguard.analysis.signals import Severity, Signal
from chainguard.config import get_settings
from chainguard.logging_setup import get_logger

logger = get_logger(__name__)

_SYSTEM_PROMPT = """You are a software supply chain security analyst.

You will be given the findings a static analyser produced for one package: its
computed risk score, and the concrete evidence behind that score.

Write a short explanation for a developer deciding whether to remove this
dependency. Requirements:

- 2-4 sentences, plain prose, no bullet points, no headings.
- Explain what the evidence indicates in practical terms: what would happen on
  the developer's machine, and when (install time vs. runtime).
- Reference specific evidence (file names, the behaviour observed). Do not invent
  details that are not in the evidence given.
- Do NOT restate the numeric score, and do NOT overrule the verdict you are
  given. You are explaining a decision that has already been made.
- If the evidence is weak or ambiguous, say so plainly rather than inflating it.
"""


@dataclass
class Explanation:
    """A rendered explanation and where it came from."""

    text: str
    source: str  # "llm" | "local"
    model: Optional[str] = None

    @property
    def is_llm(self) -> bool:
        return self.source == "llm"


def _severity_phrase(signals: list[Signal]) -> str:
    counts: dict[Severity, int] = {}
    for signal in signals:
        counts[signal.severity] = counts.get(signal.severity, 0) + 1
    parts = [
        f"{count} {severity.value}"
        for severity, count in sorted(counts.items(), key=lambda item: -item[0].rank)
        if severity.rank >= Severity.MEDIUM.rank
    ]
    return ", ".join(parts) if parts else "no high-severity findings"


def local_explanation(
    name: str, version: str, verdict: str, signals: list[Signal],
    typosquat_target: Optional[str] = None,
) -> Explanation:
    """Deterministic explanation, generated without any model.

    This is the default and the fallback. It is templated rather than generated,
    so it is always available, always consistent, and never wrong about what the
    analyser found.
    """
    if not signals:
        return Explanation(
            text=(
                f"No suspicious behaviour was detected in {name} {version}. The "
                f"package was analysed statically and raised no signals."
            ),
            source="local",
        )

    ranked = sorted(signals, key=lambda s: -s.severity.rank)
    headline = ranked[0]

    sentences = [
        f"{name} {version} was classified as {verdict} based on "
        f"{len(signals)} finding(s) ({_severity_phrase(signals)})."
    ]

    location = f" in {headline.file}" if headline.file else ""
    lead = f"The strongest evidence is {headline.title.lower()}{location}"
    if headline.detail:
        detail = headline.detail.rstrip()
        if not detail.endswith((".", "!", "?")):
            detail += "."
        sentences.append(f"{lead}: {detail}")
    else:
        sentences.append(f"{lead}.")

    if typosquat_target:
        sentences.append(
            f"The package name also closely resembles the popular package "
            f"'{typosquat_target}', which is the mechanism behind install-time "
            f"typo attacks."
        )

    install_signals = [s for s in ranked if s.category.value == "install_hook"]
    if install_signals:
        sentences.append(
            "Some of this behaviour runs automatically at install time, before "
            "any of the package's API is called."
        )

    return Explanation(text=" ".join(sentences), source="local")


def _build_prompt(
    name: str, version: str, ecosystem: str, verdict: str, score: float,
    signals: list[Signal], typosquat_target: Optional[str],
) -> str:
    lines = [
        f"Package: {name} {version} ({ecosystem})",
        f"Verdict: {verdict} (score {score:.2f})",
    ]
    if typosquat_target:
        lines.append(f"Name resembles the popular package: {typosquat_target}")

    lines.append("\nEvidence:")
    for signal in sorted(signals, key=lambda s: -s.severity.rank)[:12]:
        location = f" [{signal.location}]" if signal.file else ""
        lines.append(f"- ({signal.severity.value}) {signal.title}{location}")
        if signal.detail:
            lines.append(f"    {signal.detail}")
        if signal.evidence:
            lines.append(f"    source: {signal.evidence[:160]}")

    return "\n".join(lines)


def explain_package(
    name: str,
    version: str,
    ecosystem: str,
    verdict: str,
    score: float,
    signals: list[Signal],
    typosquat_target: Optional[str] = None,
) -> Explanation:
    """Explain a package's verdict, using the LLM when it is available.

    Always returns an explanation. Never raises.
    """
    fallback = local_explanation(name, version, verdict, signals, typosquat_target)

    settings = get_settings()
    if not settings.llm_available:
        return fallback

    try:
        import anthropic  # noqa: PLC0415 — optional dependency, imported lazily
    except ImportError:
        logger.debug("anthropic package not installed; using the local explanation")
        return fallback

    try:
        client = anthropic.Anthropic(api_key=settings.resolved_api_key)
        response = client.messages.create(
            model=settings.llm_model,
            max_tokens=settings.llm_max_tokens,
            system=_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": _build_prompt(
                        name, version, ecosystem, verdict, score, signals, typosquat_target
                    ),
                }
            ],
        )
        text = "".join(
            block.text for block in response.content if getattr(block, "type", "") == "text"
        ).strip()

        if not text:
            return fallback
        return Explanation(text=text, source="llm", model=settings.llm_model)

    except Exception as exc:  # noqa: BLE001
        # Rate limits, network failures, auth errors, API changes — every one of
        # them degrades to the deterministic explanation. An optional feature
        # must never be able to fail a scan.
        logger.warning("LLM explanation unavailable (%s); using the local summary", exc)
        return fallback


def explain_reachability(
    package: str, cve_id: str, verdict: str, reason: str, call_path: list[dict]
) -> Explanation:
    """Explain a reachability verdict in prose.

    Local-only by design. The call path is already the clearest possible
    explanation of *why* something is reachable — it is a concrete chain of calls
    with file and line numbers — so there is nothing an LLM would add beyond
    restating it less precisely.
    """
    if call_path:
        chain = " → ".join([call_path[0]["caller"]] + [step["callee"] for step in call_path])
        entry = call_path[0].get("file", "")
        return Explanation(
            text=(
                f"{cve_id} in {package} is reachable. Application code reaches the "
                f"vulnerable function through {len(call_path)} call(s), starting in "
                f"{entry}: {chain}."
            ),
            source="local",
        )

    return Explanation(text=f"{cve_id} in {package}: {reason}", source="local")
