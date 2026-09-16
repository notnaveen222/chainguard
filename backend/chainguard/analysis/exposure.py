"""Exposure classification: for a confirmed credential-exfiltration path inside a
flagged package, how would it actually trigger in *this specific* project?

Existing reachability analysis (``vulns/reachability.py``) answers this question
for known CVEs only: "is the vulnerable function actually called?" No reviewed
commercial reachability engine applies the same check to a malware detector's
own findings — Coana, the reachability engine behind Socket's acquisition,
documents malware as a fallback case it does not compute reachability for
(BUILD_LOG / VIVA_PREP has the citation trail). This module closes that specific,
narrow gap for one behaviour family — confirmed credential exfiltration — by
reusing the exact call-graph machinery already built for CVEs, not by building a
second one.

Categories, most to least certain
----------------------------------
* ``INSTALL_TIME``      — the file runs automatically on install, before any
                           application code runs. Always exposed, unconditionally.
* ``IMPORT_TIME``       — module-level code; runs the moment the package is
                           imported at all. Checked against whether the
                           application imports the package.
* ``CALL_REACHABLE``    — the flow sits inside a named function, and the
                           application's own code calls it — a cited call path,
                           the same evidentiary standard as the CVE proof paths.
* ``CALL_NOT_REACHABLE``— sits inside a named function the application never
                           calls, given what the analyser could resolve.
* ``UNKNOWN``           — no project source was supplied (single-package scans),
                           so nothing can be classified.

A verdict here is never a claim that the package is safe. Install-time and
import-time code runs regardless of anything computed here, and even
``CALL_NOT_REACHABLE`` only means "no static path was found" — dynamic dispatch,
reflection, and calls from outside the analysed source are not resolved, the
same honest limits ``vulns/reachability.py`` already states for CVEs. The
malicious/suspicious verdict from the classifier is never suppressed or
overridden by anything in this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from chainguard.analysis.dataflow import ConfirmedFlow
from chainguard.models.package import Ecosystem
from chainguard.vulns.reachability import CallSite, ReachabilityAnalyser

#: Matches the sentinel `dataflow._iter_scopes` uses for module-level flows.
_MODULE_SCOPE = "<module>"


class ExposureVerdict(str, Enum):
    INSTALL_TIME = "install_time"
    IMPORT_TIME = "import_time"
    CALL_REACHABLE = "call_reachable"
    CALL_NOT_REACHABLE = "call_not_reachable"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ExposureResult:
    flow: ConfirmedFlow
    verdict: ExposureVerdict
    reason: str
    call_path: list[CallSite] = field(default_factory=list)


def classify_exposure(
    flow: ConfirmedFlow,
    package: str,
    analyser: Optional[ReachabilityAnalyser],
) -> ExposureResult:
    """Classify one confirmed flow's exposure in a specific project.

    ``analyser`` is the same :class:`ReachabilityAnalyser` already built for CVE
    reachability earlier in this scan (Stage 5, ``scanner.py``) — reused, not
    rebuilt, so this costs nothing extra per package.
    """
    if flow.runs_at_install:
        return ExposureResult(
            flow=flow,
            verdict=ExposureVerdict.INSTALL_TIME,
            reason=(
                "This file runs automatically during installation, before any "
                "application code executes — application reachability does not "
                "apply, and the path is exposed regardless"
            ),
        )

    if analyser is None or not analyser.available or analyser.python_graph is None:
        return ExposureResult(
            flow=flow,
            verdict=ExposureVerdict.UNKNOWN,
            reason=(
                "No application source was supplied for this scan (single-package "
                "scans have nothing to check reachability against), so exposure "
                "could not be assessed"
            ),
        )

    graph = analyser.python_graph
    aliases = analyser.resolver.resolve(package, Ecosystem.PYPI)
    importers = graph.imports_package(package, aliases)

    if not importers:
        return ExposureResult(
            flow=flow,
            verdict=ExposureVerdict.CALL_NOT_REACHABLE,
            reason=f"'{package}' is in the dependency tree but the application never imports it",
        )

    if flow.function_scope == _MODULE_SCOPE:
        return ExposureResult(
            flow=flow,
            verdict=ExposureVerdict.IMPORT_TIME,
            reason=(
                f"This code runs at module level, so it executes as soon as "
                f"'{package}' is imported — and the application does import it"
            ),
        )

    matched, path = graph.find_external_call(package, [flow.function_scope], aliases)
    if matched:
        return ExposureResult(
            flow=flow,
            verdict=ExposureVerdict.CALL_REACHABLE,
            reason=f"Application code calls '{matched}' on a path from an entry point",
            call_path=path,
        )

    return ExposureResult(
        flow=flow,
        verdict=ExposureVerdict.CALL_NOT_REACHABLE,
        reason=(
            f"'{package}' is imported, but no reachable path to "
            f"`{flow.function_scope}` was found from an application entry point"
        ),
    )
