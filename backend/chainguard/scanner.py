"""Scan orchestration — the layer that produces a complete result.

One scan runs five stages:

1. **Parse** the manifest into declared requirements.
2. **Resolve** the transitive dependency graph against the live registries.
3. **Detect** — download each package, analyse it statically, and score it with
   the classifier.
4. **Advise** — query OSV for known vulnerabilities across every resolved package.
5. **Reach** — decide which of those vulnerabilities the application can actually
   reach, and prove it with a call path.

The two halves are deliberately independent: detection answers "is anything here
hostile?", reachability answers "which known flaws actually matter?". A failure in
one must not take out the other, so each stage records its own errors and the
scan continues.

Everything here is I/O-bound, so stages run concurrently within themselves and
report progress through a callback — a scan of a real project takes long enough
that a silent wait would be unusable in a demo.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

from chainguard.analysis.engine import analyse_package
from chainguard.analysis.signals import Severity, Signal
from chainguard.config import get_settings
from chainguard.logging_setup import get_logger
from chainguard.ml.model import MalwareClassifier
from chainguard.models.package import (
    DependencyGraph,
    Ecosystem,
    PackageRef,
)
from chainguard.registry.http import CachedHTTPClient, NotFoundError, RegistryError
from chainguard.registry.manifest import ManifestError, ParsedManifest, parse_manifest
from chainguard.registry.npm import NpmClient
from chainguard.registry.pypi import PyPIClient
from chainguard.registry.resolver import DependencyResolver
from chainguard.vulns.import_names import ImportNameResolver
from chainguard.vulns.osv import OSVClient, Vulnerability
from chainguard.vulns.reachability import ReachabilityAnalyser, ReachabilityResult, Verdict

logger = get_logger(__name__)

ProgressCallback = Callable[[str, float, str], None]


# --------------------------------------------------------------------------- #
# Result types
# --------------------------------------------------------------------------- #


class VulnerabilityFinding(BaseModel):
    """One advisory, with its reachability verdict attached."""

    id: str
    cve_id: Optional[str] = None
    package: str
    version: str
    ecosystem: str
    severity: str
    cvss_score: Optional[float] = None
    summary: str = ""
    fixed_version: Optional[str] = None
    references: list[str] = Field(default_factory=list)

    vulnerable_symbols: list[str] = Field(default_factory=list)
    symbol_confidence: str = "none"

    reachable: bool = True
    reachability_verdict: str = Verdict.NOT_ANALYSED.value
    reachability_reason: str = ""
    reachability_confidence: str = "none"
    matched_symbol: Optional[str] = None
    call_path: list[dict[str, Any]] = Field(default_factory=list)
    imported_by: list[str] = Field(default_factory=list)

    @property
    def priority(self) -> float:
        """Ordering key: severity, weighted down hard when unreachable.

        Reachability is the point of the project, so it dominates ordering — a
        reachable moderate belongs above an unreachable critical.
        """
        base = self.cvss_score if self.cvss_score is not None else {
            "CRITICAL": 9.0, "HIGH": 7.5, "MODERATE": 5.0, "MEDIUM": 5.0, "LOW": 2.5
        }.get(self.severity.upper(), 4.0)
        return base * (1.0 if self.reachable else 0.1)


class PackageFinding(BaseModel):
    """Everything known about one package in the dependency tree."""

    name: str
    version: str
    ecosystem: str
    depth: int = 0
    is_direct: bool = False
    required_by: list[str] = Field(default_factory=list)

    # Malicious-package detection
    malice_score: float = 0.0
    verdict: str = "benign"
    score_source: str = "rules-baseline"
    signals: list[Signal] = Field(default_factory=list)
    top_contributors: list[tuple[str, float]] = Field(default_factory=list)
    typosquat_target: Optional[str] = None

    # Known vulnerabilities
    vulnerabilities: list[VulnerabilityFinding] = Field(default_factory=list)

    analysis_error: Optional[str] = None
    files_analysed: int = 0

    @property
    def is_flagged(self) -> bool:
        return self.verdict in ("malicious", "suspicious")

    @property
    def reachable_vulnerabilities(self) -> list[VulnerabilityFinding]:
        return [v for v in self.vulnerabilities if v.reachable]

    @property
    def critical_signals(self) -> list[Signal]:
        return [s for s in self.signals if s.severity is Severity.CRITICAL]


class ScanSummary(BaseModel):
    """Headline numbers for one scan."""

    total_packages: int = 0
    direct_packages: int = 0
    max_depth: int = 0

    malicious_packages: int = 0
    suspicious_packages: int = 0

    total_vulnerabilities: int = 0
    reachable_vulnerabilities: int = 0
    unreachable_vulnerabilities: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    reachable_by_severity: dict[str, int] = Field(default_factory=dict)

    @property
    def noise_reduction(self) -> float:
        """Fraction of advisories the reachability analysis rules out.

        The project's central empirical claim, reported as a single number.
        """
        if not self.total_vulnerabilities:
            return 0.0
        return self.unreachable_vulnerabilities / self.total_vulnerabilities


class ScanResult(BaseModel):
    """The complete output of one scan."""

    scan_id: str
    target: str
    ecosystem: str
    status: str = "completed"
    started_at: float = 0.0
    duration_seconds: float = 0.0

    summary: ScanSummary = Field(default_factory=ScanSummary)
    packages: list[PackageFinding] = Field(default_factory=list)

    reachability_available: bool = False
    reachability_stats: dict[str, int] = Field(default_factory=dict)
    model_source: str = "rules-baseline"

    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    stage_timings: dict[str, float] = Field(default_factory=dict)

    def flagged_packages(self) -> list[PackageFinding]:
        return sorted(
            (p for p in self.packages if p.is_flagged), key=lambda p: -p.malice_score
        )

    def all_vulnerabilities(self) -> list[VulnerabilityFinding]:
        return [v for p in self.packages for v in p.vulnerabilities]

    def prioritised_vulnerabilities(self) -> list[VulnerabilityFinding]:
        return sorted(self.all_vulnerabilities(), key=lambda v: -v.priority)


# --------------------------------------------------------------------------- #
# Remediation
# --------------------------------------------------------------------------- #


class RemediationAction(BaseModel):
    """A suggested upgrade and what it resolves."""

    package: str
    current_version: str
    target_version: str
    ecosystem: str
    fixes_total: int = 0
    fixes_reachable: int = 0
    highest_severity: str = "UNKNOWN"
    cve_ids: list[str] = Field(default_factory=list)
    is_direct: bool = False


def build_remediation_plan(result: ScanResult) -> list[RemediationAction]:
    """Group findings into upgrade actions, ordered by what they actually fix.

    Ordered by *reachable* fixes first. An upgrade that clears eight unreachable
    advisories is less valuable than one clearing a single reachable
    vulnerability, and ordering by raw count would invert that.
    """
    from chainguard.registry import semver

    by_package: dict[str, list[VulnerabilityFinding]] = {}
    package_index = {f"{p.ecosystem}:{p.name}": p for p in result.packages}

    for finding in result.all_vulnerabilities():
        if not finding.fixed_version:
            continue
        by_package.setdefault(f"{finding.ecosystem}:{finding.package}", []).append(finding)

    actions: list[RemediationAction] = []
    for key, findings in by_package.items():
        package = package_index.get(key)
        if package is None:
            continue

        # The upgrade target is the highest fixed-version across the advisories,
        # since a lower one would leave some unresolved.
        fixed_versions = [f.fixed_version for f in findings if f.fixed_version]
        target = fixed_versions[0]
        for candidate in fixed_versions[1:]:
            parsed_target = semver.Version.parse(target)
            parsed_candidate = semver.Version.parse(candidate)
            if parsed_target and parsed_candidate and parsed_candidate > parsed_target:
                target = candidate

        severities = [f.severity.upper() for f in findings]
        highest = next(
            (s for s in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW") if s in severities),
            "UNKNOWN",
        )

        actions.append(
            RemediationAction(
                package=package.name,
                current_version=package.version,
                target_version=target,
                ecosystem=package.ecosystem,
                fixes_total=len(findings),
                fixes_reachable=sum(1 for f in findings if f.reachable),
                highest_severity=highest,
                cve_ids=sorted({f.cve_id or f.id for f in findings})[:12],
                is_direct=package.is_direct,
            )
        )

    return sorted(actions, key=lambda a: (-a.fixes_reachable, -a.fixes_total, a.package))


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #


class Scanner:
    """Runs a full supply-chain scan."""

    def __init__(
        self,
        classifier: Optional[MalwareClassifier] = None,
        progress: Optional[ProgressCallback] = None,
    ) -> None:
        self.settings = get_settings()
        self.classifier = classifier or MalwareClassifier.load()
        self.progress = progress or (lambda stage, pct, message: None)

    def _report(self, stage: str, pct: float, message: str) -> None:
        try:
            self.progress(stage, pct, message)
        except Exception:  # noqa: BLE001 — a broken progress sink must not fail a scan
            pass

    # ------------------------------------------------------------------ #

    async def scan_manifest(
        self,
        manifest_text: str,
        filename: str,
        *,
        project_root: Optional[Path] = None,
        include_dev: bool = False,
        max_packages: Optional[int] = None,
    ) -> ScanResult:
        """Scan a manifest, optionally with project source for reachability."""
        started = time.time()
        scan_id = uuid.uuid4().hex[:12]

        try:
            manifest = parse_manifest(manifest_text, filename)
        except ManifestError as exc:
            return ScanResult(
                scan_id=scan_id,
                target=filename,
                ecosystem="unknown",
                status="failed",
                started_at=started,
                errors=[str(exc)],
            )

        result = ScanResult(
            scan_id=scan_id,
            target=manifest.project_name or filename,
            ecosystem=manifest.ecosystem.value,
            started_at=started,
        )
        result.warnings.extend(manifest.warnings)

        async with CachedHTTPClient() as http:
            await self._run_stages(
                result, manifest, http, project_root, include_dev, max_packages
            )

        result.duration_seconds = time.time() - started
        self._report("done", 1.0, f"Scan complete in {result.duration_seconds:.1f}s")
        return result

    async def scan_project(
        self,
        project_dir: Path,
        *,
        include_dev: bool = False,
        max_packages: Optional[int] = None,
    ) -> ScanResult:
        """Scan a project directory, discovering its manifest automatically."""
        from chainguard.registry.manifest import detect_project_manifests

        manifests = detect_project_manifests(project_dir)
        if not manifests:
            return ScanResult(
                scan_id=uuid.uuid4().hex[:12],
                target=str(project_dir),
                ecosystem="unknown",
                status="failed",
                errors=[
                    "No package.json, requirements.txt or pyproject.toml found in "
                    f"{project_dir}"
                ],
            )

        path = manifests[0]
        return await self.scan_manifest(
            path.read_text(encoding="utf-8", errors="replace"),
            path.name,
            project_root=project_dir,
            include_dev=include_dev,
            max_packages=max_packages,
        )

    async def scan_package(self, name: str, version: str, ecosystem: Ecosystem) -> ScanResult:
        """Analyse a single package without resolving a dependency tree."""
        started = time.time()
        result = ScanResult(
            scan_id=uuid.uuid4().hex[:12],
            target=f"{name}@{version}",
            ecosystem=ecosystem.value,
            started_at=started,
        )

        async with CachedHTTPClient() as http:
            findings = await self._detect(
                http, [PackageRef(name=name, version=version, ecosystem=ecosystem)], {}
            )
            result.packages = findings

            osv = OSVClient(http)
            refs = [PackageRef(name=f.name, version=f.version, ecosystem=ecosystem)
                    for f in findings]
            advisories = await osv.query_batch(refs)
            for finding, ref in zip(findings, refs):
                finding.vulnerabilities = [
                    _to_finding(v, ref, None) for v in advisories.get(ref.key, [])
                ]

        result.model_source = "model" if self.classifier.is_trained else "rules-baseline"
        _summarise(result)
        result.duration_seconds = time.time() - started
        return result

    # ------------------------------------------------------------------ #

    async def _run_stages(
        self,
        result: ScanResult,
        manifest: ParsedManifest,
        http: CachedHTTPClient,
        project_root: Optional[Path],
        include_dev: bool,
        max_packages: Optional[int],
    ) -> None:
        # --- Stage 1/2: resolve ---------------------------------------- #
        stage_start = time.time()
        self._report("resolve", 0.05, "Resolving the dependency tree...")

        resolver = DependencyResolver(http)
        try:
            graph = await resolver.resolve(manifest, include_dev=include_dev)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"Dependency resolution failed: {exc}")
            result.status = "failed"
            return

        if graph.truncated and graph.truncation_reason:
            result.warnings.append(f"Dependency resolution truncated: {graph.truncation_reason}")
        result.warnings.extend(f"Unresolved: {u}" for u in graph.unresolved[:15])
        result.stage_timings["resolve"] = time.time() - stage_start

        refs = graph.all_refs
        if max_packages and len(refs) > max_packages:
            result.warnings.append(
                f"Scan limited to the {max_packages} shallowest of {len(refs)} packages"
            )
            ordered = sorted(graph.nodes.values(), key=lambda n: n.depth)[:max_packages]
            refs = [n.ref for n in ordered]

        if not refs:
            result.warnings.append("No dependencies were resolved")
            _summarise(result)
            return

        # --- Stage 3: detection ---------------------------------------- #
        stage_start = time.time()
        self._report("detect", 0.15, f"Analysing {len(refs)} packages...")
        resolver = ImportNameResolver()
        findings = await self._detect(http, refs, graph.nodes, resolver)
        result.packages = findings
        result.stage_timings["detect"] = time.time() - stage_start

        # --- Stage 4: advisories --------------------------------------- #
        stage_start = time.time()
        self._report("advise", 0.70, "Querying OSV for known vulnerabilities...")
        osv = OSVClient(http)
        try:
            advisories = await osv.query_batch(refs)
        except Exception as exc:  # noqa: BLE001 — detection results stay valid
            result.errors.append(f"Vulnerability lookup failed: {exc}")
            advisories = {}
        result.stage_timings["advise"] = time.time() - stage_start

        # --- Stage 5: reachability ------------------------------------- #
        stage_start = time.time()
        analyser: Optional[ReachabilityAnalyser] = None
        if project_root is not None:
            self._report("reach", 0.85, "Building the call graph...")
            analyser = ReachabilityAnalyser(project_root, manifest.ecosystem, resolver)
            result.reachability_available = analyser.available
            result.reachability_stats = analyser.stats()
            if not analyser.available:
                result.warnings.append(
                    "No application source found to analyse — every advisory is "
                    "reported as reachable (fail-safe)"
                )
        else:
            result.warnings.append(
                "No project source supplied, so reachability was not computed and "
                "all advisories are reported"
            )

        by_key = {f"{f.ecosystem}:{f.name.lower()}:{f.version}": f for f in findings}
        for ref in refs:
            finding = by_key.get(ref.key)
            if finding is None:
                continue
            for vulnerability in advisories.get(ref.key, []):
                reachability = (
                    analyser.analyse(ref.name, vulnerability.vulnerable_symbols)
                    if analyser is not None
                    else None
                )
                finding.vulnerabilities.append(_to_finding(vulnerability, ref, reachability))

        result.stage_timings["reach"] = time.time() - stage_start
        result.model_source = "model" if self.classifier.is_trained else "rules-baseline"
        _summarise(result)

    async def _detect(
        self,
        http: CachedHTTPClient,
        refs: list[PackageRef],
        nodes: dict[str, Any],
        resolver: Optional[ImportNameResolver] = None,
    ) -> list[PackageFinding]:
        """Download, analyse and score every package.

        Also records which modules each distribution provides. The packages are
        already downloaded here, so reading their top-level module names is free
        — and it is what lets reachability match ``import yaml`` against the
        ``pyyaml`` advisory.
        """
        npm = NpmClient(http)
        pypi = PyPIClient(http)
        semaphore = asyncio.Semaphore(8)
        completed = 0
        total = len(refs)

        async def _one(ref: PackageRef) -> PackageFinding:
            nonlocal completed
            node = nodes.get(ref.key)
            finding = PackageFinding(
                name=ref.name,
                version=ref.version,
                ecosystem=ref.ecosystem.value,
                depth=getattr(node, "depth", 0),
                is_direct=getattr(node, "is_direct", False),
                required_by=list(getattr(node, "required_by", []) or []),
            )

            try:
                async with semaphore:
                    if ref.ecosystem is Ecosystem.NPM:
                        metadata = await npm.fetch_metadata(ref.name, ref.version)
                        contents = await npm.fetch_contents(metadata)
                    else:
                        metadata = await pypi.fetch_metadata(ref.name, f"=={ref.version}")
                        contents = await pypi.fetch_contents(metadata)

                if resolver is not None:
                    resolver.record(ref.name, ref.ecosystem, contents)

                analysis = analyse_package(contents)
                prediction = self.classifier.predict(analysis.features, analysis.rules_score)

                finding.malice_score = round(prediction.probability, 4)
                finding.verdict = prediction.verdict
                finding.score_source = prediction.source
                finding.top_contributors = prediction.top_contributors
                finding.typosquat_target = analysis.typosquat_target
                finding.files_analysed = analysis.files_analysed
                # Keep the report readable: the highest-severity evidence only.
                finding.signals = analysis.top_signals(12)

            except (RegistryError, NotFoundError) as exc:
                finding.analysis_error = str(exc)
            except Exception as exc:  # noqa: BLE001 — one package must not fail a scan
                finding.analysis_error = f"Analysis failed: {exc}"
                logger.debug("Analysis failed for %s: %s", ref, exc)

            completed += 1
            if total and completed % 10 == 0:
                self._report(
                    "detect",
                    0.15 + 0.55 * (completed / total),
                    f"Analysed {completed}/{total} packages",
                )
            return finding

        return list(await asyncio.gather(*(_one(ref) for ref in refs)))


def _to_finding(
    vulnerability: Vulnerability,
    ref: PackageRef,
    reachability: Optional[ReachabilityResult],
) -> VulnerabilityFinding:
    """Merge an advisory with its reachability verdict."""
    finding = VulnerabilityFinding(
        id=vulnerability.id,
        cve_id=vulnerability.cve_id,
        package=ref.name,
        version=ref.version,
        ecosystem=ref.ecosystem.value,
        severity=vulnerability.severity,
        cvss_score=vulnerability.cvss_score,
        summary=vulnerability.summary,
        fixed_version=vulnerability.fixed_version,
        references=vulnerability.references,
        vulnerable_symbols=vulnerability.vulnerable_symbols,
        symbol_confidence=vulnerability.symbol_confidence,
    )

    if reachability is None:
        # No reachability analysis was run. Fail safe: report it.
        finding.reachable = True
        finding.reachability_verdict = Verdict.NOT_ANALYSED.value
        finding.reachability_reason = "Reachability analysis was not run for this scan"
        finding.reachability_confidence = "none"
        return finding

    finding.reachable = reachability.is_reachable
    finding.reachability_verdict = reachability.verdict.value
    finding.reachability_reason = reachability.reason
    finding.reachability_confidence = reachability.confidence
    finding.matched_symbol = reachability.matched_symbol
    finding.imported_by = reachability.imported_by
    finding.call_path = [
        {"caller": step.caller, "callee": step.callee, "file": step.file, "line": step.line}
        for step in reachability.call_path
    ]
    return finding


def _summarise(result: ScanResult) -> None:
    """Populate the summary from the collected findings."""
    summary = ScanSummary()
    summary.total_packages = len(result.packages)
    summary.direct_packages = sum(1 for p in result.packages if p.is_direct)
    summary.max_depth = max((p.depth for p in result.packages), default=0)
    summary.malicious_packages = sum(1 for p in result.packages if p.verdict == "malicious")
    summary.suspicious_packages = sum(1 for p in result.packages if p.verdict == "suspicious")

    for vulnerability in result.all_vulnerabilities():
        summary.total_vulnerabilities += 1
        severity = vulnerability.severity.upper()
        summary.by_severity[severity] = summary.by_severity.get(severity, 0) + 1
        if vulnerability.reachable:
            summary.reachable_vulnerabilities += 1
            summary.reachable_by_severity[severity] = (
                summary.reachable_by_severity.get(severity, 0) + 1
            )
        else:
            summary.unreachable_vulnerabilities += 1

    result.summary = summary
