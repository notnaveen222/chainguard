"""The analysis engine: package contents in, signals and features out.

Orchestrates the per-file analysers, then performs the two passes that no single
file analyser can do on its own:

* **Composite derivation.** Reading the environment is unremarkable. Making an
  HTTP request is unremarkable. Doing both in one file is the shape of credential
  theft. Composites are computed from the per-file behaviour flags after all
  files have been analysed.
* **Package-level context.** Metadata heuristics, typosquat comparison, and
  propagation of install-time reachability into the files an install hook runs.

The result is an :class:`AnalysisResult` carrying both the numeric feature vector
(for the classifier) and the ordered evidence list (for a human).
"""

from __future__ import annotations

import re
import time
from typing import Optional

from pydantic import BaseModel, Field

from chainguard.analysis.base import FileAnalysis
from chainguard.analysis.dataflow import ConfirmedFlow
from chainguard.analysis.features import PackageFeatures, build_features
from chainguard.analysis.js_ast import analyse_javascript_file
from chainguard.analysis.python_ast import analyse_python_file
from chainguard.analysis.shell import analyse_install_command
from chainguard.analysis.signals import Severity, Signal, make_signal, rules_score
from chainguard.analysis.typosquat import TyposquatMatch, find_typosquat
from chainguard.config import get_settings
from chainguard.logging_setup import get_logger
from chainguard.models.package import (
    Ecosystem,
    PackageContents,
    PackageFile,
    PackageMetadata,
    PackageRef,
)

logger = get_logger(__name__)

_PYTHON_SUFFIXES = frozenset({".py", ".pyi"})
_JS_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".jsx"})

# Paths that are almost always vendored dependencies or build output rather than
# the package's own code. Analysing them inflates every count and attributes
# another project's behaviour to this package.
_SKIP_PATH_RE = re.compile(
    r"(^|/)(node_modules|\.git|test|tests|__tests__|spec|__pycache__|"
    r"site-packages|vendor|third_party|examples?|docs?|fixtures?|benchmarks?)(/|$)",
    re.IGNORECASE,
)

# A .js path mentioned inside an npm lifecycle hook, so the file it runs can be
# marked as executing at install time.
_HOOK_SCRIPT_RE = re.compile(r"[\w./\\-]+\.(?:js|cjs|mjs)\b")


class AnalysisResult(BaseModel):
    """Everything the engine learned about one package."""

    ref: PackageRef
    signals: list[Signal] = Field(default_factory=list)
    features: PackageFeatures = Field(default_factory=PackageFeatures)

    #: Traced credential-exfiltration paths (analysis/dataflow.py), carried
    #: through so a project scan can classify each one's exposure — see
    #: analysis/exposure.py and Stage 5 in scanner.py.
    confirmed_flows: list[ConfirmedFlow] = Field(default_factory=list)

    typosquat_target: Optional[str] = None
    typosquat_kind: Optional[str] = None

    files_analysed: int = 0
    files_skipped: int = 0
    duration_seconds: float = 0.0
    truncated: bool = False
    truncation_reason: Optional[str] = None

    @property
    def rules_score(self) -> float:
        """Baseline rules-only score. Kept for the ML-vs-rules comparison."""
        return rules_score(self.signals)

    @property
    def critical_signals(self) -> list[Signal]:
        return [s for s in self.signals if s.severity is Severity.CRITICAL]

    def top_signals(self, limit: int = 10) -> list[Signal]:
        """Distinct signals ordered by severity, for display.

        Collapsed by code, keeping the highest-severity occurrence and recording
        how many times it fired. A large package can trigger the same signal in
        a dozen files — `pillow` produces twelve `DYNAMIC_EVAL` hits — and twelve
        near-identical rows crowd out every other kind of evidence in a report.

        Only the display is affected. Feature extraction reads ``self.signals``,
        the uncollapsed list, so per-occurrence counts still reach the model.
        """
        collapsed: dict[str, Signal] = {}
        for signal in sorted(self.signals, key=lambda s: -s.severity.rank):
            existing = collapsed.get(signal.code)
            if existing is None:
                collapsed[signal.code] = signal.model_copy(update={"occurrences": 1})
            else:
                existing.occurrences += 1

        return sorted(
            collapsed.values(), key=lambda s: (-s.severity.rank, -s.occurrences)
        )[:limit]


def _should_skip(path: str) -> bool:
    return bool(_SKIP_PATH_RE.search(path))


def _analyse_file(file: PackageFile) -> Optional[FileAnalysis]:
    """Dispatch one file to the analyser for its language."""
    suffix = file.suffix
    if suffix in _PYTHON_SUFFIXES:
        return analyse_python_file(file.path, file.text())
    if suffix in _JS_SUFFIXES:
        return analyse_javascript_file(file.path, file.text())
    return None


def _install_entry_points(metadata: Optional[PackageMetadata]) -> set[str]:
    """Filenames referenced by npm lifecycle hooks.

    Behaviour inside these files runs during ``npm install``, which raises its
    significance sharply: the same code in a lazily-imported module might never
    execute at all.
    """
    if metadata is None:
        return set()
    entry_points: set[str] = set()
    for command in metadata.install_scripts.values():
        for match in _HOOK_SCRIPT_RE.findall(command or ""):
            entry_points.add(match.lstrip("./").replace("\\", "/"))
    return entry_points


def _derive_composites(analyses: list[FileAnalysis]) -> list[Signal]:
    """Derive co-occurrence signals from per-file behaviour flags."""
    signals: list[Signal] = []

    for analysis in analyses:
        install_note = " during installation" if analysis.runs_at_install else ""

        if analysis.has_sensitive_path and analysis.has_network:
            signals.append(
                make_signal(
                    "EXFIL_CREDENTIALS_TO_NETWORK",
                    file=analysis.path,
                    detail=(
                        "This file both reads credential material and performs network "
                        f"I/O{install_note} — the two behaviours together are what make "
                        "this conclusive"
                    ),
                )
            )
        elif analysis.has_env_access and analysis.has_network and (
            analysis.has_host_recon or analysis.runs_at_install
        ):
            # Environment access plus network is extremely common in benign
            # config-loading code, so a third corroborating behaviour is required
            # before calling it exfiltration. Without this the false-positive rate
            # is unusable.
            signals.append(
                make_signal(
                    "EXFIL_ENV_TO_NETWORK",
                    file=analysis.path,
                    detail=(
                        "Reads environment variables, collects host information and "
                        f"performs network I/O in the same file{install_note}"
                    ),
                )
            )

        # Exfiltration at install time requires *both* halves: something worth
        # stealing being read, and a way to send it.
        #
        # An earlier version fired on `runs_at_install AND (network OR sensitive
        # path OR dynamic exec)`, which was badly wrong. `exec(open('version.py')
        # .read())` is the standard way real packages load their version string
        # in setup.py, so dynamic-exec-at-install-time flagged pillow, lxml,
        # flask, urllib3 and requests as malicious with scores above 0.9.
        if (
            analysis.runs_at_install
            and analysis.has_network
            and (
                analysis.has_env_access
                or analysis.has_sensitive_path
                or analysis.has_host_recon
            )
        ):
            signals.append(
                make_signal(
                    "EXFIL_ON_INSTALL",
                    file=analysis.path,
                    detail=(
                        "A file that runs automatically at install time both collects "
                        "local data and performs network I/O"
                    ),
                )
            )

    return signals


def _metadata_signals(
    metadata: Optional[PackageMetadata], source_file_count: int, total_bytes: int
) -> list[Signal]:
    """Heuristics over registry metadata."""
    if metadata is None:
        return []

    signals: list[Signal] = []

    if not metadata.has_repository:
        signals.append(
            make_signal(
                "NO_REPOSITORY",
                detail="No source repository declared, so shipped code cannot be compared to public source",
            )
        )

    age = metadata.age_days
    if age is not None and age < 7:
        signals.append(
            make_signal(
                "VERY_NEW_PACKAGE",
                detail=f"Published {age:.1f} days ago",
            )
        )

    # A count of 0 means "unknown", not "one version". Registry metadata always
    # reports at least 1, so 0 only occurs when metadata was reconstructed from
    # inside an archive — as it is for every sample during dataset construction.
    # Emitting the signal there would fire it on 100% of both classes, adding
    # noise to the aggregate counts while carrying no information.
    if metadata.version_count == 1:
        signals.append(
            make_signal("SINGLE_VERSION", detail="Only one version has ever been published")
        )

    if not (metadata.description or "").strip():
        signals.append(make_signal("EMPTY_DESCRIPTION", detail="No description published"))

    has_hook = bool(metadata.install_scripts)
    if has_hook and source_file_count <= 3 and total_bytes < 20_000:
        signals.append(
            make_signal(
                "TINY_PACKAGE_WITH_HOOK",
                detail=(
                    f"Ships {source_file_count} source file(s) totalling {total_bytes} bytes "
                    "but executes code at install time"
                ),
            )
        )

    return signals


def _typosquat_signal(match: TyposquatMatch) -> Signal:
    code = {
        "homoglyph": "TYPOSQUAT_HOMOGLYPH",
        "scope": "TYPOSQUAT_SCOPE_CONFUSION",
    }.get(match.kind, "TYPOSQUAT_NEAR_MISS")
    return make_signal(code, detail=match.explanation, evidence=f"{match.candidate} → {match.target}")


def analyse_package(
    contents: PackageContents,
    *,
    check_typosquat: bool = True,
) -> AnalysisResult:
    """Run the full static analysis pipeline over one package."""
    started = time.monotonic()
    settings = get_settings()
    limits = settings.limits

    metadata = contents.metadata
    ref = contents.ref

    result = AnalysisResult(
        ref=ref,
        truncated=contents.truncated,
        truncation_reason=contents.truncation_reason,
    )
    signals: list[Signal] = []

    # --- npm lifecycle hooks ------------------------------------------------ #
    # Checked first and unconditionally: hooks execute before any of the
    # package's own source is imported, so they matter even if every file below
    # is skipped.
    if metadata is not None:
        for hook, command in metadata.install_scripts.items():
            signals.extend(analyse_install_command(hook, command))

    entry_points = _install_entry_points(metadata)

    # --- per-file analysis --------------------------------------------------- #
    analyses: list[FileAnalysis] = []
    skipped = 0
    deadline = started + limits.analysis_timeout_seconds

    for file in contents.files:
        if len(analyses) >= limits.max_files_per_package:
            result.truncated = True
            result.truncation_reason = f"analysis capped at {limits.max_files_per_package} files"
            break
        if time.monotonic() > deadline:
            result.truncated = True
            result.truncation_reason = (
                f"analysis exceeded the {limits.analysis_timeout_seconds:.0f}s time limit"
            )
            logger.warning("Analysis of %s timed out", ref)
            break

        if _should_skip(file.path):
            skipped += 1
            continue
        if file.size > limits.max_file_bytes:
            skipped += 1
            continue

        try:
            analysis = _analyse_file(file)
        except Exception as exc:  # noqa: BLE001 — hostile input must never crash a scan
            logger.debug("Analyser failed on %s: %s", file.path, exc)
            skipped += 1
            continue

        if analysis is None:
            continue

        basename = file.path.rsplit("/", 1)[-1]
        if basename == "setup.py" or file.path in entry_points or basename in entry_points:
            analysis.runs_at_install = True

        analyses.append(analysis)
        signals.extend(analysis.signals)

    # --- package-level passes -------------------------------------------------- #
    signals.extend(_derive_composites(analyses))

    source_file_count = sum(
        1 for a in analyses if any(a.path.endswith(e) for e in (*_PYTHON_SUFFIXES, *_JS_SUFFIXES))
    )
    signals.extend(_metadata_signals(metadata, source_file_count, contents.total_bytes))

    typosquat: Optional[TyposquatMatch] = None
    if check_typosquat:
        typosquat = find_typosquat(ref.name, ref.ecosystem)
        if typosquat is not None:
            signals.append(_typosquat_signal(typosquat))
            result.typosquat_target = typosquat.target
            result.typosquat_kind = typosquat.kind

    # --- assemble --------------------------------------------------------------- #
    for analysis in analyses:
        result.confirmed_flows.extend(analysis.confirmed_flows)
    result.signals = sorted(signals, key=lambda s: (-s.severity.rank, s.code))
    result.features = build_features(
        signals=result.signals,
        file_analyses=analyses,
        metadata=metadata,
        typosquat=typosquat,
        file_count=contents.file_count,
        total_bytes=contents.total_bytes,
    )
    result.files_analysed = len(analyses)
    result.files_skipped = skipped
    result.duration_seconds = time.monotonic() - started

    return result


def analyse_source_text(
    name: str,
    version: str,
    ecosystem: Ecosystem,
    files: dict[str, str],
    metadata: Optional[PackageMetadata] = None,
) -> AnalysisResult:
    """Analyse loose source text without downloading anything.

    Used by the training pipeline (which decodes samples from the quarantine
    vault into memory) and by the test suite.
    """
    contents = PackageContents(
        ref=PackageRef(name=name, version=version, ecosystem=ecosystem),
        metadata=metadata,
        files=[PackageFile(path=path, content=text.encode("utf-8", errors="replace"))
               for path, text in files.items()],
    )
    return analyse_package(contents)
