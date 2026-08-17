"""The feature vector: how a package becomes numbers the classifier can learn.

Design constraints, in priority order:

1. **Fixed length and stable order.** A model trained on schema v1 must never be
   fed a v2 vector. ``SCHEMA_VERSION`` is persisted with the model and checked at
   inference time, because a silently reordered vector produces confident
   nonsense rather than an error.
2. **Every feature is nameable.** Feature-importance output is only useful if
   each column corresponds to something explainable to a human. There are no
   anonymous embedding dimensions here.
3. **Grouped by category.** Groups map onto :class:`SignalCategory`, which is
   what makes the ablation study in ARCHITECTURE.md §8 possible — whole families
   can be zeroed out to measure their contribution.

Counts are ``log1p``-compressed. A package with 400 network calls is not 400×
more suspicious than one with a single call; without compression, large legitimate
libraries would dominate the feature space purely by being large.
"""

from __future__ import annotations

import math
from typing import Optional

from pydantic import BaseModel, Field

from chainguard.analysis.base import FileAnalysis
from chainguard.analysis.signals import Severity, Signal, SignalCategory, rules_score
from chainguard.analysis.typosquat import TyposquatMatch
from chainguard.models.package import PackageMetadata

#: Bumped whenever the feature list changes in any way. Persisted alongside the
#: trained model; a mismatch is a hard error, never a silent coercion.
SCHEMA_VERSION = 1


def _log1p(value: float) -> float:
    return math.log1p(max(0.0, float(value)))


class PackageFeatures(BaseModel):
    """The numeric representation of one package."""

    schema_version: int = Field(default=SCHEMA_VERSION)

    # --- Install-time execution -------------------------------------------- #
    install_hook_present: float = 0.0
    install_hook_count: float = 0.0
    install_hook_network: float = 0.0
    install_hook_shell_pipe: float = 0.0
    install_hook_obfuscated: float = 0.0
    setup_py_side_effects: float = 0.0

    # --- Dynamic execution -------------------------------------------------- #
    dynamic_eval: float = 0.0
    decode_then_exec: float = 0.0
    dynamic_import: float = 0.0

    # --- Process spawning --------------------------------------------------- #
    process_spawn: float = 0.0
    shell_execution: float = 0.0
    reverse_shell: float = 0.0

    # --- Network ------------------------------------------------------------ #
    network_access: float = 0.0
    hardcoded_ip: float = 0.0
    suspicious_endpoint: float = 0.0
    dns_exfil: float = 0.0

    # --- Credential and filesystem access ----------------------------------- #
    sensitive_path_access: float = 0.0
    crypto_wallet_access: float = 0.0
    env_access: float = 0.0
    env_bulk_harvest: float = 0.0
    file_write_sensitive: float = 0.0
    host_recon: float = 0.0

    # --- Obfuscation -------------------------------------------------------- #
    high_entropy_string: float = 0.0
    base64_blob: float = 0.0
    charcode_obfuscation: float = 0.0
    hex_escape_heavy: float = 0.0
    string_array_decoder: float = 0.0
    minified_ratio: float = 0.0
    max_line_length: float = 0.0
    parse_failure_ratio: float = 0.0

    # --- Composite exfiltration --------------------------------------------- #
    # The highest-value features: co-occurrence within a single file, which no
    # individual detector can observe.
    exfil_env_to_network: float = 0.0
    exfil_credentials_to_network: float = 0.0
    exfil_on_install: float = 0.0

    # --- Registry metadata --------------------------------------------------- #
    has_repository: float = 0.0
    age_days: float = 0.0
    version_count: float = 0.0
    maintainer_count: float = 0.0
    description_length: float = 0.0
    dependency_count: float = 0.0
    is_single_version: float = 0.0
    has_empty_description: float = 0.0
    is_very_new: float = 0.0

    # --- Package structure ---------------------------------------------------- #
    file_count: float = 0.0
    total_bytes: float = 0.0
    source_file_count: float = 0.0
    avg_file_bytes: float = 0.0
    source_file_ratio: float = 0.0
    tiny_package_with_hook: float = 0.0

    # --- Typosquatting -------------------------------------------------------- #
    typosquat_proximity: float = Field(
        default=0.0,
        description="0 = no resemblance; approaches 1 as edit distance approaches 0.",
    )
    typosquat_homoglyph: float = 0.0
    typosquat_scope_confusion: float = 0.0
    typosquat_affix: float = 0.0

    # --- Aggregates ----------------------------------------------------------- #
    critical_signals: float = 0.0
    high_signals: float = 0.0
    medium_signals: float = 0.0
    total_signals: float = 0.0
    distinct_signal_types: float = 0.0
    rules_baseline_score: float = 0.0

    # ------------------------------------------------------------------------ #

    def to_vector(self) -> list[float]:
        """Return features in canonical order."""
        return [float(getattr(self, name)) for name in FEATURE_NAMES]

    @classmethod
    def from_vector(cls, vector: list[float]) -> PackageFeatures:
        if len(vector) != len(FEATURE_NAMES):
            raise ValueError(
                f"Expected {len(FEATURE_NAMES)} features, got {len(vector)}"
            )
        return cls(**dict(zip(FEATURE_NAMES, vector)))


#: Canonical feature order. Deriving this from the model definition means the
#: order can never drift from the fields themselves.
FEATURE_NAMES: list[str] = [
    name for name in PackageFeatures.model_fields if name != "schema_version"
]

#: Feature groups, used for the ablation study and for grouping the
#: feature-importance chart by behaviour family.
FEATURE_GROUPS: dict[str, list[str]] = {
    "install_execution": [
        "install_hook_present", "install_hook_count", "install_hook_network",
        "install_hook_shell_pipe", "install_hook_obfuscated", "setup_py_side_effects",
    ],
    "dynamic_execution": ["dynamic_eval", "decode_then_exec", "dynamic_import"],
    "process": ["process_spawn", "shell_execution", "reverse_shell"],
    "network": ["network_access", "hardcoded_ip", "suspicious_endpoint", "dns_exfil"],
    "credentials": [
        "sensitive_path_access", "crypto_wallet_access", "env_access",
        "env_bulk_harvest", "file_write_sensitive", "host_recon",
    ],
    "obfuscation": [
        "high_entropy_string", "base64_blob", "charcode_obfuscation",
        "hex_escape_heavy", "string_array_decoder", "minified_ratio",
        "max_line_length", "parse_failure_ratio",
    ],
    "exfiltration": [
        "exfil_env_to_network", "exfil_credentials_to_network", "exfil_on_install",
    ],
    "metadata": [
        "has_repository", "age_days", "version_count", "maintainer_count",
        "description_length", "dependency_count", "is_single_version",
        "has_empty_description", "is_very_new",
    ],
    "structure": [
        "file_count", "total_bytes", "source_file_count", "avg_file_bytes",
        "source_file_ratio", "tiny_package_with_hook",
    ],
    "typosquat": [
        "typosquat_proximity", "typosquat_homoglyph",
        "typosquat_scope_confusion", "typosquat_affix",
    ],
    "aggregate": [
        "critical_signals", "high_signals", "medium_signals", "total_signals",
        "distinct_signal_types", "rules_baseline_score",
    ],
}

#: Maps a signal code to the feature it increments. Codes absent from this map
#: contribute only through the severity aggregates.
_SIGNAL_TO_FEATURE: dict[str, str] = {
    "INSTALL_HOOK_PRESENT": "install_hook_present",
    "INSTALL_HOOK_NETWORK": "install_hook_network",
    "INSTALL_HOOK_SHELL_PIPE": "install_hook_shell_pipe",
    "INSTALL_HOOK_OBFUSCATED": "install_hook_obfuscated",
    "SETUP_PY_SIDE_EFFECTS": "setup_py_side_effects",
    "DYNAMIC_EVAL": "dynamic_eval",
    "DECODE_THEN_EXEC": "decode_then_exec",
    "DYNAMIC_IMPORT": "dynamic_import",
    "PROCESS_SPAWN": "process_spawn",
    "SHELL_TRUE": "shell_execution",
    "REVERSE_SHELL_PATTERN": "reverse_shell",
    "NETWORK_ACCESS": "network_access",
    "HARDCODED_IP_ENDPOINT": "hardcoded_ip",
    "SUSPICIOUS_ENDPOINT": "suspicious_endpoint",
    "DNS_EXFIL_PATTERN": "dns_exfil",
    "SENSITIVE_PATH_ACCESS": "sensitive_path_access",
    "CRYPTO_WALLET_ACCESS": "crypto_wallet_access",
    "ENV_ACCESS": "env_access",
    "ENV_BULK_HARVEST": "env_bulk_harvest",
    "FILE_WRITE_SENSITIVE": "file_write_sensitive",
    "HOST_RECON": "host_recon",
    "HIGH_ENTROPY_STRING": "high_entropy_string",
    "BASE64_BLOB": "base64_blob",
    "CHARCODE_OBFUSCATION": "charcode_obfuscation",
    "HEX_ESCAPE_HEAVY": "hex_escape_heavy",
    "STRING_ARRAY_DECODER": "string_array_decoder",
    "EXFIL_ENV_TO_NETWORK": "exfil_env_to_network",
    "EXFIL_CREDENTIALS_TO_NETWORK": "exfil_credentials_to_network",
    "EXFIL_ON_INSTALL": "exfil_on_install",
    "TYPOSQUAT_HOMOGLYPH": "typosquat_homoglyph",
    "TYPOSQUAT_SCOPE_CONFUSION": "typosquat_scope_confusion",
}

_SOURCE_EXTENSIONS = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".py", ".pyi"})


def build_features(
    signals: list[Signal],
    file_analyses: list[FileAnalysis],
    metadata: Optional[PackageMetadata] = None,
    typosquat: Optional[TyposquatMatch] = None,
    *,
    file_count: int = 0,
    total_bytes: int = 0,
) -> PackageFeatures:
    """Assemble a feature vector from analysis output."""
    features = PackageFeatures()

    # --- signal counts ------------------------------------------------------ #
    counts: dict[str, int] = {}
    for signal in signals:
        counts[signal.code] = counts.get(signal.code, 0) + 1

    for code, count in counts.items():
        field_name = _SIGNAL_TO_FEATURE.get(code)
        if field_name:
            setattr(features, field_name, _log1p(count))

    features.install_hook_count = _log1p(counts.get("INSTALL_HOOK_PRESENT", 0))

    # --- severity aggregates ------------------------------------------------- #
    by_severity: dict[Severity, int] = {}
    for signal in signals:
        by_severity[signal.severity] = by_severity.get(signal.severity, 0) + 1

    features.critical_signals = _log1p(by_severity.get(Severity.CRITICAL, 0))
    features.high_signals = _log1p(by_severity.get(Severity.HIGH, 0))
    features.medium_signals = _log1p(by_severity.get(Severity.MEDIUM, 0))
    features.total_signals = _log1p(len(signals))
    features.distinct_signal_types = _log1p(len(counts))
    features.rules_baseline_score = rules_score(signals)

    # --- structural measurements --------------------------------------------- #
    features.file_count = _log1p(file_count or len(file_analyses))
    features.total_bytes = _log1p(total_bytes)

    source_files = [
        f for f in file_analyses
        if any(f.path.endswith(ext) for ext in _SOURCE_EXTENSIONS)
    ]
    features.source_file_count = _log1p(len(source_files))
    if file_count:
        features.source_file_ratio = len(source_files) / file_count
    if file_analyses:
        analysed_bytes = sum(f.byte_count for f in file_analyses)
        features.avg_file_bytes = _log1p(analysed_bytes / len(file_analyses))
        features.minified_ratio = sum(1 for f in file_analyses if f.is_minified) / len(file_analyses)
        features.parse_failure_ratio = (
            sum(1 for f in file_analyses if f.parse_failed) / len(file_analyses)
        )
        features.max_line_length = _log1p(max((f.max_line_length for f in file_analyses), default=0))

    # A package that ships almost no code but still executes on install is a
    # dropper rather than a library. Encoded as its own feature because the
    # combination is meaningful in a way neither part is alone.
    has_hook = counts.get("INSTALL_HOOK_PRESENT", 0) > 0 or counts.get(
        "SETUP_PY_SIDE_EFFECTS", 0
    ) > 0
    if has_hook and len(source_files) <= 3 and total_bytes < 20_000:
        features.tiny_package_with_hook = 1.0

    # --- registry metadata ---------------------------------------------------- #
    if metadata is not None:
        features.has_repository = 1.0 if metadata.has_repository else 0.0
        age = metadata.age_days
        if age is not None:
            features.age_days = _log1p(age)
            features.is_very_new = 1.0 if age < 7 else 0.0
        features.version_count = _log1p(metadata.version_count)
        features.maintainer_count = _log1p(metadata.maintainer_count)
        features.description_length = _log1p(len(metadata.description or ""))
        features.dependency_count = _log1p(len(metadata.dependency_names))
        features.is_single_version = 1.0 if metadata.version_count <= 1 else 0.0
        features.has_empty_description = 0.0 if (metadata.description or "").strip() else 1.0

    # --- typosquatting --------------------------------------------------------- #
    if typosquat is not None:
        # Inverted so that closer resemblance is a larger number, which reads
        # correctly on a feature-importance chart.
        features.typosquat_proximity = 1.0 / (1.0 + typosquat.distance)
        features.typosquat_homoglyph = 1.0 if typosquat.kind == "homoglyph" else 0.0
        features.typosquat_scope_confusion = 1.0 if typosquat.kind == "scope" else 0.0
        features.typosquat_affix = 1.0 if typosquat.kind in {"affix", "separator"} else 0.0

    return features


def group_of(feature_name: str) -> Optional[str]:
    """Return the group a feature belongs to."""
    for group, names in FEATURE_GROUPS.items():
        if feature_name in names:
            return group
    return None


def category_to_group(category: SignalCategory) -> str:
    """Map a signal category onto its feature group name."""
    return {
        SignalCategory.INSTALL_HOOK: "install_execution",
        SignalCategory.DYNAMIC_EXEC: "dynamic_execution",
        SignalCategory.PROCESS_SPAWN: "process",
        SignalCategory.NETWORK: "network",
        SignalCategory.FILESYSTEM: "credentials",
        SignalCategory.CREDENTIAL_ACCESS: "credentials",
        SignalCategory.OBFUSCATION: "obfuscation",
        SignalCategory.EXFILTRATION: "exfiltration",
        SignalCategory.METADATA: "metadata",
        SignalCategory.TYPOSQUAT: "typosquat",
    }[category]
