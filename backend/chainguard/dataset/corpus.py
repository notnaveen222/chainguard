"""Turning stored samples into a labelled feature matrix.

Preventing label leakage
------------------------
This is the most important design decision in the training pipeline, and getting
it wrong would invalidate every number the project reports.

Malicious samples come from an archived research dataset. The packages they
describe were removed from npm and PyPI years ago, so no live registry metadata
exists for them: no publication date, no version count, no maintainer list.
Benign samples are downloaded from the live registries and have all of it.

If registry metadata were fed to the classifier, ``version_count > 0`` would
separate the two classes perfectly — not because it detects malware, but because
it detects *which corpus a sample came from*. The model would report near-perfect
accuracy and be worthless on real input.

Two rules follow, and both are enforced here rather than left to convention:

1. **Metadata is reconstructed from inside the archive only** — from the
   ``package.json`` or ``PKG-INFO`` that ships with the package. Both classes are
   treated identically, and the fields available are exactly the fields an
   attacker also controls.
2. **Registry-only features are zeroed for every sample.** ``age_days``,
   ``version_count``, ``maintainer_count``, ``is_single_version`` and
   ``is_very_new`` are set to zero on both classes, so they cannot carry
   corpus-of-origin information. They remain in the schema and are still
   populated at *scan* time, where the information is real and symmetric.

The cost is that the model cannot use "this package was published yesterday" as
evidence. That is the correct trade: a feature that is only available for one
class in training is not a feature, it is a label.
"""

from __future__ import annotations

import io
import json
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import Any, Optional

from chainguard.analysis.engine import AnalysisResult, analyse_package
from chainguard.analysis.features import FEATURE_NAMES
from chainguard.dataset.sources import extract_encrypted_sample
from chainguard.dataset.vault import SampleRecord, SampleVault
from chainguard.logging_setup import get_logger
from chainguard.models.package import (
    Ecosystem,
    PackageContents,
    PackageFile,
    PackageMetadata,
    PackageRef,
)

logger = get_logger(__name__)

#: Features that exist only for packages still live on a registry. Zeroed during
#: dataset construction — see the module docstring.
REGISTRY_ONLY_FEATURES = (
    "age_days",
    "version_count",
    "maintainer_count",
    "is_single_version",
    "is_very_new",
)


@dataclass
class LabelledSample:
    """One row of the training matrix."""

    sample_id: str
    name: str
    version: str
    ecosystem: str
    label: int  # 1 = malicious, 0 = benign
    group: str  # package family, used to keep near-duplicates on one side of the split
    features: list[float]
    signal_codes: list[str] = field(default_factory=list)
    file_count: int = 0
    source: str = ""


def _decode_archive(record: SampleRecord, payload: bytes) -> dict[str, bytes]:
    """Recover a sample's files from its stored archive, in memory."""
    if record.archive_format == "encrypted-zip":
        return extract_encrypted_sample(payload)

    # Benign samples are ordinary registry distributions.
    try:
        if payload[:2] == b"\x1f\x8b":
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
                return {
                    member.name.replace("\\", "/"): (
                        archive.extractfile(member).read()  # type: ignore[union-attr]
                        if archive.extractfile(member)
                        else b""
                    )
                    for member in archive
                    if member.isfile() and member.size <= 2 * 1024 * 1024
                }
        if payload[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                return {
                    info.filename.replace("\\", "/"): archive.read(info)
                    for info in archive.infolist()
                    if not info.is_dir() and info.file_size <= 2 * 1024 * 1024
                }
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError) as exc:
        logger.debug("Could not decode archive for %s: %s", record.sample_id, exc)
    return {}


def _strip_common_prefix(files: dict[str, bytes]) -> dict[str, bytes]:
    """Drop the wrapper directory that registry archives add."""
    if not files:
        return files
    first = next(iter(files))
    if "/" not in first:
        return files
    prefix = first.split("/", 1)[0] + "/"
    if not all(path.startswith(prefix) for path in files):
        return files
    return {path[len(prefix):]: data for path, data in files.items()}


def metadata_from_archive(
    files: dict[str, bytes], name: str, version: str, ecosystem: Ecosystem
) -> PackageMetadata:
    """Reconstruct metadata using only what ships inside the package.

    Symmetric across both classes by construction: every field here comes from a
    file the package author wrote and shipped, which is equally available for an
    archived malicious sample and a live benign one.
    """
    metadata = PackageMetadata(name=name, version=version, ecosystem=ecosystem)

    def _find(basename: str) -> Optional[bytes]:
        matches = [p for p in files if p.rsplit("/", 1)[-1] == basename]
        return files[min(matches, key=lambda p: p.count("/"))] if matches else None

    if ecosystem is Ecosystem.NPM:
        raw = _find("package.json")
        if raw:
            try:
                document = json.loads(raw.decode("utf-8", errors="replace"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                document = {}
            if isinstance(document, dict):
                metadata.description = (
                    document.get("description") if isinstance(document.get("description"), str) else None
                )
                repository = document.get("repository")
                if isinstance(repository, str):
                    metadata.repository_url = repository or None
                elif isinstance(repository, dict) and isinstance(repository.get("url"), str):
                    metadata.repository_url = repository["url"] or None
                if isinstance(document.get("license"), str):
                    metadata.license = document["license"]
                if isinstance(document.get("homepage"), str):
                    metadata.homepage = document["homepage"]

                scripts = document.get("scripts")
                if isinstance(scripts, dict):
                    metadata.install_scripts = {
                        hook: str(body)
                        for hook, body in scripts.items()
                        if hook in ("preinstall", "install", "postinstall", "prepare", "prepublish")
                        and body
                    }

                dependencies = document.get("dependencies")
                if isinstance(dependencies, dict):
                    metadata.dependency_names = sorted(str(k) for k in dependencies)
    else:
        raw = _find("PKG-INFO") or _find("METADATA")
        if raw:
            text = raw.decode("utf-8", errors="replace")
            for line in text.splitlines():
                if line.startswith("Summary:"):
                    metadata.description = line.split(":", 1)[1].strip() or None
                elif line.startswith("Home-page:"):
                    metadata.homepage = line.split(":", 1)[1].strip() or None
                elif line.startswith("License:"):
                    metadata.license = line.split(":", 1)[1].strip() or None
                elif line.startswith("Project-URL:") and not metadata.repository_url:
                    value = line.split(":", 1)[1].strip()
                    if any(k in value.lower() for k in ("source", "repository", "github")):
                        metadata.repository_url = value

    return metadata


def analyse_sample(record: SampleRecord, payload: bytes) -> Optional[AnalysisResult]:
    """Decode and statically analyse one stored sample."""
    files = _strip_common_prefix(_decode_archive(record, payload))
    if not files:
        return None

    ecosystem = Ecosystem(record.ecosystem)
    metadata = metadata_from_archive(files, record.name, record.version, ecosystem)

    contents = PackageContents(
        ref=PackageRef(name=record.name, version=record.version or "0.0.0", ecosystem=ecosystem),
        metadata=metadata,
        files=[PackageFile(path=path, content=data) for path, data in files.items()],
    )
    return analyse_package(contents)


def build_matrix(vault: SampleVault, *, progress_every: int = 100) -> list[LabelledSample]:
    """Analyse every stored sample and return the labelled feature matrix."""
    samples: list[LabelledSample] = []
    records = list(vault.records())
    failures = 0

    for index, record in enumerate(records, start=1):
        payload = vault.get(record.sample_id)
        if payload is None:
            failures += 1
            continue

        try:
            result = analyse_sample(record, payload)
        except Exception as exc:  # noqa: BLE001 — one bad sample must not stop a build
            logger.debug("Analysis failed for %s: %s", record.sample_id, exc)
            failures += 1
            continue

        if result is None:
            failures += 1
            continue

        features = result.features
        # Enforce the leakage rule at the point of matrix construction, so it
        # cannot be bypassed by a caller building features another way.
        for name in REGISTRY_ONLY_FEATURES:
            setattr(features, name, 0.0)

        samples.append(
            LabelledSample(
                sample_id=record.sample_id,
                name=record.name,
                version=record.version,
                ecosystem=record.ecosystem,
                label=1 if record.label == "malicious" else 0,
                # Grouping key: the package name. Different versions of one
                # package, and repeat uploads from one campaign, must not be
                # split across train and test.
                group=f"{record.ecosystem}:{record.name.lower()}",
                features=features.to_vector(),
                signal_codes=sorted({s.code for s in result.signals}),
                file_count=result.files_analysed,
                source=record.source,
            )
        )

        if progress_every and index % progress_every == 0:
            logger.info("Analysed %d/%d samples", index, len(records))

    if failures:
        logger.warning(
            "%d of %d samples could not be analysed and were excluded", failures, len(records)
        )
    return samples


def matrix_summary(samples: list[LabelledSample]) -> dict[str, Any]:
    """Summarise a built matrix, for the dataset card and build log."""
    malicious = [s for s in samples if s.label == 1]
    benign = [s for s in samples if s.label == 0]

    by_ecosystem: dict[str, dict[str, int]] = {}
    for sample in samples:
        bucket = by_ecosystem.setdefault(sample.ecosystem, {"malicious": 0, "benign": 0})
        bucket["malicious" if sample.label == 1 else "benign"] += 1

    return {
        "total": len(samples),
        "malicious": len(malicious),
        "benign": len(benign),
        "class_balance": round(len(malicious) / len(samples), 4) if samples else 0.0,
        "by_ecosystem": by_ecosystem,
        "distinct_groups": len({s.group for s in samples}),
        "feature_count": len(FEATURE_NAMES),
        "zeroed_features": list(REGISTRY_ONLY_FEATURES),
    }
