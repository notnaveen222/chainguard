"""Acquisition of labelled training samples.

Two corpora, deliberately sourced differently:

**Malicious** — the DataDog *malicious-software-packages-dataset* (Apache-2.0),
a curated collection of real npm and PyPI packages that were caught attacking
users. Samples ship as password-encrypted ZIPs (password ``infected``), which is
the dataset's own convention for keeping malware inert on disk. That property is
preserved end to end here: the encrypted archive is decrypted **in memory only**,
and the vault re-encodes it before anything touches disk.

**Benign** — real packages downloaded live from npm and PyPI, drawn from the
popular-package list. Using genuine popular packages rather than hand-written
"clean" examples matters: the classifier has to learn to distinguish malware from
*real library code*, which is full of network calls, subprocess use and dynamic
imports. A benign corpus of toy examples would produce a model that looks
excellent in evaluation and fails on the first real scan.

Nothing here executes a sample. Archives are parsed, never installed.
"""

from __future__ import annotations

import asyncio
import io
import json
import random
import zipfile
from dataclasses import dataclass
from typing import Any, Optional

from chainguard.dataset.vault import SampleRecord, SampleVault
from chainguard.logging_setup import get_logger
from chainguard.models.package import Ecosystem
from chainguard.registry.http import CachedHTTPClient, NotFoundError, RegistryError
from chainguard.registry.npm import NpmClient
from chainguard.registry.pypi import PyPIClient

logger = get_logger(__name__)

DATASET_REPO = "DataDog/malicious-software-packages-dataset"
DATASET_LICENCE = "Apache-2.0"
RAW_BASE = f"https://raw.githubusercontent.com/{DATASET_REPO}/main"
API_BASE = f"https://api.github.com/repos/{DATASET_REPO}"

#: The dataset's published password for its sample archives.
SAMPLE_PASSWORD = b"infected"

#: Dataset directory name → the ecosystem it holds.
_ECOSYSTEM_DIR = {Ecosystem.NPM: "npm", Ecosystem.PYPI: "pypi"}


@dataclass
class SamplePath:
    """A locatable sample inside the dataset repository."""

    package: str
    version: str
    path: str
    category: str  # "malicious_intent" | "compromised_lib"


class MaliciousSampleSource:
    """Downloads malicious samples from the DataDog dataset."""

    def __init__(self, http: CachedHTTPClient) -> None:
        self.http = http

    async def list_samples(
        self, ecosystem: Ecosystem, *, limit: int = 500, seed: int = 20260817
    ) -> list[SamplePath]:
        """Enumerate available sample archives for an ecosystem.

        Uses the Git *trees* API rather than the contents API. The contents API
        needs one request per directory, and unauthenticated GitHub allows only
        60 requests an hour — enumerating even a few hundred packages that way
        would exhaust the quota long before the build finished. The trees API
        returns the whole subtree in a single request.
        """
        directory = _ECOSYSTEM_DIR[ecosystem]

        try:
            tree_sha = await self._resolve_tree_sha(["samples", directory])
        except (RegistryError, NotFoundError, KeyError) as exc:
            logger.error("Could not locate %s samples in the dataset: %s", directory, exc)
            return []

        try:
            document = await self.http.get_json(
                f"{API_BASE}/git/trees/{tree_sha}?recursive=1"
            )
        except (RegistryError, NotFoundError) as exc:
            logger.error("Could not list %s sample tree: %s", directory, exc)
            return []

        entries = document.get("tree") or []
        if document.get("truncated"):
            # Expected for npm, which holds tens of thousands of packages. The
            # returned prefix is still far larger than the sample we need, but
            # the truncation is logged rather than passed off as a full listing.
            logger.info(
                "Sample tree for %s was truncated by GitHub at %d entries; "
                "sampling from the returned subset",
                directory,
                len(entries),
            )

        samples: list[SamplePath] = []
        for entry in entries:
            if entry.get("type") != "blob":
                continue
            path = str(entry.get("path", ""))
            if not path.endswith(".zip"):
                continue
            # Layout: <category>/<package>/<version>/<date>-<package>-v<version>.zip
            parts = path.split("/")
            if len(parts) < 4:
                continue
            samples.append(
                SamplePath(
                    category=parts[0],
                    package=parts[1],
                    version=parts[2],
                    path=f"samples/{directory}/{path}",
                )
            )

        # Sample deterministically so a rebuild reproduces the same dataset.
        # One archive per package: multiple versions of one malicious package are
        # near-identical, and letting them span the train/test split would inflate
        # the reported scores.
        by_package: dict[str, SamplePath] = {}
        for sample in samples:
            by_package.setdefault(sample.package, sample)

        unique = sorted(by_package.values(), key=lambda s: s.path)
        random.Random(seed).shuffle(unique)
        selected = unique[:limit]

        logger.info(
            "%s: %d archives across %d packages, selected %d",
            directory, len(samples), len(unique), len(selected),
        )
        return selected

    async def _resolve_tree_sha(self, path_parts: list[str]) -> str:
        """Walk the git tree to find the SHA of a nested directory."""
        document = await self.http.get_json(f"{API_BASE}/git/trees/main")
        sha = document["sha"]
        for part in path_parts:
            document = await self.http.get_json(f"{API_BASE}/git/trees/{sha}")
            match = next(
                (e for e in document.get("tree", []) if e.get("path") == part), None
            )
            if match is None:
                raise KeyError(f"Path component not found in dataset tree: {part}")
            sha = match["sha"]
        return sha

    async def fetch_sample(self, sample: SamplePath) -> Optional[bytes]:
        """Download one encrypted sample archive."""
        try:
            return await self.http.get_bytes(f"{RAW_BASE}/{sample.path}")
        except (RegistryError, NotFoundError) as exc:
            logger.debug("Could not download %s: %s", sample.path, exc)
            return None


def extract_encrypted_sample(payload: bytes) -> dict[str, bytes]:
    """Decrypt a dataset archive **in memory** and return its files.

    The archive contains the original package distribution, usually nested a
    couple of directories deep. Directory entries and oversized members are
    dropped; a member that fails to decrypt is skipped rather than aborting the
    sample, since a single bad entry should not discard an otherwise usable one.
    """
    files: dict[str, bytes] = {}
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
    except (zipfile.BadZipFile, OSError) as exc:
        logger.debug("Sample is not a readable zip: %s", exc)
        return files

    with archive:
        for info in archive.infolist():
            if info.is_dir() or info.file_size > 2 * 1024 * 1024:
                continue
            try:
                data = archive.read(info, pwd=SAMPLE_PASSWORD)
            except (RuntimeError, zipfile.BadZipFile, OSError) as exc:
                logger.debug("Could not decrypt %s: %s", info.filename, exc)
                continue
            files[info.filename.replace("\\", "/")] = data

    return _strip_wrapper_directories(files)


def _strip_wrapper_directories(files: dict[str, bytes]) -> dict[str, bytes]:
    """Remove the archive's wrapper directories so paths match a real package.

    Samples are nested as ``<date>-<name>-v<version>/<name>-<version>/...``.
    Analysis expects ``setup.py`` and ``package.json`` near the root, so the
    common prefix is stripped — repeatedly, since there are usually two levels.
    """
    for _ in range(3):
        if not files:
            break
        first = next(iter(files))
        if "/" not in first:
            break
        prefix = first.split("/", 1)[0] + "/"
        if not all(path.startswith(prefix) for path in files):
            break
        files = {path[len(prefix):]: data for path, data in files.items() if path != prefix}
    return files


class BenignSampleSource:
    """Downloads real packages from the live registries as negative examples."""

    def __init__(self, http: CachedHTTPClient) -> None:
        self.http = http
        self.npm = NpmClient(http)
        self.pypi = PyPIClient(http)

    async def fetch(self, name: str, ecosystem: Ecosystem) -> Optional[tuple[bytes, dict[str, Any]]]:
        """Fetch a package distribution and its metadata."""
        try:
            if ecosystem is Ecosystem.NPM:
                metadata = await self.npm.fetch_metadata(name, "latest")
            else:
                metadata = await self.pypi.fetch_metadata(name)
        except (RegistryError, NotFoundError) as exc:
            logger.debug("Metadata unavailable for %s: %s", name, exc)
            return None

        if not metadata.dist_url:
            return None

        try:
            payload = await self.http.get_bytes(metadata.dist_url)
        except (RegistryError, NotFoundError) as exc:
            logger.debug("Distribution unavailable for %s: %s", name, exc)
            return None

        return payload, {
            "version": metadata.version,
            "filename": metadata.raw.get("filename") or metadata.dist_url.rsplit("/", 1)[-1],
            "repository_url": metadata.repository_url,
            "version_count": metadata.version_count,
            "maintainer_count": metadata.maintainer_count,
            "description": metadata.description,
            "install_scripts": metadata.install_scripts,
            "published_at": metadata.published_at.isoformat() if metadata.published_at else None,
            "dependency_names": metadata.dependency_names,
        }


async def collect_malicious(
    vault: SampleVault,
    http: CachedHTTPClient,
    ecosystem: Ecosystem,
    *,
    limit: int,
    concurrency: int = 6,
) -> int:
    """Download malicious samples into the vault. Returns the number stored."""
    source = MaliciousSampleSource(http)
    samples = await source.list_samples(ecosystem, limit=limit)
    if not samples:
        return 0

    stored = 0
    semaphore = asyncio.Semaphore(concurrency)

    async def _one(sample: SamplePath) -> None:
        nonlocal stored
        sample_id = f"mal:{ecosystem.value}:{sample.package}:{sample.version}"
        if vault.has(sample_id):
            stored += 1
            return
        async with semaphore:
            payload = await source.fetch_sample(sample)
        if payload is None:
            return

        # Verify the archive is usable *before* storing it, so the vault never
        # accumulates samples that will silently yield zero features later.
        files = extract_encrypted_sample(payload)
        if not files:
            logger.debug("Sample %s decrypted to no usable files; skipping", sample.package)
            return

        vault.put(
            SampleRecord(
                sample_id=sample_id,
                name=sample.package,
                version=sample.version,
                ecosystem=ecosystem.value,
                label="malicious",
                source=f"{DATASET_REPO} ({DATASET_LICENCE})",
                archive_format="encrypted-zip",
                archive_password=SAMPLE_PASSWORD.decode(),
                extra={"category": sample.category, "path": sample.path,
                       "file_count": len(files)},
            ),
            payload,
        )
        stored += 1

    await asyncio.gather(*(_one(s) for s in samples))
    return stored


async def collect_benign(
    vault: SampleVault,
    http: CachedHTTPClient,
    ecosystem: Ecosystem,
    names: list[str],
    *,
    concurrency: int = 8,
) -> int:
    """Download real packages into the vault as benign samples."""
    source = BenignSampleSource(http)
    stored = 0
    semaphore = asyncio.Semaphore(concurrency)

    async def _one(name: str) -> None:
        nonlocal stored
        sample_id = f"ben:{ecosystem.value}:{name}"
        if vault.has(sample_id):
            stored += 1
            return
        async with semaphore:
            result = await source.fetch(name, ecosystem)
        if result is None:
            return
        payload, metadata = result
        vault.put(
            SampleRecord(
                sample_id=sample_id,
                name=name,
                version=str(metadata.get("version", "")),
                ecosystem=ecosystem.value,
                label="benign",
                source=f"live {ecosystem.display_name} registry",
                archive_format="tar.gz" if ecosystem is Ecosystem.NPM else "sdist",
                extra=metadata,
            ),
            payload,
        )
        stored += 1

    await asyncio.gather(*(_one(n) for n in names))
    return stored


def load_popular_names(ecosystem: Ecosystem) -> list[str]:
    """Read the committed popular-package list used for the benign corpus."""
    from chainguard.analysis.typosquat import _DATA_FILE  # noqa: PLC0415

    try:
        document = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [str(n) for n in document.get(ecosystem.value, []) if n]
