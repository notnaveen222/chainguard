"""In-memory extraction of package distributions.

Every function here treats its input as hostile. Package archives are downloaded
from public registries and may be deliberately malicious, so extraction enforces
four controls:

* **Path traversal (zip-slip):** member paths that escape the archive root — via
  ``..`` segments, absolute paths, or Windows drive letters — are dropped.
* **Decompression bombs:** cumulative uncompressed size and the
  compressed:uncompressed ratio are both capped.
* **Member-count exhaustion:** archives with implausibly many entries are
  truncated rather than expanded.
* **Symlink escape:** links and other non-regular members are skipped entirely.

Nothing is ever written to disk. Extraction returns bytes held in memory, which
is what keeps the "packages are never executed" invariant cheap to guarantee —
there is no file on disk for anything to execute.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from dataclasses import dataclass
from typing import Iterator, Optional

from chainguard.config import AnalysisLimits, get_settings
from chainguard.logging_setup import get_logger
from chainguard.models.package import PackageFile

logger = get_logger(__name__)


class ArchiveError(RuntimeError):
    """The archive could not be read, or violated a safety ceiling outright."""


@dataclass
class ExtractionResult:
    """Files recovered from an archive, plus whether limits cut it short."""

    files: list[PackageFile]
    truncated: bool = False
    reason: Optional[str] = None


# Extensions whose contents are worth analysing. Binary blobs, images and
# compiled artefacts are skipped: they inflate memory and the static analysers
# cannot read them anyway.
_ANALYSABLE_SUFFIXES = frozenset(
    {
        ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
        ".py", ".pyi", ".pyx",
        ".json", ".toml", ".cfg", ".ini", ".yaml", ".yml",
        ".sh", ".bash", ".bat", ".ps1",
        ".md", ".txt",
    }
)

# Files worth keeping regardless of extension, because their *name* carries the
# signal (install hooks, package metadata).
_ALWAYS_KEEP = frozenset(
    {"package.json", "setup.py", "setup.cfg", "pyproject.toml", "PKG-INFO", "METADATA"}
)


def _is_unsafe_path(name: str) -> bool:
    """True if an archive member path must not be trusted."""
    if not name or name.startswith("/") or name.startswith("\\"):
        return True
    normalised = name.replace("\\", "/")
    # Windows drive letters and UNC paths.
    if len(normalised) >= 2 and normalised[1] == ":":
        return True
    if normalised.startswith("//"):
        return True
    return any(part == ".." for part in normalised.split("/"))


def _should_analyse(path: str) -> bool:
    basename = path.rsplit("/", 1)[-1]
    if basename in _ALWAYS_KEEP:
        return True
    _, _, ext = basename.rpartition(".")
    return bool(ext) and ext != basename and f".{ext.lower()}" in _ANALYSABLE_SUFFIXES


def _strip_root_prefix(paths: list[str]) -> str:
    """Return the common leading directory shared by every path, if there is one.

    npm tarballs wrap everything in ``package/``; Python sdists use
    ``name-version/``. Stripping that prefix means downstream code can look for
    ``package.json`` or ``setup.py`` at a predictable location.
    """
    if not paths:
        return ""
    first = paths[0].split("/", 1)
    if len(first) < 2:
        return ""
    candidate = first[0] + "/"
    return candidate if all(p.startswith(candidate) for p in paths) else ""


def _collect(
    members: Iterator[tuple[str, int, bytes | None]],
    limits: AnalysisLimits,
    compressed_size: int,
) -> ExtractionResult:
    """Apply safety ceilings to an iterator of ``(path, size, reader)`` members.

    ``reader`` is ``None`` for members that should be skipped without reading —
    the size check happens before any decompression work, which is what makes
    the bomb guard effective rather than cosmetic.
    """
    files: list[PackageFile] = []
    total_uncompressed = 0
    seen_members = 0
    truncated = False
    reason: Optional[str] = None

    for path, size, content in members:
        seen_members += 1
        if seen_members > limits.max_archive_members:
            truncated, reason = True, f"archive exceeded {limits.max_archive_members} members"
            break

        total_uncompressed += size
        if total_uncompressed > limits.max_uncompressed_bytes:
            truncated, reason = (
                True,
                f"uncompressed size exceeded {limits.max_uncompressed_bytes} bytes",
            )
            break

        if compressed_size > 0:
            ratio = total_uncompressed / compressed_size
            if ratio > limits.max_compression_ratio:
                truncated, reason = (
                    True,
                    f"compression ratio {ratio:.0f}:1 exceeded "
                    f"{limits.max_compression_ratio:.0f}:1 (possible decompression bomb)",
                )
                break

        if content is None:
            continue

        if len(files) >= limits.max_files_per_package:
            truncated, reason = (
                True,
                f"file count exceeded {limits.max_files_per_package}",
            )
            break

        files.append(PackageFile(path=path, content=content))

    if truncated:
        logger.warning("Archive extraction truncated: %s", reason)

    # Normalise away the wrapper directory the ecosystem adds.
    prefix = _strip_root_prefix([f.path for f in files])
    if prefix:
        files = [
            PackageFile(path=f.path[len(prefix):], content=f.content)
            for f in files
            if f.path != prefix.rstrip("/")
        ]

    return ExtractionResult(files=files, truncated=truncated, reason=reason)


def extract_tarball(payload: bytes, limits: Optional[AnalysisLimits] = None) -> ExtractionResult:
    """Extract an in-memory ``.tar.gz`` / ``.tgz`` distribution."""
    limits = limits or get_settings().limits
    compressed_size = len(payload)

    try:
        archive = tarfile.open(fileobj=io.BytesIO(payload), mode="r:*")
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ArchiveError(f"Unreadable tar archive: {exc}") from exc

    def _members() -> Iterator[tuple[str, int, bytes | None]]:
        with archive:
            for member in archive:
                # Skip symlinks, hardlinks, devices, FIFOs — only regular files
                # are ever read. A symlink pointing at /etc/passwd must not be
                # followed.
                if not member.isfile():
                    continue
                name = member.name.replace("\\", "/").lstrip("./")
                if _is_unsafe_path(member.name):
                    logger.debug("Dropping unsafe archive path: %r", member.name)
                    continue
                if member.size > limits.max_file_bytes or not _should_analyse(name):
                    # Still counts toward the cumulative size budget, but is not read.
                    yield name, member.size, None
                    continue
                try:
                    handle = archive.extractfile(member)
                    data = handle.read() if handle else b""
                except (tarfile.TarError, OSError) as exc:
                    logger.debug("Could not read %s: %s", name, exc)
                    continue
                yield name, member.size, data

    return _collect(_members(), limits, compressed_size)


def extract_zip(payload: bytes, limits: Optional[AnalysisLimits] = None) -> ExtractionResult:
    """Extract an in-memory ``.zip`` / ``.whl`` distribution."""
    limits = limits or get_settings().limits
    compressed_size = len(payload)

    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
    except (zipfile.BadZipFile, OSError) as exc:
        raise ArchiveError(f"Unreadable zip archive: {exc}") from exc

    def _members() -> Iterator[tuple[str, int, bytes | None]]:
        with archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                name = info.filename.replace("\\", "/").lstrip("./")
                if _is_unsafe_path(info.filename):
                    logger.debug("Dropping unsafe archive path: %r", info.filename)
                    continue
                if info.file_size > limits.max_file_bytes or not _should_analyse(name):
                    yield name, info.file_size, None
                    continue
                try:
                    data = archive.read(info)
                except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
                    logger.debug("Could not read %s: %s", name, exc)
                    continue
                yield name, info.file_size, data

    return _collect(_members(), limits, compressed_size)


def extract(
    payload: bytes, filename: str = "", limits: Optional[AnalysisLimits] = None
) -> ExtractionResult:
    """Extract a distribution, dispatching on magic bytes.

    The declared filename is only a hint; the leading bytes decide, because a
    malicious package can name a zip ``.tar.gz`` to confuse naive tooling.
    """
    limits = limits or get_settings().limits

    if len(payload) > limits.max_archive_bytes:
        raise ArchiveError(
            f"Distribution is {len(payload)} bytes, over the "
            f"{limits.max_archive_bytes}-byte ceiling"
        )
    if len(payload) < 4:
        raise ArchiveError("Distribution is empty or truncated")

    if payload[:2] == b"\x1f\x8b":  # gzip
        return extract_tarball(payload, limits)
    if payload[:2] == b"PK":  # zip / wheel
        return extract_zip(payload, limits)
    if payload[:5] == b"ustar" or filename.endswith(".tar"):
        return extract_tarball(payload, limits)

    # Fall back to the filename hint, then to trying both.
    if filename.endswith((".zip", ".whl")):
        return extract_zip(payload, limits)
    try:
        return extract_tarball(payload, limits)
    except ArchiveError:
        return extract_zip(payload, limits)
