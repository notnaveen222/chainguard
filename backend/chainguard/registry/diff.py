"""Version diff by SHA-256: did an upgrade actually change anything?

Two questions, answered cheaply and in order:

1. **Archive level.** SHA-256 of each downloaded distribution. Equal hashes mean
   byte-identical packages and nothing else needs doing. Each download is also
   checked against the digest the registry published (PyPI: SHA-256, npm:
   SHA-512 ``integrity`` or the older SHA-1 ``shasum``), so a corrupted or
   tampered download is reported instead of silently diffed.
2. **File level.** SHA-256 of every extracted file, giving added / removed /
   modified. A new version that only changes ``package.json`` shows up as
   exactly that, and a rebuild whose archive bytes differ but whose files do not
   is reported as "no file changes".

SHA-256, not MD5: MD5 has practical collision attacks, which is the wrong
property for a tool whose job is spotting deliberate tampering.

Scope: file hashes cover what ``archive.extract`` keeps (source, scripts and
config; binaries and images are skipped). The archive hash covers everything, so
a change that only touches a binary still shows as "archives differ" with no
file changes, and the result says so.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any, Literal, Optional

from packaging.version import InvalidVersion, Version as PypiVersion
from pydantic import BaseModel, Field

from chainguard.models.package import Ecosystem, PackageFile
from chainguard.registry.archive import ArchiveError, extract
from chainguard.registry.http import CachedHTTPClient, NotFoundError
from chainguard.registry.npm import NpmClient
from chainguard.registry.pypi import PyPIClient

#: Files whose change deserves attention even when small: they decide what runs
#: at install time.
SENSITIVE_FILES = frozenset({"package.json", "setup.py", "setup.cfg", "pyproject.toml"})


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_against_registry(payload: bytes, digests: dict[str, Any]) -> tuple[Optional[bool], Optional[str]]:
    """Check a download against the digest the registry published.

    Returns ``(verified, algorithm)``; ``verified`` is ``None`` when the registry
    published nothing usable to check against.
    """
    declared = digests.get("sha256")
    if declared:
        return hashlib.sha256(payload).hexdigest() == str(declared).lower(), "sha256"

    integrity = digests.get("sha512_integrity")
    if integrity:
        for token in str(integrity).split():
            algo, _, b64 = token.partition("-")
            if algo == "sha512" and b64:
                actual = base64.b64encode(hashlib.sha512(payload).digest()).decode()
                return actual == b64, "sha512"

    shasum = digests.get("sha1")
    if shasum:  # legacy npm packages: integrity check only, not a security claim
        return hashlib.sha1(payload, usedforsecurity=False).hexdigest() == str(shasum).lower(), "sha1"

    return None, None


class ArchiveDigest(BaseModel):
    version: str
    #: The distribution file that was hashed (sdist, wheel or tarball).
    filename: str = ""
    sha256: str
    size_bytes: int
    #: True/False when the download was checked against the registry's own digest;
    #: None when the registry published none.
    registry_verified: Optional[bool] = None
    registry_algorithm: Optional[str] = None


class FileChange(BaseModel):
    path: str
    status: Literal["added", "removed", "modified"]
    old_sha256: Optional[str] = None
    new_sha256: Optional[str] = None
    old_size: Optional[int] = None
    new_size: Optional[int] = None
    #: An install-time file (package.json, setup.py, ...): review these first.
    sensitive: bool = False


class VersionDiff(BaseModel):
    ecosystem: str
    name: str
    old: ArchiveDigest
    new: ArchiveDigest
    #: Byte-identical archives: the upgrade changed nothing.
    identical: bool
    #: Archives differ but no analysed file does (metadata, timestamps, binaries).
    archive_only_change: bool = False
    changes: list[FileChange] = Field(default_factory=list)
    added: int = 0
    removed: int = 0
    modified: int = 0
    unchanged: int = 0
    truncated: bool = False
    notes: list[str] = Field(default_factory=list)


def diff_files(old_files: list[PackageFile], new_files: list[PackageFile]) -> tuple[list[FileChange], int]:
    """Per-file SHA-256 comparison. Returns ``(changes, unchanged_count)``."""
    old = {f.path: f.content for f in old_files}
    new = {f.path: f.content for f in new_files}
    changes: list[FileChange] = []
    unchanged = 0

    for path in sorted(old.keys() | new.keys()):
        sensitive = path.rsplit("/", 1)[-1] in SENSITIVE_FILES
        if path not in new:
            changes.append(FileChange(
                path=path, status="removed", old_sha256=sha256_hex(old[path]),
                old_size=len(old[path]), sensitive=sensitive))
        elif path not in old:
            changes.append(FileChange(
                path=path, status="added", new_sha256=sha256_hex(new[path]),
                new_size=len(new[path]), sensitive=sensitive))
        else:
            old_hash, new_hash = sha256_hex(old[path]), sha256_hex(new[path])
            if old_hash == new_hash:
                unchanged += 1
            else:
                changes.append(FileChange(
                    path=path, status="modified", old_sha256=old_hash, new_sha256=new_hash,
                    old_size=len(old[path]), new_size=len(new[path]), sensitive=sensitive))

    # Install-time files first, then added/modified before removed.
    order = {"added": 0, "modified": 1, "removed": 2}
    changes.sort(key=lambda c: (not c.sensitive, order[c.status], c.path))
    return changes, unchanged


def build_diff(
    ecosystem: str,
    name: str,
    old: tuple[ArchiveDigest, list[PackageFile], bool],
    new: tuple[ArchiveDigest, list[PackageFile], bool],
) -> VersionDiff:
    """Assemble a ``VersionDiff`` from two digested, extracted distributions."""
    (old_digest, old_files, old_trunc), (new_digest, new_files, new_trunc) = old, new
    identical = old_digest.sha256 == new_digest.sha256
    changes, unchanged = ([], len(old_files)) if identical else diff_files(old_files, new_files)
    counts = {s: sum(1 for c in changes if c.status == s) for s in ("added", "removed", "modified")}

    notes: list[str] = []
    for digest in (old_digest, new_digest):
        if digest.registry_verified is False:
            notes.append(
                f"{digest.version}: download does not match the {digest.registry_algorithm} digest "
                "the registry published. Treat this copy as untrusted."
            )
    truncated = old_trunc or new_trunc
    if truncated:
        notes.append("An archive hit a safety limit during extraction, so the file list is partial.")
    archive_only = not identical and not changes
    if archive_only:
        notes.append(
            "The archives differ but no analysed file changed: the difference is in metadata, "
            "timestamps or files that are not analysed (binaries, images)."
        )

    return VersionDiff(
        ecosystem=ecosystem, name=name, old=old_digest, new=new_digest, identical=identical,
        archive_only_change=archive_only, changes=changes, unchanged=unchanged,
        truncated=truncated, notes=notes, **counts,
    )


def _same_version(resolved: str, requested: str) -> bool:
    if resolved == requested:
        return True
    try:
        return PypiVersion(resolved) == PypiVersion(requested)
    except InvalidVersion:
        return False


async def _digest(client: Any, name: str, spec: str) -> tuple[ArchiveDigest, list[PackageFile], bool]:
    """Resolve one version, download it, hash it and extract it into memory."""
    # A diff needs exactly the versions asked for. PyPI reads a bare "2.31.0" as an
    # invalid specifier and falls back to the latest release, so pin it with "==".
    pinned = f"=={spec}" if isinstance(client, PyPIClient) and spec[:1].isdigit() else spec
    metadata = await client.fetch_metadata(name, pinned)
    if not _same_version(metadata.version, spec):
        raise NotFoundError(f"{name} has no version {spec} (registry resolved it to {metadata.version})")
    if not metadata.dist_url:
        raise ArchiveError(f"No distribution URL published for {metadata.name}@{metadata.version}")
    payload = await client.http.get_bytes(metadata.dist_url)
    verified, algorithm = verify_against_registry(payload, metadata.raw.get("registry_digests") or {})
    digest = ArchiveDigest(
        version=metadata.version, filename=str(metadata.raw.get("filename") or metadata.dist_url).rsplit("/", 1)[-1],
        sha256=sha256_hex(payload), size_bytes=len(payload),
        registry_verified=verified, registry_algorithm=algorithm,
    )
    filename = str(metadata.raw.get("filename") or metadata.dist_url)
    result = extract(payload, filename=filename)
    return digest, result.files, result.truncated


async def compare_versions(
    ecosystem: Ecosystem, name: str, old_version: str, new_version: str
) -> VersionDiff:
    """Download two versions of a package and compare them by SHA-256."""
    async with CachedHTTPClient() as http:
        client: Any = NpmClient(http) if ecosystem is Ecosystem.NPM else PyPIClient(http)
        old = await _digest(client, name, old_version)
        new = await _digest(client, name, new_version)
    return build_diff(ecosystem.display_name, name, old, new)
