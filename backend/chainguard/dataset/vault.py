"""Encoded-at-rest storage for malicious training samples.

Every byte written to ``data/quarantine/`` passes through here. Samples are
stored in an opaque encoded form and decoded **into memory only** — there is no
write-to-disk decode path anywhere in this module, deliberately.

Why this exists
---------------
Training the classifier requires real malicious packages. Storing them as
plaintext source on a personal machine has two practical problems, and the second
is the one that actually drove the design (see BUILD_LOG D-005):

1. Windows Defender quarantines the files, which would have required adding an
   antivirus exclusion — weakening a security setting on the user's laptop and
   creating a scanning blind spot.
2. More importantly, it would do so *silently and mid-build*. An overnight
   dataset build would lose samples partway through and train on a truncated
   corpus without anything obviously failing.

Encoding sidesteps both: nothing on disk is recognisable as code, so nothing is
flagged, so no exclusion is needed and no security setting was changed.

What this is *not*
------------------
This is **obfuscation, not cryptography**. The key is a constant in this file.
The threat model is "an antivirus scanner or a careless double-click", not "an
attacker with disk access" — anyone who can read the vault can also read this
source. Calling it encryption would be a false claim about the guarantee.

The security property that actually matters is enforced elsewhere and does not
depend on this encoding at all: ChainGuard never executes a sample under any code
path. Analysis is static parsing of source text.
"""

from __future__ import annotations

import hashlib
import json
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from chainguard.config import get_settings
from chainguard.logging_setup import get_logger

logger = get_logger(__name__)

#: File format magic. Version byte allows the encoding to change later without
#: silently misreading an old vault.
_MAGIC = b"CGVAULT\x01"

#: Keystream seed. Not a secret — see the module docstring.
_VAULT_SEED = b"chainguard-quarantine-v1-not-a-secret"

#: Extension chosen to be meaningless to any interpreter or loader.
_BLOB_SUFFIX = ".cgv"


def _keystream(length: int, nonce: bytes) -> bytes:
    """Generate a deterministic keystream of ``length`` bytes.

    BLAKE2b in counter mode. Deterministic given the nonce, so decoding needs no
    stored state beyond what is in the file header.
    """
    output = bytearray()
    counter = 0
    while len(output) < length:
        block = hashlib.blake2b(
            nonce + counter.to_bytes(8, "big"), key=_VAULT_SEED, digest_size=64
        ).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:length])


def _transform(payload: bytes, nonce: bytes) -> bytes:
    """XOR ``payload`` against the keystream. Its own inverse."""
    stream = _keystream(len(payload), nonce)
    return bytes(a ^ b for a, b in zip(payload, stream))


@dataclass
class SampleRecord:
    """Metadata describing one stored sample."""

    sample_id: str
    name: str
    version: str
    ecosystem: str
    label: str  # "malicious" | "benign"
    source: str  # provenance, e.g. "datadog/malicious-software-packages-dataset"
    archive_format: str = "unknown"  # "zip" | "tar.gz" | "encrypted-zip"
    archive_password: Optional[str] = None
    sha256: str = ""
    size_bytes: int = 0
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "sample_id": self.sample_id,
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "label": self.label,
            "source": self.source,
            "archive_format": self.archive_format,
            "archive_password": self.archive_password,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, data: dict) -> SampleRecord:
        return cls(
            sample_id=data["sample_id"],
            name=data.get("name", ""),
            version=data.get("version", ""),
            ecosystem=data.get("ecosystem", ""),
            label=data.get("label", "malicious"),
            source=data.get("source", ""),
            archive_format=data.get("archive_format", "unknown"),
            archive_password=data.get("archive_password"),
            sha256=data.get("sha256", ""),
            size_bytes=data.get("size_bytes", 0),
            extra=data.get("extra", {}) or {},
        )


class SampleVault:
    """An encoded-at-rest store of package samples."""

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = root or get_settings().quarantine_dir
        self.root.mkdir(parents=True, exist_ok=True)
        self.index_path = self.root / "index.jsonl"

    # ------------------------------------------------------------------ #
    # Paths
    # ------------------------------------------------------------------ #

    def _blob_path(self, sample_id: str) -> Path:
        digest = hashlib.sha256(sample_id.encode()).hexdigest()
        return self.root / "blobs" / digest[:2] / f"{digest}{_BLOB_SUFFIX}"

    # ------------------------------------------------------------------ #
    # Write
    # ------------------------------------------------------------------ #

    def put(self, record: SampleRecord, payload: bytes) -> None:
        """Store ``payload`` encoded, and append ``record`` to the index."""
        record.sha256 = hashlib.sha256(payload).hexdigest()
        record.size_bytes = len(payload)

        # Nonce derived from content, so storing the same sample twice produces
        # an identical blob and the operation stays idempotent.
        nonce = hashlib.sha256(record.sha256.encode()).digest()[:16]
        body = _transform(zlib.compress(payload, level=6), nonce)

        path = self._blob_path(record.sample_id)
        path.parent.mkdir(parents=True, exist_ok=True)

        header = json.dumps(record.to_dict(), separators=(",", ":")).encode()
        with path.open("wb") as handle:
            handle.write(_MAGIC)
            handle.write(nonce)
            handle.write(len(header).to_bytes(4, "big"))
            handle.write(header)
            handle.write(body)

        with self.index_path.open("a", encoding="utf-8") as index:
            index.write(json.dumps(record.to_dict()) + "\n")

    # ------------------------------------------------------------------ #
    # Read
    # ------------------------------------------------------------------ #

    def get(self, sample_id: str) -> Optional[bytes]:
        """Decode a sample **into memory**. Returns ``None`` if unreadable.

        There is no variant of this method that writes the decoded bytes to
        disk, and there should not be one.
        """
        path = self._blob_path(sample_id)
        if not path.exists():
            return None
        try:
            raw = path.read_bytes()
        except OSError as exc:
            logger.warning("Could not read vault blob %s: %s", sample_id, exc)
            return None

        if not raw.startswith(_MAGIC):
            logger.warning("Vault blob %s has a bad header; skipping", sample_id)
            return None

        offset = len(_MAGIC)
        nonce = raw[offset:offset + 16]
        offset += 16
        header_length = int.from_bytes(raw[offset:offset + 4], "big")
        offset += 4 + header_length

        try:
            return zlib.decompress(_transform(raw[offset:], nonce))
        except zlib.error as exc:
            # A truncated or corrupted blob must be reported, not silently
            # treated as an empty sample — training on a quietly shrinking
            # dataset is exactly the failure mode this design exists to avoid.
            logger.warning("Vault blob %s is corrupt: %s", sample_id, exc)
            return None

    def has(self, sample_id: str) -> bool:
        return self._blob_path(sample_id).exists()

    # ------------------------------------------------------------------ #
    # Index
    # ------------------------------------------------------------------ #

    def records(self) -> Iterator[SampleRecord]:
        """Iterate stored sample records, most recent write per id winning."""
        if not self.index_path.exists():
            return iter(())

        seen: dict[str, SampleRecord] = {}
        with self.index_path.open("r", encoding="utf-8") as index:
            for line in index:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = SampleRecord.from_dict(json.loads(line))
                except (json.JSONDecodeError, KeyError):
                    continue
                seen[record.sample_id] = record
        return iter(seen.values())

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in self.records():
            key = f"{record.label}/{record.ecosystem}"
            counts[key] = counts.get(key, 0) + 1
            counts["total"] = counts.get("total", 0) + 1
        return counts

    def verify(self) -> tuple[int, list[str]]:
        """Check every indexed sample decodes and matches its recorded hash.

        Returns ``(ok_count, problem_ids)``. Run after a dataset build so that a
        partially-written vault is discovered before training, not after.
        """
        ok = 0
        problems: list[str] = []
        for record in self.records():
            payload = self.get(record.sample_id)
            if payload is None:
                problems.append(f"{record.sample_id}: unreadable")
                continue
            if hashlib.sha256(payload).hexdigest() != record.sha256:
                problems.append(f"{record.sample_id}: hash mismatch")
                continue
            ok += 1
        return ok, problems
