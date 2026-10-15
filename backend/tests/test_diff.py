"""SHA-256 version diff: file comparison, registry verification, assembly."""

from __future__ import annotations

import base64
import hashlib

from chainguard.models.package import PackageFile
from chainguard.registry.diff import (
    ArchiveDigest,
    build_diff,
    diff_files,
    sha256_hex,
    verify_against_registry,
)


def _f(path: str, text: str) -> PackageFile:
    return PackageFile(path=path, content=text.encode())


def _digest(version: str, payload: bytes, verified=None) -> ArchiveDigest:
    return ArchiveDigest(version=version, sha256=sha256_hex(payload), size_bytes=len(payload),
                         registry_verified=verified)


def test_file_diff_reports_added_removed_modified_and_unchanged():
    old = [_f("a.js", "1"), _f("b.js", "2"), _f("gone.js", "x")]
    new = [_f("a.js", "1"), _f("b.js", "CHANGED"), _f("new.js", "y")]
    changes, unchanged = diff_files(old, new)
    by_path = {c.path: c.status for c in changes}
    assert by_path == {"b.js": "modified", "gone.js": "removed", "new.js": "added"}
    assert unchanged == 1


def test_install_time_files_sort_first_and_are_flagged():
    old = [_f("lib/z.js", "1"), _f("package.json", '{"v":1}')]
    new = [_f("lib/z.js", "2"), _f("package.json", '{"v":2,"scripts":{"postinstall":"x"}}')]
    changes, _ = diff_files(old, new)
    assert changes[0].path == "package.json" and changes[0].sensitive
    assert not changes[1].sensitive


def test_identical_archives_skip_file_comparison():
    payload = b"same bytes"
    d = build_diff("PyPI", "pkg", (_digest("1.0", payload), [_f("a.py", "1")], False),
                   (_digest("1.0.1", payload), [_f("a.py", "DIFFERENT")], False))
    assert d.identical and d.changes == [] and d.unchanged == 1


def test_archive_differs_but_files_do_not():
    d = build_diff("npm", "pkg", (_digest("1", b"aaa"), [_f("a.js", "1")], False),
                   (_digest("2", b"bbb"), [_f("a.js", "1")], False))
    assert not d.identical and d.archive_only_change and d.changes == []
    assert any("metadata" in n for n in d.notes)


def test_counts_match_changes():
    d = build_diff("npm", "pkg", (_digest("1", b"a"), [_f("a.js", "1"), _f("r.js", "1")], False),
                   (_digest("2", b"b"), [_f("a.js", "2"), _f("n.js", "1")], False))
    assert (d.added, d.removed, d.modified) == (1, 1, 1)


def test_failed_registry_verification_is_called_out():
    d = build_diff("PyPI", "pkg", (_digest("1", b"a", verified=False), [], False),
                   (_digest("2", b"b", verified=True), [], False))
    assert any("untrusted" in n for n in d.notes)


def test_verify_pypi_sha256():
    payload = b"wheel"
    good = {"sha256": hashlib.sha256(payload).hexdigest()}
    assert verify_against_registry(payload, good) == (True, "sha256")
    assert verify_against_registry(b"tampered", good) == (False, "sha256")


def test_verify_npm_sha512_integrity():
    payload = b"tarball"
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode()
    assert verify_against_registry(payload, {"sha512_integrity": integrity}) == (True, "sha512")
    assert verify_against_registry(b"x", {"sha512_integrity": integrity}) == (False, "sha512")


def test_verify_without_digests_is_unknown_not_failed():
    assert verify_against_registry(b"x", {}) == (None, None)


def test_version_match_is_exact_not_fuzzy():
    from chainguard.registry.diff import _same_version
    assert _same_version("2.31.0", "2.31.0")
    assert _same_version("2.31", "2.31.0")  # PEP 440 equivalence
    assert not _same_version("2.34.2", "2.31.0")
