"""Registry-layer tests: semver, manifests, and archive safety.

All offline. The archive tests are the important ones — they verify controls
against hostile input, and a scanner that ingests malicious packages is itself an
attack surface (ARCHITECTURE.md §5).
"""

from __future__ import annotations

import io
import tarfile
import zipfile

import pytest
from chainguard.config import AnalysisLimits
from chainguard.models.package import Ecosystem
from chainguard.registry import semver
from chainguard.registry.archive import ArchiveError, extract, extract_tarball, extract_zip
from chainguard.registry.manifest import ManifestError, parse_manifest

# --------------------------------------------------------------------------- #
# semver
# --------------------------------------------------------------------------- #


class TestSemver:
    VERSIONS = ["0.2.1", "0.3.0", "1.0.0", "1.2.0", "1.2.3", "1.9.9",
                "2.0.0", "2.1.0", "3.0.0-beta.1"]

    @pytest.mark.parametrize(
        "spec,expected",
        [
            ("^1.2.0", "1.9.9"),
            ("~1.2.0", "1.2.3"),
            ("1.x", "1.9.9"),
            ("1.2.x", "1.2.3"),
            (">=1.0.0 <2.0.0", "1.9.9"),
            ("2.0.0", "2.0.0"),
            ("*", "2.1.0"),
            ("^1.0.0 || ^3.0.0", "1.9.9"),
            ("1.0.0 - 1.2.3", "1.2.3"),
        ],
    )
    def test_range_resolution(self, spec, expected):
        assert semver.max_satisfying(self.VERSIONS, spec) == expected

    def test_caret_on_zero_major_pins_minor(self):
        """`^0.2.1` must not float to 0.3.0 — pre-1.0 minors may break."""
        assert semver.max_satisfying(self.VERSIONS, "^0.2.0") == "0.2.1"

    def test_prereleases_excluded_unless_pinned(self):
        assert semver.max_satisfying(self.VERSIONS, ">=3.0.0") is None
        assert semver.max_satisfying(self.VERSIONS, "3.0.0-beta.1") == "3.0.0-beta.1"

    def test_prerelease_sorts_below_release(self):
        assert semver.Version.parse("1.0.0-alpha") < semver.Version.parse("1.0.0")

    def test_unparseable_spec_returns_none(self):
        assert semver.max_satisfying(self.VERSIONS, "not-a-range") is None


# --------------------------------------------------------------------------- #
# Manifests
# --------------------------------------------------------------------------- #


class TestManifests:
    def test_package_json(self):
        manifest = parse_manifest(
            '{"name":"demo","dependencies":{"lodash":"^4.17.0"},'
            '"devDependencies":{"jest":"^29.0.0"},"peerDependencies":{"react":"^18"}}',
            "package.json",
        )
        assert manifest.ecosystem is Ecosystem.NPM
        assert manifest.requirements == {"lodash": "^4.17.0"}
        assert "jest" in manifest.dev_requirements
        assert manifest.warnings, "peerDependencies should be reported, not silently dropped"

    def test_requirements_txt_variants(self):
        manifest = parse_manifest(
            "# comment\n"
            "requests==2.31.0\n"
            "flask>=2.0,<3.0\n"
            "numpy\n"
            "uvicorn[standard]==0.30.0\n"
            "pytest ; extra == 'dev'\n"
            "-r other.txt\n"
            "git+https://example.com/x.git\n",
            "requirements.txt",
        )
        assert set(manifest.requirements) == {"requests", "flask", "numpy", "uvicorn"}
        assert manifest.locked == {"requests": "2.31.0", "uvicorn": "0.30.0"}
        assert len(manifest.warnings) == 2, "nested file and VCS requirement both reported"

    def test_lockfile_v3(self):
        manifest = parse_manifest(
            '{"name":"d","lockfileVersion":3,"packages":{'
            '"":{"name":"d"},'
            '"node_modules/lodash":{"version":"4.17.21"},'
            '"node_modules/@babel/core":{"version":"7.24.0"},'
            '"node_modules/jest":{"version":"29.7.0","dev":true}}}',
            "package-lock.json",
        )
        assert manifest.locked == {"lodash": "4.17.21", "@babel/core": "7.24.0"}
        assert manifest.has_lockfile

    def test_invalid_manifest_raises(self):
        with pytest.raises(ManifestError):
            parse_manifest("{not json", "package.json")


# --------------------------------------------------------------------------- #
# Archive safety
# --------------------------------------------------------------------------- #


def _make_tar(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _make_zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


class TestArchiveSafety:
    def test_extracts_normal_tarball_and_strips_wrapper(self):
        payload = _make_tar({
            "package/index.js": b"module.exports = 1;",
            "package/package.json": b'{"name":"x"}',
        })
        result = extract_tarball(payload)
        paths = {f.path for f in result.files}
        assert paths == {"index.js", "package.json"}, "wrapper directory should be stripped"

    def test_rejects_path_traversal_in_tar(self):
        payload = _make_tar({
            "package/safe.py": b"x = 1",
            "../../../etc/passwd": b"root:x:0:0",
            "package/../../escape.py": b"bad",
        })
        result = extract_tarball(payload)
        for file in result.files:
            assert ".." not in file.path
            assert not file.path.startswith("/")

    def test_rejects_absolute_paths_in_zip(self):
        payload = _make_zip({"/etc/shadow": b"x", "ok.py": b"y = 2"})
        result = extract_zip(payload)
        assert all(not f.path.startswith("/") for f in result.files)

    def test_decompression_bomb_is_truncated_not_fatal(self):
        """A zip bomb must degrade to a truncated result, never take the scanner down."""
        bomb = _make_zip({f"f{i}.py": b"A" * 200_000 for i in range(40)})
        limits = AnalysisLimits(
            max_uncompressed_bytes=500_000, max_compression_ratio=5.0
        )
        result = extract_zip(bomb, limits)
        assert result.truncated is True
        assert result.reason is not None

    def test_oversized_archive_rejected_before_extraction(self):
        limits = AnalysisLimits(max_archive_bytes=100)
        with pytest.raises(ArchiveError):
            extract(b"\x1f\x8b" + b"x" * 500, limits=limits)

    def test_member_count_ceiling(self):
        payload = _make_zip({f"m{i}.py": b"x" for i in range(120)})
        result = extract_zip(payload, AnalysisLimits(max_archive_members=50))
        assert result.truncated is True

    def test_binary_files_are_skipped(self):
        payload = _make_tar({
            "package/logo.png": b"\x89PNG" + b"\x00" * 500,
            "package/index.js": b"var a = 1;",
        })
        result = extract_tarball(payload)
        assert {f.path for f in result.files} == {"index.js"}

    def test_format_detected_from_magic_bytes_not_filename(self):
        """A zip named .tar.gz must still be read correctly."""
        payload = _make_zip({"a.py": b"x = 1"})
        result = extract(payload, filename="package.tar.gz")
        assert {f.path for f in result.files} == {"a.py"}

    def test_corrupt_archive_raises_archive_error(self):
        with pytest.raises(ArchiveError):
            extract(b"\x1f\x8b\x08\x00garbage-not-really-gzip-data")
