"""Dataset pipeline tests: vault integrity, encoding, and leakage prevention.

The leakage tests are the important ones. If registry-only features were to leak
back into the training matrix, every reported metric in this project would be
measuring corpus-of-origin rather than maliciousness (BUILD_LOG D-032), and the
failure would be invisible — the numbers would simply look excellent.
"""

from __future__ import annotations

from chainguard.analysis.features import FEATURE_NAMES, PackageFeatures, SCHEMA_VERSION
from chainguard.dataset.corpus import (
    REGISTRY_ONLY_FEATURES,
    metadata_from_archive,
)
from chainguard.dataset.vault import SampleRecord, SampleVault
from chainguard.models.package import Ecosystem


class TestVault:
    def test_round_trip(self, tmp_path):
        vault = SampleVault(tmp_path)
        payload = b"import os\nos.system('echo hi')\n" * 50
        record = SampleRecord(
            sample_id="mal:PyPI:evil:1.0", name="evil", version="1.0",
            ecosystem="PyPI", label="malicious", source="test",
        )
        vault.put(record, payload)
        assert vault.get("mal:PyPI:evil:1.0") == payload

    def test_stored_bytes_are_not_the_plaintext(self):
        """The whole point: nothing on disk is recognisable as source code."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            vault = SampleVault(Path(tmp))
            payload = b"import socket\nsocket.socket()\n" * 40
            vault.put(
                SampleRecord(sample_id="s1", name="x", version="1", ecosystem="PyPI",
                             label="malicious", source="test"),
                payload,
            )
            blobs = list(Path(tmp).rglob("*.cgv"))
            assert blobs, "a blob should have been written"
            raw = blobs[0].read_bytes()
            assert b"import socket" not in raw
            assert b"socket.socket" not in raw

    def test_missing_sample_returns_none(self, tmp_path):
        assert SampleVault(tmp_path).get("nope") is None

    def test_corrupt_blob_returns_none_rather_than_garbage(self, tmp_path):
        vault = SampleVault(tmp_path)
        vault.put(
            SampleRecord(sample_id="s1", name="x", version="1", ecosystem="PyPI",
                         label="malicious", source="test"),
            b"payload" * 100,
        )
        blob = next(tmp_path.rglob("*.cgv"))
        data = bytearray(blob.read_bytes())
        data[-20:] = b"\x00" * 20
        blob.write_bytes(bytes(data))

        assert vault.get("s1") is None, "corruption must be detected, not silently truncated"

    def test_verify_reports_problems(self, tmp_path):
        vault = SampleVault(tmp_path)
        for index in range(3):
            vault.put(
                SampleRecord(sample_id=f"s{index}", name=f"p{index}", version="1",
                             ecosystem="PyPI", label="benign", source="test"),
                f"content-{index}".encode() * 20,
            )
        ok, problems = vault.verify()
        assert ok == 3 and not problems

    def test_index_and_stats(self, tmp_path):
        vault = SampleVault(tmp_path)
        vault.put(SampleRecord(sample_id="a", name="a", version="1", ecosystem="PyPI",
                               label="malicious", source="t"), b"x" * 100)
        vault.put(SampleRecord(sample_id="b", name="b", version="1", ecosystem="npm",
                               label="benign", source="t"), b"y" * 100)
        stats = vault.stats()
        assert stats["total"] == 2
        assert stats["malicious/PyPI"] == 1
        assert stats["benign/npm"] == 1


class TestLeakagePrevention:
    def test_registry_only_features_are_named_correctly(self):
        for name in REGISTRY_ONLY_FEATURES:
            assert name in FEATURE_NAMES, f"{name} is not a real feature"

    def test_zeroing_registry_features_clears_them(self):
        features = PackageFeatures(
            age_days=5.2, version_count=3.1, maintainer_count=1.0,
            is_single_version=1.0, is_very_new=1.0,
            network_access=2.0,
        )
        for name in REGISTRY_ONLY_FEATURES:
            setattr(features, name, 0.0)

        vector = dict(zip(FEATURE_NAMES, features.to_vector()))
        for name in REGISTRY_ONLY_FEATURES:
            assert vector[name] == 0.0
        # Code-derived features must survive.
        assert vector["network_access"] == 2.0

    def test_metadata_from_archive_uses_only_shipped_files(self):
        """Both classes must be described by fields an attacker also controls."""
        files = {
            "package.json": (
                b'{"name":"x","description":"A tool","repository":"https://github.com/a/b",'
                b'"scripts":{"postinstall":"node install.js","test":"jest"},'
                b'"dependencies":{"lodash":"^4"}}'
            )
        }
        metadata = metadata_from_archive(files, "x", "1.0.0", Ecosystem.NPM)

        assert metadata.description == "A tool"
        assert metadata.repository_url == "https://github.com/a/b"
        assert metadata.install_scripts == {"postinstall": "node install.js"}
        assert metadata.dependency_names == ["lodash"]
        # Registry-only fields must remain unknown — they are not in the archive.
        assert metadata.version_count == 0
        assert metadata.published_at is None
        assert metadata.maintainer_count == 0

    def test_pypi_metadata_from_pkg_info(self):
        files = {
            "PKG-INFO": (
                b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n"
                b"Summary: A demo package\nHome-page: https://example.com\n"
            )
        }
        metadata = metadata_from_archive(files, "demo", "1.0", Ecosystem.PYPI)
        assert metadata.description == "A demo package"
        assert metadata.version_count == 0


class TestFeatureSchema:
    def test_vector_round_trip(self):
        features = PackageFeatures(network_access=1.5, exfil_on_install=1.0)
        restored = PackageFeatures.from_vector(features.to_vector())
        assert restored.network_access == 1.5
        assert restored.exfil_on_install == 1.0

    def test_vector_length_matches_names(self):
        assert len(PackageFeatures().to_vector()) == len(FEATURE_NAMES)

    def test_schema_version_present(self):
        assert PackageFeatures().schema_version == SCHEMA_VERSION

    def test_wrong_length_vector_rejected(self):
        import pytest

        with pytest.raises(ValueError):
            PackageFeatures.from_vector([0.0, 1.0])

    def test_no_duplicate_feature_names(self):
        assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))
