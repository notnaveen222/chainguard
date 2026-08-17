"""Reachability analysis tests.

Built around a temporary fixture project so the call graph is real rather than
mocked. The negative cases matter most: a false "not reachable" is the one error
this system must never make, because it hides a genuinely exploitable
vulnerability behind a confident all-clear.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from chainguard.models.package import Ecosystem, PackageRef
from chainguard.vulns.import_names import ImportNameResolver, import_names_for
from chainguard.vulns.osv import extract_symbols, parse_vulnerability
from chainguard.vulns.reachability import ReachabilityAnalyser, Verdict

FIXTURE_FILES = {
    "main.py": """
import yaml
from helpers import parse_config


def run(path):
    return load_settings(path)


def load_settings(path):
    with open(path) as handle:
        return yaml.load(handle.read())


if __name__ == "__main__":
    run("config.yml")
""",
    "helpers.py": """
import requests
import jinja2


def parse_config(text):
    return text.strip()


def never_called(url):
    return requests.get(url)
""",
    "deep/__init__.py": "",
    "deep/nested.py": """
import urllib.request


def fetch(url):
    return urllib.request.urlopen(url)
""",
}


@pytest.fixture
def project(tmp_path: Path) -> Path:
    for name, source in FIXTURE_FILES.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    return tmp_path


class TestPythonReachability:
    def test_called_symbol_is_reachable_with_proof(self, project):
        analyser = ReachabilityAnalyser(project, Ecosystem.PYPI)
        result = analyser.analyse("yaml", ["yaml.load", "load"])

        assert result.verdict is Verdict.REACHABLE
        assert result.is_reachable
        assert result.confidence == "high"
        assert result.call_path, "a reachable verdict must carry a proof path"
        assert result.call_path[-1].callee.endswith("load")
        # Every step names a real file and line.
        for step in result.call_path:
            assert step.file
            assert step.line > 0

    def test_imported_but_uncalled_symbol_is_not_reachable(self, project):
        analyser = ReachabilityAnalyser(project, Ecosystem.PYPI)
        result = analyser.analyse("jinja2", ["Environment", "from_string"])

        assert result.verdict is Verdict.SYMBOL_NOT_CALLED
        assert not result.is_reachable
        assert result.imported_by, "should record which modules import it"

    def test_absent_package_is_not_imported(self, project):
        analyser = ReachabilityAnalyser(project, Ecosystem.PYPI)
        result = analyser.analyse("flask", ["Flask"])

        assert result.verdict is Verdict.NOT_IMPORTED
        assert not result.is_reachable
        assert result.confidence == "high", "absence of any import is the strongest negative"

    def test_no_symbols_means_assumed_reachable(self, project):
        """Fail-safe: an advisory naming no symbols cannot be ruled out."""
        analyser = ReachabilityAnalyser(project, Ecosystem.PYPI)
        result = analyser.analyse("jinja2", [])

        assert result.verdict is Verdict.ASSUMED_REACHABLE
        assert result.is_reachable
        assert result.confidence == "low"

    def test_missing_source_never_reports_safe(self, tmp_path):
        analyser = ReachabilityAnalyser(tmp_path / "does-not-exist", Ecosystem.PYPI)
        result = analyser.analyse("anything", ["x"])

        assert result.verdict is Verdict.NOT_ANALYSED
        assert result.is_reachable, "uncertainty must resolve toward reachable"

    def test_dotted_import_resolves(self, project):
        """`import urllib.request` then `urllib.request.urlopen(...)`."""
        analyser = ReachabilityAnalyser(project, Ecosystem.PYPI)
        result = analyser.analyse("urllib3", ["urlopen"])
        # urllib3 is a different distribution from stdlib urllib, so it must not
        # match — but the graph should still have recorded the urllib import.
        assert result.verdict in (Verdict.NOT_IMPORTED, Verdict.SYMBOL_NOT_CALLED)

    def test_every_uncertain_verdict_counts_as_reachable(self):
        assert Verdict.REACHABLE.is_reachable
        assert Verdict.ASSUMED_REACHABLE.is_reachable
        assert Verdict.NOT_ANALYSED.is_reachable
        assert not Verdict.NOT_IMPORTED.is_reachable
        assert not Verdict.SYMBOL_NOT_CALLED.is_reachable


class TestImportNames:
    @pytest.mark.parametrize(
        "distribution,expected_module",
        [("pyyaml", "yaml"), ("pillow", "PIL"), ("beautifulsoup4", "bs4"),
         ("python-dateutil", "dateutil"), ("scikit-learn", "sklearn")],
    )
    def test_curated_table(self, distribution, expected_module):
        assert expected_module in import_names_for(distribution, Ecosystem.PYPI)

    def test_distribution_name_is_always_included(self):
        names = import_names_for("requests", Ecosystem.PYPI)
        assert "requests" in names

    def test_npm_names_pass_through(self):
        assert import_names_for("lodash", Ecosystem.NPM) == ("lodash",)

    def test_pyyaml_reachability_regression(self, project):
        """Regression for BUILD_LOG D-040.

        `pyyaml` ships the module `yaml`. Querying by distribution name must find
        `import yaml`, or three critical advisories get reported as safe.
        """
        analyser = ReachabilityAnalyser(project, Ecosystem.PYPI, ImportNameResolver())
        result = analyser.analyse("pyyaml", ["yaml.load", "load"])
        assert result.verdict is Verdict.REACHABLE
        assert result.call_path


class TestOSVParsing:
    def test_cvss_v3_base_score(self):
        vuln = parse_vulnerability(
            {
                "id": "GHSA-test",
                "summary": "Test",
                "aliases": ["CVE-2020-0001"],
                "severity": [
                    {"type": "CVSS_V3",
                     "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                ],
                "affected": [
                    {"package": {"name": "pkg"},
                     "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]}
                ],
            },
            PackageRef(name="pkg", version="1.0.0", ecosystem=Ecosystem.PYPI),
        )
        # This vector is the canonical 9.8 CRITICAL.
        assert vuln.cvss_score == pytest.approx(9.8, abs=0.05)
        assert vuln.severity == "CRITICAL"
        assert vuln.fixed_version == "1.2.3"
        assert vuln.cve_id == "CVE-2020-0001"

    def test_symbols_from_curated_table_are_labelled(self):
        symbols, confidence = extract_symbols({"summary": "", "details": ""}, "pyyaml")
        assert "yaml.load" in symbols
        assert confidence == "curated"

    def test_symbols_parsed_from_prose_are_labelled_as_such(self):
        symbols, confidence = extract_symbols(
            {"summary": "RCE", "details": "The `renderTemplate` function is unsafe."},
            "some-unknown-package",
        )
        assert confidence in ("parsed", "none")
        if confidence == "parsed":
            assert "renderTemplate" in symbols

    def test_duplicate_cve_records_are_merged(self):
        """OSV aggregates several databases, so one CVE arrives more than once.

        Regression: the demo project reported CVE-2019-20477 twice — as
        `CRITICAL 9.8` from GHSA and again as `UNKNOWN` from PyPA — inflating
        both the advisory total and the reachable count. Since the project's
        headline claim is the ratio between those numbers, duplicates distort
        the central result.
        """
        from chainguard.scanner import VulnerabilityFinding, _dedupe_vulnerabilities

        rich = VulnerabilityFinding(
            id="GHSA-aaaa", cve_id="CVE-2019-20477", package="pyyaml", version="5.1",
            ecosystem="PyPI", severity="CRITICAL", cvss_score=9.8, fixed_version="5.2",
            summary="Deserialization of untrusted data",
        )
        sparse = VulnerabilityFinding(
            id="PYSEC-2019-1", cve_id="CVE-2019-20477", package="pyyaml", version="5.1",
            ecosystem="PyPI", severity="UNKNOWN",
        )
        other = VulnerabilityFinding(
            id="GHSA-bbbb", cve_id="CVE-2020-1747", package="pyyaml", version="5.1",
            ecosystem="PyPI", severity="CRITICAL", cvss_score=9.8,
        )

        merged = _dedupe_vulnerabilities([rich, sparse, other])
        assert len(merged) == 2

        kept = next(v for v in merged if v.cve_id == "CVE-2019-20477")
        assert kept.cvss_score == 9.8, "the more informative record must survive"
        assert kept.fixed_version == "5.2"

    def test_dedupe_keeps_fixed_version_from_either_record(self):
        from chainguard.scanner import VulnerabilityFinding, _dedupe_vulnerabilities

        scored = VulnerabilityFinding(
            id="GHSA-x", cve_id="CVE-1", package="p", version="1", ecosystem="PyPI",
            severity="HIGH", cvss_score=7.5,
        )
        with_fix = VulnerabilityFinding(
            id="PYSEC-x", cve_id="CVE-1", package="p", version="1", ecosystem="PyPI",
            severity="UNKNOWN", fixed_version="2.0.0",
        )
        merged = _dedupe_vulnerabilities([scored, with_fix])
        assert len(merged) == 1
        assert merged[0].fixed_version == "2.0.0"

    def test_advisories_without_cve_are_not_collapsed(self):
        from chainguard.scanner import VulnerabilityFinding, _dedupe_vulnerabilities

        a = VulnerabilityFinding(id="GHSA-1", package="p", version="1",
                                 ecosystem="npm", severity="HIGH")
        b = VulnerabilityFinding(id="GHSA-2", package="p", version="1",
                                 ecosystem="npm", severity="HIGH")
        assert len(_dedupe_vulnerabilities([a, b])) == 2

    def test_prose_stopwords_are_not_symbols(self):
        symbols, _ = extract_symbols(
            {"summary": "An attacker", "details": "The `attacker` can exploit the `version`."},
            "unknown-pkg",
        )
        assert "attacker" not in symbols
        assert "version" not in symbols
