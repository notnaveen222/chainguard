"""Reporting and explanation-layer tests.

The explanation tests exist mainly to pin the *fallback* behaviour. The LLM layer
is optional and disabled by default, so the path that actually runs in almost
every scan — and in every demo — is the local one. If that silently broke,
nothing would fail loudly; reports would just quietly lose their prose.
"""

from __future__ import annotations

from chainguard.analysis.signals import Severity, make_signal
from chainguard.config import get_settings
from chainguard.llm.explain import explain_package, explain_reachability, local_explanation
from chainguard.reporting.html import render_report
from chainguard.scanner import (
    PackageFinding,
    ScanResult,
    ScanSummary,
    VulnerabilityFinding,
    _summarise,
)


def _sample_result() -> ScanResult:
    package = PackageFinding(
        name="pyyaml", version="5.1", ecosystem="PyPI", is_direct=True,
        malice_score=0.12, verdict="benign",
        vulnerabilities=[
            VulnerabilityFinding(
                id="GHSA-1", cve_id="CVE-2019-20477", package="pyyaml", version="5.1",
                ecosystem="PyPI", severity="CRITICAL", cvss_score=9.8,
                summary="Deserialization of untrusted data", fixed_version="5.2",
                reachable=True, reachability_verdict="reachable",
                reachability_reason="Application code calls 'yaml.load'",
                reachability_confidence="high", matched_symbol="yaml.load",
                call_path=[
                    {"caller": "app", "callee": "app.main", "file": "app.py", "line": 31},
                    {"caller": "app.main", "callee": "yaml.load", "file": "config.py", "line": 18},
                ],
            ),
            VulnerabilityFinding(
                id="GHSA-2", cve_id="CVE-2020-9999", package="pyyaml", version="5.1",
                ecosystem="PyPI", severity="HIGH", cvss_score=7.5,
                summary="Another issue", fixed_version="5.3",
                reachable=False, reachability_verdict="symbol_not_called",
                reachability_reason="Vulnerable symbol is never called",
                reachability_confidence="medium",
            ),
        ],
    )
    flagged = PackageFinding(
        name="reqeusts", version="1.0.0", ecosystem="PyPI",
        malice_score=0.94, verdict="malicious", typosquat_target="requests",
        explanation="This package impersonates requests and exfiltrates data on install.",
        explanation_source="local",
        signals=[
            make_signal("EXFIL_ON_INSTALL", file="setup.py",
                        detail="Collects data and sends it during installation"),
            make_signal("TYPOSQUAT_NEAR_MISS", detail="Resembles 'requests'"),
        ],
    )

    result = ScanResult(
        scan_id="testscan1234", target="demo-project", ecosystem="PyPI",
        duration_seconds=4.2, reachability_available=True, model_source="model",
        packages=[package, flagged],
        warnings=["Dependency resolution truncated at depth 6"],
    )
    _summarise(result)
    return result


class TestHtmlReport:
    def test_renders_and_is_self_contained(self):
        html = render_report(_sample_result())

        assert html.startswith("<!doctype html>")
        assert html.rstrip().endswith("</html>")
        # No external asset may be referenced: the report must render with no
        # network, from an email attachment or a USB stick.
        assert "src=\"http" not in html
        assert "cdn." not in html
        assert "<link" not in html

    def test_includes_the_headline_reachability_result(self):
        html = render_report(_sample_result())
        assert "advisories reported" in html
        assert "ruled out as unreachable" in html
        assert "50%" in html, "1 of 2 advisories is unreachable"

    def test_includes_call_path_proof(self):
        html = render_report(_sample_result())
        assert "Call paths" in html
        assert "yaml.load" in html
        assert "config.py" in html

    def test_includes_unreachable_section_with_reasons(self):
        html = render_report(_sample_result())
        assert "Not reachable" in html
        assert "never called" in html
        assert "de-prioritised, not" in html.lower() or "De-prioritised, not" in html

    def test_includes_flagged_package_and_explanation(self):
        html = render_report(_sample_result())
        assert "reqeusts" in html
        assert "impersonates requests" in html
        assert "EXFIL_ON_INSTALL" in html

    def test_escapes_untrusted_content(self):
        """Package names come from a registry and are attacker-controlled."""
        result = _sample_result()
        result.packages[1].name = "<script>alert(1)</script>"
        html = render_report(result)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_renders_with_no_findings(self):
        empty = ScanResult(scan_id="x", target="clean", ecosystem="npm", summary=ScanSummary())
        html = render_report(empty)
        assert "No packages were flagged" in html
        assert "No reachable vulnerabilities" in html


class TestExplanations:
    def test_local_explanation_mentions_evidence(self):
        signals = [
            make_signal("EXFIL_ON_INSTALL", file="setup.py",
                        detail="Sends environment data during installation"),
            make_signal("NETWORK_ACCESS", file="setup.py"),
        ]
        explanation = local_explanation("evil", "1.0.0", "malicious", signals, "requests")

        assert explanation.source == "local"
        assert "evil" in explanation.text
        assert "requests" in explanation.text, "typosquat target should be mentioned"
        assert "install time" in explanation.text

    def test_local_explanation_sentences_are_terminated(self):
        signals = [make_signal("DYNAMIC_EVAL", file="a.py", detail="Uses eval")]
        text = local_explanation("p", "1.0", "suspicious", signals).text
        # No sentence should run into the next without punctuation.
        assert ". The" in text or text.count(".") >= 2

    def test_clean_package_explanation(self):
        explanation = local_explanation("tidy", "1.0.0", "benign", [])
        assert "No suspicious behaviour" in explanation.text
        assert explanation.source == "local"

    def test_falls_back_to_local_when_llm_disabled(self):
        assert get_settings().llm_available is False, "LLM must be off by default"
        explanation = explain_package(
            "x", "1.0", "PyPI", "malicious", 0.9,
            [make_signal("DYNAMIC_EVAL", file="a.py")],
        )
        assert explanation.source == "local"
        assert explanation.text

    def test_reachability_explanation_uses_the_call_path(self):
        explanation = explain_reachability(
            "pyyaml", "CVE-2019-20477", "reachable", "calls yaml.load",
            [{"caller": "app.main", "callee": "yaml.load", "file": "config.py", "line": 18}],
        )
        assert "yaml.load" in explanation.text
        assert "config.py" in explanation.text

    def test_reachability_explanation_without_a_path(self):
        explanation = explain_reachability(
            "flask", "CVE-1", "not_imported", "never imported by the application", []
        )
        assert "never imported" in explanation.text


class TestSignalCollapsing:
    def test_repeated_codes_are_collapsed_with_a_count(self):
        from chainguard.analysis.engine import AnalysisResult
        from chainguard.models.package import Ecosystem, PackageRef

        result = AnalysisResult(
            ref=PackageRef(name="p", version="1", ecosystem=Ecosystem.PYPI),
            signals=[
                make_signal("DYNAMIC_EVAL", file=f"mod{i}.py", line=10) for i in range(12)
            ] + [make_signal("NETWORK_ACCESS", file="net.py")],
        )

        top = result.top_signals(10)
        codes = [s.code for s in top]
        assert codes.count("DYNAMIC_EVAL") == 1, "repeats must collapse to one row"
        assert "NETWORK_ACCESS" in codes, "collapsing must not crowd out other evidence"

        collapsed = next(s for s in top if s.code == "DYNAMIC_EVAL")
        assert collapsed.occurrences == 12

    def test_raw_signal_list_is_untouched(self):
        """Feature extraction must still see every occurrence."""
        from chainguard.analysis.engine import AnalysisResult
        from chainguard.models.package import Ecosystem, PackageRef

        signals = [make_signal("DYNAMIC_EVAL", file=f"m{i}.py") for i in range(5)]
        result = AnalysisResult(
            ref=PackageRef(name="p", version="1", ecosystem=Ecosystem.PYPI), signals=signals
        )
        result.top_signals(10)
        assert len(result.signals) == 5
        assert all(s.occurrences == 1 for s in result.signals)

    def test_highest_severity_kept_first(self):
        from chainguard.analysis.engine import AnalysisResult
        from chainguard.models.package import Ecosystem, PackageRef

        result = AnalysisResult(
            ref=PackageRef(name="p", version="1", ecosystem=Ecosystem.PYPI),
            signals=[
                make_signal("ENV_ACCESS", file="a.py"),
                make_signal("EXFIL_ON_INSTALL", file="setup.py"),
                make_signal("MINIFIED_SOURCE", file="b.js"),
            ],
        )
        top = result.top_signals(5)
        assert top[0].severity is Severity.CRITICAL
