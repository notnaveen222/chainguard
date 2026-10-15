"""Jev review: evidence shaping, response parsing and graceful failure."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from chainguard.llm import jev
from chainguard.llm.jev import JevReview, review_package_jev
from chainguard.scanner import PackageFinding


def _finding() -> PackageFinding:
    return PackageFinding(
        name="colourama", version="1.0.0", ecosystem="pypi",
        malice_score=0.91, verdict="malicious", model_verdict="malicious",
        typosquat_target="colorama", files_analysed=3,
    )


def _response() -> SimpleNamespace:
    return SimpleNamespace(
        model="jev-1.13",
        answers={
            "verdict": SimpleNamespace(
                choice="malicious", confidence=0.93,
                probabilities={"malicious": 0.93, "suspicious": 0.05, "benign": 0.02},
            ),
            "exfiltration": SimpleNamespace(noul=0.97),
            "payload_execution": SimpleNamespace(noul=0.4),
            "normal_behaviour": SimpleNamespace(noul=0.02),
        },
    )


class _FakeClient:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response, error, []

    def system_one(self, state, questions):
        self.calls.append((state, questions))
        if self.error:
            raise self.error
        return self.response


def test_review_parses_typed_answers_and_times_the_call():
    client = _FakeClient(_response())
    review = review_package_jev(_finding(), client)
    assert isinstance(review, JevReview)
    assert review.verdict == "malicious"
    assert review.confidence == pytest.approx(0.93)
    assert review.exfiltration == pytest.approx(0.97)
    assert review.probabilities["benign"] == pytest.approx(0.02)
    assert review.model == "jev-1.13"
    assert review.latency_ms is not None and review.latency_ms >= 0


def test_all_four_questions_are_asked_in_one_call():
    client = _FakeClient(_response())
    review_package_jev(_finding(), client)
    assert len(client.calls) == 1
    _, questions = client.calls[0]
    assert set(questions) == {"verdict", "exfiltration", "payload_execution", "normal_behaviour"}


def test_state_carries_the_classifier_verdict_not_the_final_one():
    finding = _finding()
    finding.verdict = "benign"  # as if GPT had already overridden it
    assert jev._state(finding)["classifier"]["verdict"] == "malicious"


def test_state_never_contains_package_source():
    state = jev._state(_finding())
    assert set(state) == {"context", "package", "classifier", "typosquat_of",
                          "score_drivers", "signals", "traced_flows"}


def test_failure_returns_none_instead_of_raising():
    assert review_package_jev(_finding(), _FakeClient(error=RuntimeError("boom"))) is None


def test_no_key_means_no_client(monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setattr(jev, "get_settings",
                        lambda: SimpleNamespace(jev_available=False))
    assert jev.jev_client() is None
