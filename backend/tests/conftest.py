"""Shared test configuration."""

import pytest

from chainguard.config import get_settings


@pytest.fixture(autouse=True)
def _no_ai_calls():
    """Keep the OpenAI layer off in tests.

    A developer's .env may contain a real OPENAI_API_KEY; tests must neither make
    paid network calls nor change behaviour depending on that file.
    """
    settings = get_settings()
    previous = settings.llm_enabled
    settings.llm_enabled = False
    yield
    settings.llm_enabled = previous
