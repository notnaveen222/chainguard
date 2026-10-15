"""Provider switching (OpenAI <-> Gemini) for the optional AI layer."""

from types import SimpleNamespace

import pytest

from chainguard.config import Settings
from chainguard.llm import client as llm_client_module
from chainguard.llm.assistant import _accumulate_tool_call, _chat_tools, TOOLS
from chainguard.llm.client import _drop_key, parse_json


def _settings(monkeypatch, **env: str) -> Settings:
    for name in ("AI_PROVIDER", "OPENAI_API_KEY", "GEMINI_API_KEY", "CHAINGUARD_LLM_MODEL"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return Settings(_env_file=None)


def test_default_provider_is_openai(monkeypatch):
    s = _settings(monkeypatch, OPENAI_API_KEY="sk-test")
    assert s.ai_provider == "openai"
    assert s.llm_available
    assert s.llm_base_url is None
    assert s.resolved_api_key == "sk-test"
    assert s.llm_model == s.openai_model
    assert s.llm_key_env_name == "OPENAI_API_KEY"


def test_gemini_provider_uses_its_own_key_endpoint_and_model(monkeypatch):
    s = _settings(monkeypatch, AI_PROVIDER="gemini", GEMINI_API_KEY="g-key", OPENAI_API_KEY="sk-test")
    assert s.resolved_api_key == "g-key"
    assert "generativelanguage.googleapis.com" in s.llm_base_url
    assert s.llm_model == s.gemini_model
    assert s.llm_key_env_name == "GEMINI_API_KEY"


def test_provider_without_its_key_is_unavailable(monkeypatch):
    s = _settings(monkeypatch, AI_PROVIDER="gemini", OPENAI_API_KEY="sk-test")
    assert not s.llm_available


def test_switching_back_to_openai_needs_only_provider_and_key(monkeypatch):
    s = _settings(monkeypatch, AI_PROVIDER="OpenAI ", OPENAI_API_KEY="sk-test", GEMINI_API_KEY="g-key")
    assert s.ai_provider == "openai"
    assert s.resolved_api_key == "sk-test"
    assert s.llm_base_url is None


def test_stale_model_override_from_other_provider_is_ignored(monkeypatch):
    gemini = _settings(monkeypatch, AI_PROVIDER="gemini", CHAINGUARD_LLM_MODEL="gpt-5.6-luna")
    assert gemini.llm_model == gemini.gemini_model
    openai = _settings(monkeypatch, CHAINGUARD_LLM_MODEL="gemini-3.5-flash")
    assert openai.llm_model == openai.openai_model


def test_model_override_for_the_active_provider_is_used(monkeypatch):
    s = _settings(monkeypatch, AI_PROVIDER="gemini", CHAINGUARD_LLM_MODEL="gemini-3.5-flash")
    assert s.llm_model == "gemini-3.5-flash"


def test_unknown_provider_is_rejected(monkeypatch):
    with pytest.raises(ValueError):
        _settings(monkeypatch, AI_PROVIDER="claude")


def test_token_limit_parameter_differs_by_provider(monkeypatch):
    monkeypatch.setattr(llm_client_module, "get_settings", lambda: SimpleNamespace(ai_provider="gemini"))
    assert llm_client_module.token_limit_param(50) == {"max_tokens": 50}
    monkeypatch.setattr(llm_client_module, "get_settings", lambda: SimpleNamespace(ai_provider="openai"))
    assert llm_client_module.token_limit_param(50) == {"max_completion_tokens": 50}


def test_drop_key_removes_it_at_every_depth():
    schema = {"type": "object", "additionalProperties": False,
              "properties": {"a": {"type": "object", "additionalProperties": False}}}
    cleaned = _drop_key(schema, "additionalProperties")
    assert "additionalProperties" not in cleaned
    assert "additionalProperties" not in cleaned["properties"]["a"]
    assert "additionalProperties" in schema  # original untouched


def test_parse_json_accepts_fenced_output():
    assert parse_json('```json\n{"verdict": "benign"}\n```') == {"verdict": "benign"}
    assert parse_json('{"verdict": "benign"}') == {"verdict": "benign"}
    with pytest.raises(ValueError):
        parse_json("[1, 2]")


def test_tools_convert_to_chat_completions_shape():
    tools = _chat_tools()
    assert len(tools) == len(TOOLS)
    assert all(t["type"] == "function" and set(t["function"]) == {"name", "description", "parameters"} for t in tools)


def _part(index, id=None, name=None, arguments=None, extra=None):
    part = SimpleNamespace(index=index, id=id, function=SimpleNamespace(name=name, arguments=arguments))
    part.model_extra = {"extra_content": extra} if extra else {}
    return part


def test_openai_style_fragments_are_merged_by_index():
    pending: dict = {}
    _accumulate_tool_call(pending, _part(0, "call_1", "check_package", ""))
    _accumulate_tool_call(pending, _part(0, None, None, '{"name": "ax'))
    _accumulate_tool_call(pending, _part(0, None, None, 'ios"}'))
    assert pending[0]["name"] == "check_package"
    assert pending[0]["arguments"] == '{"name": "axios"}'


def test_gemini_style_parallel_calls_sharing_index_zero_stay_separate():
    pending: dict = {}
    _accumulate_tool_call(pending, _part(0, "a", "get_model_card", "{}", extra={"google": {"thought_signature": "sig"}}))
    _accumulate_tool_call(pending, _part(0, "b", "list_scans", '{"limit": 5}'))
    assert [pending[i]["name"] for i in sorted(pending)] == ["get_model_card", "list_scans"]
    assert pending[0]["extra"] == {"google": {"thought_signature": "sig"}}
    assert pending[1]["arguments"] == '{"limit": 5}'
