"""Provider-neutral LLM access (OpenAI or Gemini).

Both providers are reached through the ``openai`` SDK and the Chat Completions
API: Gemini exposes an OpenAI-compatible endpoint, so switching provider only
changes the base URL, key and model (``AI_PROVIDER`` in ``.env``). Callers never
branch on provider except for the few request parameters that differ, which are
handled here.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from chainguard.config import get_settings
from chainguard.logging_setup import get_logger

logger = get_logger(__name__)


def llm_client() -> Optional[Any]:
    """A client for the configured provider when a key is set, else None."""
    settings = get_settings()
    if not settings.llm_available:
        return None
    try:
        from openai import OpenAI  # noqa: PLC0415 — optional dependency
    except ImportError:
        logger.debug("openai package not installed; AI layer disabled")
        return None
    return OpenAI(
        api_key=settings.resolved_api_key,
        base_url=settings.llm_base_url,
        max_retries=2,
        timeout=60,
    )


def token_limit_param(limit: int) -> dict[str, int]:
    """Newer OpenAI models reject ``max_tokens``; Gemini's endpoint only knows it."""
    if get_settings().ai_provider == "gemini":
        return {"max_tokens": limit}
    return {"max_completion_tokens": limit}


def _drop_key(node: Any, key: str) -> Any:
    if isinstance(node, dict):
        return {k: _drop_key(v, key) for k, v in node.items() if k != key}
    if isinstance(node, list):
        return [_drop_key(v, key) for v in node]
    return node


def complete(
    client: Any,
    instructions: str,
    user_input: str,
    json_schema: Optional[dict[str, Any]] = None,
    schema_name: str = "response",
) -> str:
    """One non-streaming completion; returns the text (a JSON document with a schema)."""
    settings = get_settings()
    kwargs: dict[str, Any] = {
        "model": settings.llm_model,
        "messages": [
            {"role": "system", "content": instructions},
            {"role": "user", "content": user_input},
        ],
        **token_limit_param(settings.llm_max_tokens),
    }
    if settings.ai_provider == "gemini":
        # Thinking tokens count against the limit; keep room for the answer.
        kwargs["reasoning_effort"] = "low"
    if json_schema is not None:
        if settings.ai_provider == "gemini":
            kwargs["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": schema_name, "schema": _drop_key(json_schema, "additionalProperties")},
            }
        else:
            kwargs["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": schema_name, "schema": json_schema, "strict": True},
            }
    response = client.chat.completions.create(**kwargs)
    return (response.choices[0].message.content or "").strip()


def parse_json(text: str) -> dict[str, Any]:
    """Parse a JSON object from model output, tolerating a markdown code fence."""
    text = text.strip()
    fenced = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("model output is not a JSON object")
    return data
