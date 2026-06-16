"""LLM client factory + chat helpers for the NVIDIA (OpenAI-compatible) backend.

All model access in the pipeline goes through here so the client is configured in one place
(base_url, key, timeout) and JSON parsing is consistent. We call the official ``openai`` SDK
directly — not ``langchain-openai`` — to keep the dependency tree light (ADR-4, R-01).
"""

from __future__ import annotations

import json
import os
import re

from openai import OpenAI

from . import constants

_client: OpenAI | None = None


class LLMConfigError(RuntimeError):
    """Raised when the backend is not configured (missing key)."""


def get_client() -> OpenAI:
    """Return a cached OpenAI client pointed at the NVIDIA endpoint."""
    global _client
    if _client is None:
        key = os.getenv(constants.API_KEY_ENV)
        if not key:
            raise LLMConfigError(
                f"{constants.API_KEY_ENV} is not set. Add it to .env or the environment."
            )
        _client = OpenAI(base_url=constants.BASE_URL, api_key=key, timeout=600.0, max_retries=2)
    return _client


def chat(
    system: str,
    user: str,
    *,
    max_tokens: int = constants.MAX_TOKENS_NONSTREAMING,
    temperature: float = constants.TEMPERATURE,
) -> tuple[str, dict]:
    """Single-turn chat. Returns (text, usage) where usage = {input_tokens, output_tokens}.

    Streams the response so long generations don't hit a single-request HTTP timeout
    (tokens arrive continuously) — see Phase 3 design / ADR notes.
    """
    client = get_client()
    stream = client.chat.completions.create(
        model=constants.MODEL,
        max_tokens=max_tokens,
        temperature=temperature,
        top_p=constants.TOP_P,
        stream=True,
        stream_options={"include_usage": True},
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    parts: list[str] = []
    usage: dict = {}
    for chunk in stream:
        if chunk.choices:
            delta = chunk.choices[0].delta
            if delta and delta.content:
                parts.append(delta.content)
        if getattr(chunk, "usage", None):
            usage = {
                "input_tokens": chunk.usage.prompt_tokens,
                "output_tokens": chunk.usage.completion_tokens,
            }
    return "".join(parts), usage


def extract_json(text: str) -> dict | list:
    """Best-effort JSON extraction from a model response.

    Handles plain JSON, ```json fenced blocks, and leading/trailing prose by locating the first
    balanced ``{...}`` or ``[...]`` span. Raises ValueError if nothing parses — callers treat
    that as a retryable failure.
    """
    text = text.strip()
    # Strip markdown code fences if present.
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Fall back to the first balanced bracket span.
    start = min((i for i in (text.find("{"), text.find("[")) if i != -1), default=-1)
    if start == -1:
        raise ValueError("No JSON object/array found in model output.")
    opening = text[start]
    closing = "}" if opening == "{" else "]"
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == opening:
            depth += 1
        elif ch == closing:
            depth -= 1
            if depth == 0:
                return json.loads(text[start : i + 1])
    raise ValueError("Unbalanced JSON in model output.")


def chat_json(system: str, user: str, **kwargs) -> tuple[dict | list, dict]:
    """chat() + extract_json(). Returns (parsed_json, usage)."""
    text, usage = chat(system, user, **kwargs)
    return extract_json(text), usage
