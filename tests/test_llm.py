"""LLM client-config tests (no network)."""

from __future__ import annotations

import pytest

from iac_threatgen import constants, llm


def test_get_client_raises_without_key(monkeypatch):
    monkeypatch.setattr(llm, "_client", None)
    monkeypatch.delenv(constants.API_KEY_ENV, raising=False)
    with pytest.raises(llm.LLMConfigError):
        llm.get_client()


import types  # noqa: E402


def _chunk(content=None, usage=None):
    delta = types.SimpleNamespace(content=content)
    choice = types.SimpleNamespace(delta=delta)
    return types.SimpleNamespace(choices=[choice] if content is not None else [], usage=usage)


def test_chat_accumulates_stream_and_usage(monkeypatch):
    usage = types.SimpleNamespace(prompt_tokens=11, completion_tokens=7)
    chunks = [_chunk("Hello "), _chunk("world"), _chunk(None, usage=usage)]

    class _FakeCompletions:
        def create(self, **kwargs):
            assert kwargs["stream"] is True
            return iter(chunks)

    fake_client = types.SimpleNamespace(
        chat=types.SimpleNamespace(completions=_FakeCompletions())
    )
    monkeypatch.setattr(llm, "_client", fake_client)

    text, got = llm.chat("sys", "user")
    assert text == "Hello world"
    assert got == {"input_tokens": 11, "output_tokens": 7}


def test_chat_json_parses_streamed_text(monkeypatch):
    chunks = [_chunk('[{"id": '), _chunk('"TH-001"}]')]

    class _FakeCompletions:
        def create(self, **kwargs):
            return iter(chunks)

    monkeypatch.setattr(
        llm, "_client", types.SimpleNamespace(chat=types.SimpleNamespace(completions=_FakeCompletions()))
    )
    parsed, _ = llm.chat_json("sys", "user")
    assert parsed == [{"id": "TH-001"}]
