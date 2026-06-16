"""LLM JSON-extraction tests (robustness of parsing model output)."""

from __future__ import annotations

import pytest

from iac_threatgen.llm import extract_json


def test_plain_json_object():
    assert extract_json('{"a": 1}') == {"a": 1}


def test_fenced_json():
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_prose_wrapped_array():
    text = 'Here is the result:\n[{"id": "TH-001"}]\nHope that helps!'
    assert extract_json(text) == [{"id": "TH-001"}]


def test_braces_inside_strings_do_not_break_balance():
    assert extract_json('{"k": "a } b"}') == {"k": "a } b"}


def test_raises_without_json():
    with pytest.raises(ValueError):
        extract_json("no json here")
