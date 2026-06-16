"""Shared pytest fixtures."""

from __future__ import annotations

import pathlib

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_stack() -> str:
    return str(FIXTURES / "sample_stack")
