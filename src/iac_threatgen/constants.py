"""Single source of truth for the LLM backend configuration.

Backend: **NVIDIA Developer API** (NIM) — an OpenAI-compatible inference endpoint.
We talk to it with the official ``openai`` SDK by pointing ``base_url`` at NVIDIA's
endpoint and authenticating with an ``nvapi-...`` key.

Model decision (2026-06-16): ``meta/llama-3.3-70b-instruct`` — chosen for the most
reliable instruction-following of the available NVIDIA-hosted set, which the STRIDE /
MITRE ATT&CK / NIST CSF structured-output nodes depend on.

Notes:
- This endpoint is OpenAI-compatible: use ``chat.completions.create(...)``.
- There is no Anthropic-style ``thinking``/``effort`` parameter here; reasoning depth is
  steered via the system prompt and ``temperature``.
- Long-output calls should **stream** to avoid client HTTP timeouts.
"""

from __future__ import annotations

import os

# NVIDIA Developer API (OpenAI-compatible). Overridable for self-hosted NIM.
BASE_URL: str = os.getenv("IAC_THREATGEN_BASE_URL", "https://integrate.api.nvidia.com/v1")

# Default model. Overridable via env for experiments, but pinned by default.
MODEL: str = os.getenv("IAC_THREATGEN_MODEL", "meta/llama-3.3-70b-instruct")

# Sampling defaults. Low temperature for deterministic, grounded security output.
TEMPERATURE: float = float(os.getenv("IAC_THREATGEN_TEMPERATURE", "0.2"))
TOP_P: float = float(os.getenv("IAC_THREATGEN_TOP_P", "0.95"))

# Conservative max_tokens defaults:
#   non-streaming stays under client HTTP timeouts; streaming gets more room.
MAX_TOKENS_NONSTREAMING: int = 4_096
MAX_TOKENS_STREAMING: int = 16_384

# Name of the environment variable that holds the API key.
API_KEY_ENV: str = "NVIDIA_API_KEY"
