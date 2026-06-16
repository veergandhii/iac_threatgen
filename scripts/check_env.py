#!/usr/bin/env python3
"""Phase-1 environment & connectivity sanity check.

Verifies that:
  1. the ``openai`` SDK is importable,
  2. an NVIDIA API key is configured (from .env or the environment),
  3. the configured model (``meta/llama-3.3-70b-instruct``) is reachable via NVIDIA's
     OpenAI-compatible endpoint and responds.

Exit codes:
  0  PASS  — SDK present, key set, model reachable
  2  SETUP — SDK or key missing (actionable: install deps / set key)
  3  FAIL  — API reachable but returned an error (auth / model / network)

Run:  python scripts/check_env.py
"""

from __future__ import annotations

import sys

GREEN, RED, YEL, DIM, RST = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def _info(msg: str) -> None:
    print(f"{DIM}-{RST} {msg}")


def main() -> int:
    # --- 1. SDK import -------------------------------------------------------
    try:
        import openai
    except ModuleNotFoundError:
        print(f"{RED}SETUP{RST} 'openai' not installed.")
        print("      Fix: run ./scripts/bootstrap.ps1 (Windows) or ./scripts/bootstrap.sh,")
        print("           or: pip install -r requirements.txt")
        return 2

    _info(f"openai SDK version: {openai.__version__}")

    # --- 2. Load .env (optional) + check key --------------------------------
    try:
        from dotenv import load_dotenv

        load_dotenv()
        _info(".env loaded (if present)")
    except ModuleNotFoundError:
        _info("python-dotenv not installed; reading key from process env only")

    import os

    # Import config from the package (single source of truth).
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    try:
        from iac_threatgen.constants import API_KEY_ENV, BASE_URL, MODEL
    except ModuleNotFoundError:
        API_KEY_ENV = "NVIDIA_API_KEY"
        BASE_URL = os.getenv("IAC_THREATGEN_BASE_URL", "https://integrate.api.nvidia.com/v1")
        MODEL = os.getenv("IAC_THREATGEN_MODEL", "meta/llama-3.3-70b-instruct")

    api_key = os.getenv(API_KEY_ENV)
    if not api_key:
        print(f"{YEL}SETUP{RST} {API_KEY_ENV} is not set.")
        print("      Fix: copy .env.example to .env and paste your nvapi- key, then re-run.")
        return 2

    _info(f"endpoint: {BASE_URL}")
    _info(f"target model: {MODEL}")

    # --- 3. Live connectivity check -----------------------------------------
    client = openai.OpenAI(base_url=BASE_URL, api_key=api_key)
    try:
        resp = client.chat.completions.create(
            model=MODEL,
            max_tokens=64,
            temperature=0,
            messages=[
                {
                    "role": "user",
                    "content": "Reply with exactly: IaC ThreatGen connectivity OK",
                }
            ],
        )
    except openai.AuthenticationError:
        print(f"{RED}FAIL{RST}  Authentication failed — the API key is invalid or revoked.")
        return 3
    except openai.NotFoundError:
        print(f"{RED}FAIL{RST}  Model '{MODEL}' not found for this endpoint.")
        print("      Check the model id in src/iac_threatgen/constants.py.")
        return 3
    except openai.APIConnectionError:
        print(f"{RED}FAIL{RST}  Network error reaching {BASE_URL}. Check connectivity.")
        return 3
    except openai.APIStatusError as e:
        print(f"{RED}FAIL{RST}  API error {e.status_code}: {e.message}")
        return 3

    text = (resp.choices[0].message.content or "").strip()
    print(f"{GREEN}PASS{RST}  Model responded: {text!r}")
    usage = resp.usage
    if usage is not None:
        _info(f"usage: in={usage.prompt_tokens} out={usage.completion_tokens} id={resp.id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
