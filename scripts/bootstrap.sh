#!/usr/bin/env bash
# Phase-1 environment bootstrap (Linux / macOS — matches CI).
# Creates a venv, upgrades pip, installs the pinned baseline, and reminds about .env.
# Usage:  ./scripts/bootstrap.sh
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Python version:"
python3 --version

if [ ! -d ".venv" ]; then
  echo "==> Creating virtual environment (.venv)"
  python3 -m venv .venv
fi

echo "==> Activating .venv"
# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> Upgrading pip"
python -m pip install --upgrade pip

echo "==> Installing pinned baseline (requirements.txt)"
pip install -r requirements.txt

echo "==> Installing package in editable mode"
pip install -e .

if [ ! -f ".env" ]; then
  cp .env.example .env
  echo "==> Created .env from template. EDIT IT and paste your NVIDIA_API_KEY."
fi

echo ""
echo "Done. Next:"
echo "  1) Edit .env -> set NVIDIA_API_KEY (nvapi-...)"
echo "  2) python scripts/check_env.py"
