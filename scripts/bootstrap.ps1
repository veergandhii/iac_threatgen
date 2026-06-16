# Phase-1 environment bootstrap (Windows / PowerShell).
# Creates a venv, upgrades pip, installs the pinned baseline, and reminds about .env.
# Usage:  ./scripts/bootstrap.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "==> Python version:" -ForegroundColor Cyan
python --version

if (-not (Test-Path ".venv")) {
    Write-Host "==> Creating virtual environment (.venv)" -ForegroundColor Cyan
    python -m venv .venv
}

Write-Host "==> Activating .venv" -ForegroundColor Cyan
& ".\.venv\Scripts\Activate.ps1"

Write-Host "==> Upgrading pip" -ForegroundColor Cyan
python -m pip install --upgrade pip

Write-Host "==> Installing pinned baseline (requirements.txt)" -ForegroundColor Cyan
pip install -r requirements.txt

Write-Host "==> Installing package in editable mode" -ForegroundColor Cyan
pip install -e .

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "==> Created .env from template. EDIT IT and paste your NVIDIA_API_KEY." -ForegroundColor Yellow
}

Write-Host "`nDone. Next:" -ForegroundColor Green
Write-Host "  1) Edit .env -> set NVIDIA_API_KEY (nvapi-...)"
Write-Host "  2) python scripts/check_env.py"
