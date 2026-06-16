# How to Run IaC ThreatGen

Two ways to run the **same core pipeline**: the **CLI** (local) and the **GitHub Action** (CI).

---

## 1. Prerequisites

- **Python 3.11+** (developed/tested on 3.13.9).
- An **NVIDIA Developer API key** (`nvapi-…`) from <https://build.nvidia.com/>.
- *(Only for `--remediate`)* the **`terraform`** binary on `PATH` (the `terraform validate` gate).
- *(Only for `--open-pr`)* a **GitHub token** with `contents:write` + `pull_requests:write`.

---

## 2. Local setup (Windows / PowerShell — primary)

```powershell
./scripts/bootstrap.ps1                  # creates .venv, installs locked deps, copies .env
# edit .env -> set NVIDIA_API_KEY=nvapi-...
.\.venv\Scripts\python.exe scripts\check_env.py   # expect: PASS
```

Linux / macOS (matches CI):

```bash
./scripts/bootstrap.sh
cp .env.example .env          # then edit .env
python scripts/check_env.py
```

> The bootstrap installs the **exact locked dependency tree** (`requirements.lock.txt`).

---

## 3. CLI usage

```bash
# Basic scan -> JSON + Markdown report
iac-threatgen scan ./path/to/iac -o threat_report.json --markdown threat_report.md

# Also generate secure-by-default Terraform and validate it (needs terraform binary)
iac-threatgen scan ./infra --remediate -o report.json

# Generate remediation AND open a PR (needs GITHUB_TOKEN + GITHUB_REPOSITORY)
iac-threatgen scan ./infra --remediate --open-pr
```

If the `iac-threatgen` entry point isn't on PATH, use the module form:

```bash
python -m iac_threatgen.cli scan ./path/to/iac
```

**Try it on the bundled sample stack:**

```bash
python -m iac_threatgen.cli scan tests/fixtures/sample_stack --markdown report.md
```

### Exit codes
| Code | Meaning |
|----:|---------|
| 0 | Success — report written |
| 2 | Setup error (missing key/deps/path) |
| 3 | Runtime failure |

### Output
- **JSON** report — conforms to [`schemas/threat_report.schema.json`](../src/iac_threatgen/schemas/threat_report.schema.json) (validated every run).
- **Markdown** report — Mermaid DFD + STRIDE table + ATT&CK links + CSF mitigations.
- See a real example: [`examples/sample_report.md`](../examples/sample_report.md).

---

## 4. GitHub Action

Add your NVIDIA key as a repo secret named **`NVIDIA_API_KEY`**
(*Settings → Secrets and variables → Actions*). Then use the action — see the ready-made workflow
[`.github/workflows/threatgen.yml`](../.github/workflows/threatgen.yml):

```yaml
- uses: ./                       # or owner/iac-threatgen@v1 once published
  with:
    path: "."
    remediate: "false"
    open-pr: "false"
  env:
    NVIDIA_API_KEY: ${{ secrets.NVIDIA_API_KEY }}
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Action inputs:** `path`, `remediate`, `open-pr`, `output`, `markdown`, `python-version`.
**Action outputs:** `report-path`, `threat-count`.

To open remediation PRs from CI, the job needs:
```yaml
permissions:
  contents: write
  pull-requests: write
```

---

## 5. Configuration (env vars)

| Variable | Purpose | Default |
|---|---|---|
| `NVIDIA_API_KEY` | NVIDIA Developer API key (**required**) | — |
| `IAC_THREATGEN_MODEL` | model id | `meta/llama-3.3-70b-instruct` |
| `IAC_THREATGEN_BASE_URL` | OpenAI-compatible endpoint | `https://integrate.api.nvidia.com/v1` |
| `IAC_THREATGEN_TEMPERATURE` | sampling temperature | `0.2` |
| `GITHUB_TOKEN` / `GITHUB_REPOSITORY` | for `--open-pr` | — |
| `IAC_THREATGEN_DATA_DIR` | override bundled ATT&CK/CSF data dir | package data |

---

## 6. Security notes (practiced, not just preached)

- Secrets are read only from `.env` (git-ignored) or CI secrets — never hard-coded, never logged.
- Hardcoded secrets in IaC are **redacted before** the model call and never appear in the report/PR.
- IaC is treated as untrusted data; the PR agent only opens a branch + PR (never auto-merges).
