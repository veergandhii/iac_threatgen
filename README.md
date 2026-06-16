# IaC ThreatGen — Agentic Threat Model Generator from Infrastructure-as-Code

> Parses Terraform / Kubernetes YAML and auto-generates **STRIDE** threat models with
> **MITRE ATT&CK (Cloud)** mappings and **NIST CSF** mitigations, then opens
> secure-by-default Terraform pull requests.

This is an **industry-grade capstone**, built phase-by-phase as a professional SDLC.
Each phase ships a plan **and** runnable artifacts.

| Phase | SDLC stage | Status |
|------:|------------|--------|
| 1 | Planning (Project Lead / Product Owner) | ✅ done |
| 2 | Requirements Analysis (Requirements Analyst) | ✅ done |
| 3 | Design — architecture, DFD, agent topology (Solutions Architect) | ✅ done |
| 4 | Implementation (Senior Engineer) | ✅ done |
| 5 | Testing (QA / Security Engineer) | ✅ done |
| 6 | Integration & Deployment (DevOps Engineer) | ✅ done |

## Pipeline (target architecture)

```
IaC Parser ─▶ STRIDE Threat Mapper (RAG over MITRE ATT&CK Cloud) ─▶ Remediation Agent ─▶ GitHub PR Agent
```

Orchestrated as a **LangGraph** multi-agent pipeline; all LLM reasoning runs on the
**NVIDIA Developer API** (OpenAI-compatible NIM endpoint) via the official `openai` Python SDK.

- **Model:** `meta/llama-3.3-70b-instruct` (chosen for reliable structured instruction-following)
- **Output:** Mermaid data-flow diagram · STRIDE threat table · ATT&CK TTP mapping ·
  NIST CSF mitigations · a syntax-validated pull request
- **Surfaces:** CLI + GitHub Action

## Quick start

```powershell
# Windows / PowerShell (primary dev environment)
./scripts/bootstrap.ps1
copy .env.example .env        # then edit .env and paste your NVIDIA_API_KEY (nvapi-...)
python scripts/check_env.py   # verifies SDK + model connectivity (expect PASS)

# scan the bundled sample stack
python -m iac_threatgen.cli scan tests/fixtures/sample_stack --markdown report.md
```

```bash
# Linux / macOS (matches CI)
./scripts/bootstrap.sh
cp .env.example .env          # then edit .env
python scripts/check_env.py
iac-threatgen scan ./path/to/iac -o threat_report.json --markdown threat_report.md
```

Full run guide (CLI flags, GitHub Action, secrets): **[docs/04-usage.md](docs/04-usage.md)**.

## Repository layout

```
iac-threatgen/
├── README.md
├── pyproject.toml             # package metadata + tooling (ruff) config
├── requirements.txt           # pinned direct deps — grows one phase at a time
├── requirements.lock.txt      # exact resolved tree (pip freeze) — R-01 lock
├── .env.example               # secrets template (never commit the real .env)
├── .gitignore
├── action.yml                 # GitHub Action (composite) — same core pipeline
├── .github/workflows/         # ci.yml (lint+test) · threatgen.yml (example consumer)
├── docs/
│   ├── 01-project-charter.md  # vision, scope, success metrics, RACI
│   ├── 02-requirements.md     # functional/non-functional reqs, user stories, traceability
│   ├── 03-architecture.md     # architecture, DFDs, LangGraph topology, RAG + dep design
│   ├── 04-usage.md            # how to run (CLI + Action)
│   ├── milestones.md          # phase plan + exit criteria
│   └── risk-register.md       # ranked risks + mitigations
├── examples/                  # a real generated report (JSON + Markdown)
├── scripts/
│   ├── bootstrap.ps1/.sh      # env setup
│   ├── check_env.py           # connectivity / model sanity check
│   └── build_attack_corpus.py # regenerate the pinned ATT&CK snapshot
├── src/iac_threatgen/         # the package
│   ├── parsers/               # Terraform + Kubernetes -> resource graph
│   ├── data/                  # bundled ATT&CK corpus + NIST CSF vocab
│   ├── schemas/               # frozen I/O contracts (JSON Schema 2020-12)
│   ├── pipeline.py            # LangGraph wiring + run_pipeline (shared core)
│   ├── threats.py rag.py validation.py dfd.py remediation.py github_pr.py …
│   └── cli.py                 # `iac-threatgen` entry point
└── tests/                     # pytest suite (mocked LLM = CI needs no API key)
```

## Security posture (practiced, not just preached)

Threat modeling is the domain, so the project applies its own advice:

- **Secrets:** API keys/tokens live only in `.env` (git-ignored) or CI secrets — never in code, never in logs.
- **Least privilege:** the GitHub token used by the PR Agent needs only `contents:write` + `pull_requests:write` on the target repo.
- **Supply-chain hygiene:** every dependency is pinned to an exact version and introduced one phase at a time to keep the resolver conflict-free.
- **Untrusted input:** IaC files are untrusted data — they are never executed, and their text is treated as a prompt-injection surface (hardened in Phase 4).

See [docs/01-project-charter.md](docs/01-project-charter.md) for the full plan.
