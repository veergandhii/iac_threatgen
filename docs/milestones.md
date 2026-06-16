# Milestones & Phase Gates

Each phase ships **plan + runnable artifacts** and is gated by explicit exit criteria.
We do not advance until the gate is met and confirmed.

| Phase | Role | Key deliverables | Exit criteria (gate) |
|------:|------|------------------|----------------------|
| **1. Planning** | Project Lead / PO | Charter, scope, success metrics, RACI, risk register, repo scaffold, env baseline, connectivity check | `check_env.py` reaches NVIDIA `meta/llama-3.3-70b-instruct`; scaffold present; scope signed off |
| **2. Requirements** | Requirements Analyst | Functional + non-functional requirements, user stories w/ acceptance criteria, I/O contracts (input IaC → output schema), traceability matrix | Every Phase-1 goal maps to ≥1 testable requirement; output JSON schema agreed |
| **3. Design** | Solutions Architect | System architecture, Level-0/1 DFDs, LangGraph agent topology + state schema, RAG design (corpus + retrieval backend), full pinned dependency set | Architecture review passes; deps install clean together on 3.13; state contract defined |
| **4. Implementation** | Senior Engineer | IaC parser, STRIDE mapper (RAG), remediation agent, PR agent, CLI — all runnable | End-to-end run on a sample stack produces the full report locally |
| **5. Testing** | QA / Security Engineer | Unit + integration tests, ATT&CK-ID groundedness validator, prompt-injection tests, security lint gate | Tests green; groundedness validator passes; no high-severity lint findings |
| **6. Integration & Deployment** | DevOps Engineer | GitHub Action workflow, packaging, `terraform validate` gate, docs | Action runs in CI and opens a validated PR on a demo repo |

## Sequencing notes

- **Dependencies are added at the phase that first needs them**, with cross-compatibility
  confirmed at that point (R-01 mitigation). Phase 1 pins only the `openai` SDK baseline.
- **RAG corpus + retrieval backend** is a Phase-3 decision — the choice (local embeddings vs.
  lexical/BM25 over the ATT&CK corpus) affects the dep set (R-02).
- **`terraform` binary** is only required for the Phase-6 validation gate; earlier phases can
  emit and self-check HCL without it.

## Phase 1 — Definition of Done

- [x] Repo scaffold created (`docs/`, `scripts/`, `src/`, `tests/`, config).
- [x] Charter with scope, non-goals, success metrics, RACI.
- [x] Risk register with ranked risks + mitigations.
- [x] Pinned Phase-1 env baseline (`openai==2.41.1`, `python-dotenv==1.2.2`) + bootstrap scripts.
- [x] `python scripts/check_env.py` returns **PASS** against `meta/llama-3.3-70b-instruct` (2026-06-16).
- [x] Scope sign-off from stakeholder (you) — advanced to Phase 2 on 2026-06-16.

## Phases 2–4 — Definition of Done (2026-06-16)

- [x] **P2 Requirements:** functional/non-functional reqs, user stories, traceability, frozen I/O schemas.
- [x] **P3 Design:** architecture + DFDs + LangGraph topology; RAG = BM25 (R-02); full dep set resolved/installed/locked together on 3.13 (R-01).
- [x] **P4 Implementation:** parsers → STRIDE mapper (RAG) → DFD → remediation → PR agent → CLI, wired via LangGraph; **live end-to-end run** produced a schema-valid, 100%-grounded report.

## Phase 5 — Testing — Definition of Done (2026-06-16)

- [x] `pytest` suite: 41 tests (parser, redaction, DFD, groundedness, schema, LLM JSON, injection, mocked pipeline, CLI, PR, remediation).
- [x] **Coverage 92.6% ≥ 90% target**, enforced in CI (`--cov-fail-under=90`).
- [x] Prompt-injection isolation test (FR-16) + anti-hallucination/groundedness tests (FR-17).
- [x] Mocked-LLM pipeline test → CI runs with **no API key / no network**.
- [x] `ruff` (incl. flake8-bandit) clean across `src`, `scripts`, `tests`.

## Phase 6 — Integration & Deployment — Definition of Done (2026-06-16)

- [x] **GitHub Action** (`action.yml`, composite) wrapping the shared core; inputs/outputs documented.
- [x] **CI workflow** (`.github/workflows/ci.yml`): lint + test + coverage gate.
- [x] **Example consumer workflow** (`threatgen.yml`) with least-privilege permissions.
- [x] **Packaging fixed + proven:** data/schemas bundled in the wheel; resources resolve from a non-editable install.
- [x] **`terraform validate` gate** implemented (graceful when binary absent); PR agent opens branch+PR, never auto-merges.
- [x] Usage guide ([04-usage.md](04-usage.md)) — CLI + Action + secrets.
