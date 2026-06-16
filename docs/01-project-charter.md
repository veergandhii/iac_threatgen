# Project Charter — IaC ThreatGen

**Phase 1 · Planning**  |  **Role: Project Lead / Product Owner**  |  Date: 2026-06-16

---

## 1. Problem & vision

Security review of cloud infrastructure is manual, inconsistent, and lags behind how fast
Infrastructure-as-Code (IaC) changes. Threat models — when they exist — are written once in a
doc and rot. We want the threat model to be **generated from the real infrastructure** and
delivered **as a pull request the team can merge**, so security keeps pace with the repo.

**Vision:** An agent that reads Terraform / Kubernetes IaC and reasons about it like a senior
cloud architect — producing a STRIDE threat model, mapping each threat to MITRE ATT&CK (Cloud)
techniques, recommending NIST CSF–aligned mitigations, and opening a secure-by-default
Terraform PR.

## 2. Goals (in scope)

| # | Goal | Measure of done |
|---|------|-----------------|
| G1 | Parse Terraform (HCL) and Kubernetes (YAML) into a normalized resource graph | Parser handles the sample fixtures with 0 crashes; unknown blocks degrade gracefully |
| G2 | Generate a STRIDE threat table grounded in the parsed resources | Each threat cites a concrete resource + STRIDE category |
| G3 | Map threats to MITRE ATT&CK Cloud TTPs via RAG | Each mapping cites a real ATT&CK technique ID (e.g. `T1190`) |
| G4 | Recommend NIST CSF–aligned mitigations | Each mitigation references a CSF function/subcategory |
| G5 | Emit a Mermaid data-flow diagram (DFD) of the infrastructure | DFD renders in GitHub Markdown |
| G6 | Open a **syntax-validated** secure-by-default Terraform PR | `terraform validate` passes on the PR branch |
| G7 | Ship as a CLI **and** a GitHub Action | Both run the same core pipeline |

## 3. Non-goals (explicit scope boundaries)

- ❌ Live cloud account scanning (CSPM) — we reason about IaC, not running infra.
- ❌ Auto-merge — the agent **proposes**; a human approves the PR.
- ❌ Provider coverage beyond Terraform + Kubernetes in the capstone (AWS-leaning examples).
- ❌ A hosted web UI / SaaS — out of scope for a finite capstone.
- ❌ Maintenance phase — excluded per project definition (finite build).

## 4. Success metrics

- **Coverage:** ≥ 90% of parsed resources appear in the threat table.
- **Groundedness:** 100% of ATT&CK mappings reference a real technique ID present in the
  ATT&CK corpus (no hallucinated IDs) — enforced by a validator in Phase 5.
- **PR validity:** 100% of generated PRs pass `terraform validate` (Phase 6 gate).
- **Determinism of structure:** output always conforms to a fixed schema (STRIDE table,
  TTP map, CSF mitigations, DFD) regardless of input.
- **Cost guardrail:** a full run on a sample stack stays within a documented token budget.

## 5. Stakeholders & RACI

| Activity | Product Owner | Solutions Architect | Senior Engineer | QA/Security | DevOps |
|----------|:-:|:-:|:-:|:-:|:-:|
| Scope & priorities | **A/R** | C | C | C | C |
| Architecture & agent topology | C | **A/R** | C | C | C |
| Implementation | I | C | **A/R** | C | C |
| Testing & security validation | C | C | C | **A/R** | C |
| CI/CD & release | I | C | C | C | **A/R** |

*(R = Responsible, A = Accountable, C = Consulted, I = Informed. One role is adopted per SDLC phase.)*

## 6. Constraints & assumptions

- **LLM backend:** NVIDIA Developer API (OpenAI-compatible NIM endpoint), via the official
  `openai` SDK pointed at `https://integrate.api.nvidia.com/v1`. Model `meta/llama-3.3-70b-instruct`.
- **Runtime:** Python 3.13.9 (local) / Linux runners (CI). Windows is the primary dev box.
- **Dependency discipline:** exact pins, introduced one phase at a time (the user reports
  frequent dependency-conflict pain — this is mitigated by design; see R-01).
- **RAG retrieval backend chosen in Phase 3:** NVIDIA does host embedding NIMs, but to keep the
  dep tree light and deterministic we default to evaluating local embeddings vs. lexical/BM25
  over the ATT&CK corpus (see R-02).
- **External calls:** `terraform` binary required for the validation gate (Phase 6).

## 7. Security & compliance (lightweight, woven in)

The tool models threats, so it must be exemplary:

- **Secrets handling:** keys/tokens only in `.env` (git-ignored) or CI secrets; never logged, never in prompts.
- **Least privilege:** GitHub PR token scoped to `contents:write` + `pull_requests:write` on one repo.
- **Supply-chain hygiene:** pinned deps, `ruff` security lint (`flake8-bandit`) in CI from Phase 5.
- **Untrusted input:** IaC text is data, never executed; treated as a prompt-injection surface (Phase 4 hardening).

## 8. High-level plan

See [milestones.md](milestones.md) for per-phase objectives and exit criteria, and
[risk-register.md](risk-register.md) for ranked risks. Each phase is gated: we do not advance
until its exit criteria are met and confirmed.
