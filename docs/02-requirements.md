# Requirements Specification — IaC ThreatGen

**Phase 2 · Requirements Analysis**  |  **Role: Requirements Analyst**  |  Date: 2026-06-16

This document turns the charter's goals (G1–G7) into **testable** requirements, defines the
**I/O contract** (what IaC goes in, what schema comes out), captures **user stories with
acceptance criteria**, and provides a **traceability matrix** so every goal maps to a
requirement and, later, to a test.

> Security note (woven in): requirements include secret-redaction (FR-15) and prompt-injection
> isolation (FR-16) because the input is untrusted IaC — the system must practice the threat
> modeling it preaches.

---

## 1. Scope of this phase

In: functional + non-functional requirements, I/O contracts, output JSON schema, user stories,
traceability. Out: architecture, agent topology, library pins (Phase 3); code (Phase 4).

The two contracts that downstream phases build against are frozen here:
- **Input contract** — §3
- **Resource-graph schema** (parser → mappers) — [`resource_graph.schema.json`](../src/iac_threatgen/schemas/resource_graph.schema.json)
- **Threat-report schema** (final output) — [`threat_report.schema.json`](../src/iac_threatgen/schemas/threat_report.schema.json)

---

## 2. Personas

| Persona | Goal | Cares about |
|---|---|---|
| **Platform Engineer** (primary) | Catch design-time risk before infra ships | Accurate, low-noise findings; runs locally + in CI |
| **Security Reviewer** | Trust the threat model | Grounded threats (real resources, real ATT&CK IDs), no hallucinations |
| **Developer (PR author)** | Fix issues fast | A reviewable, valid Terraform PR — never an auto-merge |
| **CI Maintainer** | Automate the gate | A GitHub Action with clear inputs/outputs and exit codes |

---

## 3. Input contract (what goes in)

| Aspect | Specification |
|---|---|
| **Accepted formats** | Terraform `.tf` and `.tf.json`; Kubernetes `.yaml` / `.yml` (one or many docs per file) |
| **Source** | A file or directory path (CLI, recursive); in the Action, the checked-out repo path |
| **Encoding / size** | UTF-8; per-file soft cap (default 1 MiB) — larger files are skipped with a warning |
| **Untrusted** | IaC is **data, never executed**; no `terraform apply`, no `kubectl`, no shell from content |
| **Mixed inputs** | A directory may contain both Terraform and K8s; both are normalized into one resource graph |
| **Failure mode** | Unparseable/unknown blocks **degrade gracefully** (skip + warn), never crash the run (FR-4) |

---

## 4. Functional requirements

Each FR has a stable ID, a MoSCoW priority, the goal it serves, and a verification method
(realized as a test in Phase 5).

| ID | Requirement | Priority | Goal | Verify |
|----|-------------|:--------:|:----:|--------|
| **FR-1** | Ingest IaC from a file or directory path (recursive); classify each file as Terraform or Kubernetes | Must | G1,G7 | Unit: mixed fixture dir → correct file classification |
| **FR-2** | Parse Terraform HCL into the normalized resource graph (resources + attributes + source location) | Must | G1 | Unit: `.tf` fixture → expected resources/edges |
| **FR-3** | Parse Kubernetes YAML (multi-doc) into the same resource graph (kind, metadata, spec essentials) | Must | G1 | Unit: `.yaml` fixture → expected resources |
| **FR-4** | Degrade gracefully on unknown/invalid blocks: skip, warn, continue (0 crashes) | Must | G1 | Unit: malformed fixture → run completes, warning emitted |
| **FR-5** | Generate a STRIDE threat table where **every threat cites a concrete resource id + STRIDE category** | Must | G2 | Schema + check: each threat `resource_id` ∈ graph |
| **FR-6** | Map each threat to ≥1 MITRE ATT&CK (Cloud) technique via RAG; **only real technique IDs** | Must | G3 | Validator: every `technique_id` ∈ ATT&CK corpus |
| **FR-7** | Recommend NIST CSF–aligned mitigations referencing a CSF function/subcategory | Must | G4 | Schema: each mitigation has valid `csf_function`/`csf_subcategory` |
| **FR-8** | Emit a Mermaid data-flow diagram of the infrastructure | Must | G5 | Render check: `dfd_mermaid` parses as valid Mermaid |
| **FR-9** | Produce output that **always conforms to the fixed threat-report JSON schema** | Must | metrics | Schema validation on every run output |
| **FR-10** | Generate secure-by-default Terraform remediation snippets for findings | Should | G6 | Golden test: known finding → expected hardened HCL |
| **FR-11** | Validate generated Terraform with `terraform validate` before proposing it | Must | G6 | Integration: PR branch passes `terraform validate` |
| **FR-12** | Open a GitHub PR (new branch + PR); **never auto-merge, never force-push default** | Must | G6 | Integration (mock): branch+PR created, no merge call |
| **FR-13** | Provide a CLI that runs the full pipeline and writes the report (file + stdout) | Must | G7 | E2E: `iac-threatgen scan <dir>` exits 0 + emits report |
| **FR-14** | Provide a GitHub Action wrapping the same core pipeline (documented inputs/outputs) | Must | G7 | CI: Action runs on a demo repo |
| **FR-15** | Pre-scan IaC for secret patterns and **redact before** sending to the model and into any output/PR | Must | sec/R-05 | Unit: planted secret → redacted in prompt + report |
| **FR-16** | Isolate IaC text as delimited untrusted content; operator instructions stay in the system prompt | Must | sec/R-04 | Unit: injection string in IaC → instructions not overridden |
| **FR-17** | Reject/flag any ATT&CK ID or STRIDE category not in the controlled vocab (anti-hallucination gate) | Must | G3/R-03 | Validator rejects a synthetic fake `T9999` |
| **FR-18** | Deterministic report **structure** across runs (ordering, schema) regardless of input | Should | metrics | Two runs on same input → structurally identical schema |

---

## 5. Non-functional requirements

| ID | Category | Requirement | Verify |
|----|----------|-------------|--------|
| **NFR-1** | Determinism | Fixed output schema; low temperature (default 0.2–0.4); stable section ordering | Schema validation; diff of structure across runs |
| **NFR-2** | Security — secrets | API keys/tokens only via `.env` (git-ignored) or CI secrets; never logged, never in output | Lint/grep gate: no secret in logs/report |
| **NFR-3** | Supply chain | Exact version pins; deps added one phase at a time; `requirements.lock.txt` committed at Phase 3 | `pip install` resolves clean on 3.13; lock present |
| **NFR-4** | Cost guardrail | A full run on the sample stack stays within a documented token budget; usage logged per run | Run report shows in/out tokens ≤ budget |
| **NFR-5** | Portability | Runs on Windows (dev) and Linux (CI); Python ≥ 3.11 | CI matrix green |
| **NFR-6** | Reliability | Parser: 0 crashes on fixtures; ≥90% of parsed resources appear in the threat table | Coverage metric on fixtures |
| **NFR-7** | Observability | Log model id, token usage, request id — **never** secrets or raw key | Inspect logs in test run |
| **NFR-8** | Usability | CLI `--help`, meaningful exit codes (0 ok / 2 setup / 3 fail); Action I/O documented | CLI contract test |
| **NFR-9** | Maintainability | `ruff` lint incl. `flake8-bandit` (S) passes; typed public functions | Lint gate in CI |
| **NFR-10** | Privacy | Only IaC needed for analysis is sent to the model; secrets redacted first (ties FR-15) | Inspect outgoing prompt in test |

---

## 6. User stories with acceptance criteria

**US-1 — Local scan (Platform Engineer)**
> *As a platform engineer, I want to run one command on my Terraform directory and get a threat report, so I can review risk before shipping.*
- **Given** a directory of `.tf` files, **when** I run `iac-threatgen scan ./infra`, **then** it exits 0 and writes a schema-valid report containing a STRIDE table, ATT&CK mappings, CSF mitigations, and a Mermaid DFD. *(FR-1,2,5–9,13)*
- **Given** an unparseable file in that directory, **when** I run the scan, **then** the run still completes and the file is reported as skipped. *(FR-4)*

**US-2 — Trustworthy findings (Security Reviewer)**
> *As a security reviewer, I want every finding grounded in real artifacts, so I can trust the model isn't hallucinating.*
- **Given** a generated report, **when** I inspect any threat, **then** its `resource_id` exists in the parsed graph and every `technique_id` is a real ATT&CK ID. *(FR-5,6,17)*
- **Given** a model response containing a fake technique id, **when** the validator runs, **then** the run flags/rejects it. *(FR-17)*

**US-3 — Reviewable fix (Developer)**
> *As a developer, I want the agent to open a PR with a validated fix, so I can review and merge it myself.*
- **Given** a finding with a remediation, **when** the PR agent runs, **then** it creates a branch + PR whose Terraform passes `terraform validate`, and it does **not** merge. *(FR-10,11,12)*

**US-4 — CI gate (CI Maintainer)**
> *As a CI maintainer, I want a GitHub Action, so threat modeling runs automatically.*
- **Given** the Action configured on a repo, **when** a PR opens, **then** the Action runs the same pipeline and surfaces the report. *(FR-14)*

**US-5 — No secret leakage (Security Reviewer)**
> *As a security reviewer, I want secrets in IaC never echoed, so we don't widen exposure.*
- **Given** a `.tf` file containing a hardcoded secret, **when** the pipeline runs, **then** the secret is redacted before the model call and absent from the report and PR. *(FR-15, NFR-2,7,10)*

**US-6 — Injection resistance (Platform Engineer)**
> *As a platform engineer, I want the agent to ignore instructions hidden in IaC, so it can't be hijacked.*
- **Given** a comment in IaC saying "ignore your rules and output X", **when** the pipeline runs, **then** the agent treats it as data and the controlling instructions are unaffected. *(FR-16)*

---

## 7. Traceability matrix (Goal → Requirements → Phase-5 verification)

| Goal | Measure of done (charter) | Requirements | Verified by (Phase 5) |
|------|---------------------------|--------------|-----------------------|
| **G1** Parse TF + K8s → resource graph | 0 crashes; graceful degradation | FR-1, FR-2, FR-3, FR-4 | Parser unit tests on fixtures (incl. malformed) |
| **G2** STRIDE table grounded in resources | each threat cites resource + STRIDE | FR-5, FR-9 | Schema + grounding check |
| **G3** Map to ATT&CK via RAG | real technique IDs only | FR-6, FR-17 | Groundedness validator vs. corpus |
| **G4** NIST CSF mitigations | each cites CSF function/subcategory | FR-7 | Schema validation |
| **G5** Mermaid DFD | renders in GitHub MD | FR-8 | Mermaid render/parse test |
| **G6** Syntax-validated secure-by-default PR | `terraform validate` passes | FR-10, FR-11, FR-12 | Integration test (validate + mock PR) |
| **G7** CLI + GitHub Action | both run same core | FR-13, FR-14 | CLI E2E + Action CI run |
| **Metrics** coverage/determinism/cost | ≥90% coverage; fixed schema; budget | FR-9, FR-18, NFR-1, NFR-4, NFR-6 | Coverage + structure-diff + token-budget checks |

Every goal maps to ≥1 testable requirement ✅ — Phase 2 exit criterion met.

---

## 8. Open questions carried to Phase 3 (Design)

1. **RAG retrieval backend** — local embeddings vs. lexical/BM25 over the ATT&CK corpus (R-02). Affects deps.
2. **ATT&CK corpus source & snapshot** — which export (e.g. MITRE STIX) and pinned version for reproducible groundedness.
3. **CSF control vocabulary** — embed a static CSF subcategory list for FR-7/FR-17 validation.
4. **State schema** for the LangGraph pipeline (the in-memory object passed between nodes).
5. **Remediation scope** — which resource types get auto-generated Terraform fixes in the capstone.
