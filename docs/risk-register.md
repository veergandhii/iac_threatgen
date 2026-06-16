# Risk Register

Ranked by exposure (Likelihood × Impact). Owned by the Project Lead; revisited each phase gate.

| ID | Risk | L | I | Exposure | Mitigation | Owner / phase |
|----|------|:-:|:-:|:--------:|------------|---------------|
| **R-01** | **Dependency conflicts / version hell** (langgraph ↔ langchain-core ↔ pydantic ↔ openai) — flagged as a recurring pain point | H | H | 🔴 High | Pin exact versions; introduce deps **one phase at a time**; lock the full set in Phase 3 and verify they install together on 3.13 before coding; commit a `requirements.lock.txt` via `pip freeze`; call the NVIDIA endpoint through the official `openai` SDK directly (avoid `langchain-openai` to drop one tightly-coupled version constraint) | PO → Architect (P3) |
| **R-02** | **RAG retrieval backend choice** — a remote embeddings call adds latency, cost, and a network dependency | H | M | 🟠 Med | Decide retrieval backend in Phase 3: local embeddings (`sentence-transformers`/`fastembed`) **or** lexical retrieval (BM25) over the ATT&CK corpus. Lexical keeps the dep tree light and deterministic; evaluate both on groundedness | Architect (P3) |
| **R-03** | **Hallucinated ATT&CK technique IDs / STRIDE mappings** | M | H | 🟠 Med | Ground generation in retrieved ATT&CK text; add a Phase-5 validator that rejects any technique ID not in the corpus; low temperature + structured output schema | QA/Sec (P5) |
| **R-04** | **Prompt injection via IaC content** (a comment/name in a `.tf` file telling the agent to ignore instructions) | M | H | 🟠 Med | Treat IaC as untrusted data; isolate it in clearly delimited user content; keep operator instructions in the system prompt; never let model output drive shell/git actions without validation | Eng/Sec (P4–P5) |
| **R-05** | **Secrets embedded in IaC** get echoed into prompts/outputs/PRs | M | H | 🟠 Med | Pre-scan IaC for secret patterns before sending to the model; redact; never write secrets into the generated PR or logs | Eng (P4) |
| **R-06** | **GitHub PR write scope too broad / token leak** | L | H | 🟡 Low | Fine-grained PAT limited to one repo, `contents`+`pull_requests` only; token from CI secret; PR agent opens a branch + PR, never force-pushes to default | DevOps (P6) |
| **R-07** | **LLM cost / rate limits** on large stacks | M | M | 🟡 Low | Token-count inputs before sending; chunk large stacks; prompt-cache the static system/corpus prefix; document a per-run budget; stream long outputs | Eng (P4) |
| **R-08** | **`terraform validate` needs the terraform binary** not present in all environments | M | M | 🟡 Low | Make the binary a Phase-6 CI prerequisite (`hashicorp/setup-terraform`); locally, degrade to a syntax self-check with a clear warning | DevOps (P6) |
| **R-09** | **Python 3.13 wheel availability** for a heavy transitive dep | L | M | 🟡 Low | Phase-1 baseline is pure-Python (verified). Re-check at Phase 3 when adding parsers/RAG; pin to versions with cp313 wheels; fall back to a 3.12 venv only if forced | Architect (P3) |
| **R-10** | **Non-deterministic LLM output breaks downstream parsing** | M | M | 🟡 Low | Constrain to a fixed output schema (structured outputs); validate/repair before use; keep the report contract stable across runs | Eng (P4) |

**Legend:** L/I = Likelihood / Impact (L/M/H). Exposure is the qualitative product.

Top risk **R-01** drives a core process decision visible already in `requirements.txt`:
deps are added phase-by-phase, not all at once.
