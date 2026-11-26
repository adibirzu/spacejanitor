# PRD-005: On-Demand Local SLM Cleanup & Forensics Advisor

**Version:** 1.0  
**Status:** Partially implemented (loopback advisor on `main`; GGUF spawning, grammar decoding and benchmarks not implemented)
**Related ADRs:** [ADR-004](../adr/ADR-004-privacy-zero-leak-and-two-step-remediation.md), [ADR-005](../adr/ADR-005-local-slm-cleanup-advisor.md)

---

## 1. Objective & Problem

When SpaceJanitor surfaces unfamiliar large directories, idle worktrees, OS Trash accumulations, or complex process/memory blockers, users want concise, plain-language guidance (*"What is this, why is it safe or unsafe to clean, and how much RAM/disk will it recover?"*) without sending private workstation paths to cloud APIs or wasting resident RAM on an always-on LLM daemon.

## 2. Target Personas

- **Workstation User:** Wants clear, prioritized explanations and proposed dry-run cleanups before confirming actions.
- **Fleet Evaluator:** Tests accuracy, latency, and RAM footprint of 0.5B–1.5B GGUF SLMs across macOS, Linux, and Windows (`x86_64` and `ARM64`).

## 3. Functional Requirements

| ID | Requirement | Priority |
|---|---|---|
| **FR-5.1** | **Opt-In On-Demand Execution (`spacejanitor advise` / UI "Analyze"):** Spawn local `llama.cpp` inference (or connect to configured `localhost` Ollama/OpenAI-compatible server) only on request and terminate/unload immediately on completion (`0 MiB` idle). | P0 |
| **FR-5.2** | **Grammar-Constrained Structured Proposals (`spacejanitor.proposal.v1`):** Enforce JSON Schema / GBNF decoding producing typed proposals: `target`, `category`, `safety_tier` (`safe_cache`, `review`, `keep_protected`), `estimated_reclaim`, `rationale`, and `dry_run_command`. | P0 |
| **FR-5.3** | **Memory-Pressure Self-Guard:** Check `spacejanitor.memory.v1` before loading GGUF weights; refuse inference cleanly when free/available RAM is `< 2.5 GiB` or swap is critical, falling back to deterministic heuristic summaries. | P0 |
| **FR-5.4** | **Deterministic Core Re-Validation:** Pass every SLM-proposed path or PID through `sj-core` (`is_protected_path`, git clean/pushed proof, `PPID == 1` verification) before presenting it as actionable in dry-run UI or CLI. | P0 |
| **FR-5.5** | **Model Profile Presets:** Ship preset configurations for **Ultra-Tiny (`0.5B` / `360M` Q4_K_M)** and **Balanced (`1.0B–1.7B` Q4_K_M)** models with fixed `-c 2048 --temp 0.1` context caps. | P1 |
| **FR-5.6** | **Fleet Evaluation Harness:** Provide a synthetic fixture benchmark comparing JSON validity rate, latency, peak RSS, and false-unsafe proposal rate (`0%` allowed on protected/dirty fixtures) across `x86_64` and `ARM64` hosts. | P1 |

## 4. Non-Functional Requirements

- **Idle RAM:** `0 MiB` when advisor is not actively generating a proposal.
- **Peak RAM:** `<= 1.2 GiB` (Ultra-Tiny tier) / `<= 2.5 GiB` (Standard tier) at `-c 2048`.
- **Safety Violation Rate:** `0%` (hard invariant enforced deterministically by `sj-core`, never trusting model output alone).
- **Latency:** `< 5s` per proposal batch on Apple Silicon / modern x64 CPUs.

## 5. Acceptance Criteria & Milestones

- **M1 (PRD-005 / Milestone 6):** Grammar schema + redacted prompt builder + memory-pressure self-guard + deterministic re-validator pass synthetic unit tests with 0% unsafe recommendations.
- **M2 (Fleet Eval):** Benchmark across macOS ARM64, Linux x64/ARM64, and Windows hosts records peak RAM, inference latency, and JSON accuracy.

---

## Implementation Status (as of `main`, PR #10)

| Requirement | State | Where |
|---|---|---|
| FR-5.1 Opt-in, on-demand | Implemented against a **loopback OpenAI-compatible endpoint** (for example Ollama), only on request and with a user-supplied URL. SpaceJanitor does not spawn or unload `llama.cpp` itself | `packages/core/src/slm.mjs`, `apps/desktop/src/slmAdvisor.ts` |
| FR-5.2 Grammar-constrained proposals | Partial: JSON-shaped response with `temperature 0.1`, parsed and validated; **no GBNF or JSON-schema constrained decoding** | `slm.mjs` |
| FR-5.3 Memory self-guard | Implemented: refuses below `2.5 GiB` free RAM (returns no proposals; no deterministic fallback) | `slm.mjs` |
| FR-5.4 Deterministic re-validation | Implemented: every proposed path goes through the Rust `sj protect` gate; protected targets become `keep_protected` | `slm.mjs`, `candidateAnnotations.ts` |
| FR-5.5 Model presets | Not implemented (default model name only) | n/a |
| FR-5.6 Evaluation harness | Not implemented | n/a |

The advisor has **no execution capability**; any action still goes through the `sj` two-step gate. Loopback-only enforcement covers `127.0.0.1`, `localhost` and `::1`.
