# ADR-005: On-Demand Tiny Local SLM Cleanup Advisor

- **Status:** Accepted; partially implemented (loopback advisor shipped; GGUF lifecycle and constrained decoding not built)
- **Date:** 2026-11-24
- **Drivers:** Intelligent classification and plain-language cleanup proposals for unfamiliar caches/orphans without cloud telemetry, cost, or idle RAM overhead.

---

## Context

Deterministic rules catch known package caches (`npm`, `cargo`, `pip`) and clean/pushed git worktrees, but users often encounter unfamiliar application caches, orphaned work directories, or repeated process clusters where a rule-only table feels opaque. Sending filesystem paths or process commands to a cloud LLM violates local privacy, fails offline, and introduces API cost. Conversely, running a large local LLM continuously would worsen workstation memory pressure.

## Decision

Integrate an **optional, strictly on-demand Small Language Model (SLM) advisor** running quantized **0.5B–1.5B parameter GGUF models** locally via `llama.cpp` (or an optional user-configured local OpenAI-compatible/Ollama endpoint):

### 1. Recommended Model Tiers (`Q4_K_M` GGUF, `-c 2048 --temp 0.1`)

| Tier | Recommended Models | Disk Weight Size | Peak RAM (On-Demand) | Idle RAM | Target Hosts |
|---|---|---:|---:|---:|---|
| **Ultra-Tiny** | **Qwen2.5 / Qwen3 0.5B Instruct**, **SmolLM2 360M** | ~350–450 MiB | ~1.0–1.2 GiB | **0 MiB** | Low-RAM laptops, SBCs, Linux/Windows ARM64 edge nodes |
| **Standard Advisor** | **Qwen2.5 / Qwen3 1.5B Instruct**, **Llama 3.2 1B**, **SmolLM2 1.7B** | ~650 MiB–1.1 GiB | ~1.4–2.4 GiB | **0 MiB** | Standard macOS/Linux/Windows developer workstations |

### 2. Strict Grammar & Execution Guardrails

1. **Zero Idle Footprint:** The SLM process is spawned **only** when the user explicitly clicks *"Explain / Propose Cleanup"* or runs `spacejanitor advise`, and unloads immediately once the JSON proposal completes.
2. **GBNF / JSON Schema Grammar Constraint:** Decoding uses `llama.cpp` JSON Schema / GBNF grammar enforcement so the model cannot emit malformed JSON or invent unrecognized fields (`rule_id`, `tier`, `risk`, `rationale`, `recommended_action`).
3. **Read-Only Metadata Input & Secret Redaction:** The prompt receives only redacted summary metadata (directory path basename/depth, byte size, age in days, git clean/pushed status, process owner group, RSS/compressed MiB)—never raw file contents or unredacted CLI secrets.
4. **Deterministic Gate Override:** The SLM **never** executes commands or deletes files. Every candidate it proposes is re-validated against `sj-core` (`is_protected_path()`, git safety proof) and requires standard two-step human confirmation.
5. **Memory-Pressure Self-Guard:** Before loading a GGUF file, `sj-core` checks live available RAM (`>= 2.5 GiB` free/reclaimable and swap below critical ceiling). If the host is already critically starved, the advisor refuses model load and emits deterministic rule explanations instead.

## Consequences

- **Positive:** Plain-English reasoning over novel disk/RAM consumers completely offline with `0 MiB` background RAM cost and strict schema safety.
- **Negative / Mitigation:** Requires downloading a ~400 MiB–1.1 GiB GGUF file if enabled; mitigated by keeping the SLM advisor 100% opt-in and always pairing it with deterministic fallback explanations.

---

## Implementation Status (as of `main`)

| Decision area | State |
|---|---|
| On-demand, off by default, `0 MiB` idle | Implemented (no resident model; user supplies a loopback endpoint) |
| Loopback-only (`127.0.0.1`, `localhost`, `::1`) | Implemented and tested |
| `2.5 GiB` free-RAM self-guard with deterministic fallback | Implemented |
| Redacted input, no execution capability, re-validation by `sj protect` | Implemented |
| Spawning/unloading GGUF via `llama.cpp`, GBNF/grammar decoding, model presets, fleet benchmark | Not implemented |
