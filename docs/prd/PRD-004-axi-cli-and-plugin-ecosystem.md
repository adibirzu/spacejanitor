# PRD-004: AXI CLI (`spacejanitor-axi`) & Plugin Ecosystem

**Version:** 1.0  
**Status:** Implemented from source (not published to npm; plugin runtime is declarative only)
**Related ADRs:** [ADR-003](../adr/ADR-003-axi-cli-and-plugin-contract.md), [ADR-004](../adr/ADR-004-privacy-zero-leak-and-two-step-remediation.md)

---

## 1. Objective & Problem

SpaceJanitor should serve equally well as a standalone human CLI, an AI-agent AXI skill (`npx -y spacejanitor-axi`), and an extensible telemetry/rule engine whose snapshots can feed external fleet dashboards or custom organization plugins without polluting the MIT core.

## 2. Target Personas

- **AI Coding Agents & Orchestrators:** Need compact TOON output and stable `--json` contracts to verify host health before spawning parallel workers or pruning old worktrees.
- **Platform & Plugin Authors:** Want to add custom cleanup rule packs, OS collectors, or dashboard exporters via a typed TypeScript SDK.

## 3. Functional Requirements

| ID | Requirement | Priority |
|---|---|---|
| **FR-4.1** | Provide zero-install Node CLI (`npx -y spacejanitor-axi` / `spacejanitor`) supporting `disk`, `memory`, `blockers`, `orphans`, `trash`, `mcp-audit`, `remediate`, and `doctor`. | P0 |
| **FR-4.2** | Emit token-efficient TOON output by default and versioned `--json` envelopes (`spacejanitor.storage.v1`, `spacejanitor.memory.v1`, `spacejanitor.blockers.v1`, `spacejanitor.orphans.v1`). | P0 |
| **FR-4.3** | Ship a portable `SKILL.md` (`skills/spacejanitor-axi/SKILL.md`) describing safe read-only diagnostic workflows and fail-closed remediation rules for AI agents. | P0 |
| **FR-4.4** | Publish `@spacejanitor/plugin-sdk` supporting four declarative extension capabilities: `rule-pack`, `collector`, `widget`, and `exporter`. | P1 |
| **FR-4.5** | Validate every loaded plugin rule against `packages/core` immutable protected paths at load time—rejecting or blocking protected targets deterministically. | P0 |

## 4. Non-Functional Requirements

- **Cold Start:** `spacejanitor doctor --json` executes in `< 150 ms` on Node `>= 20`.
- **Zero Forced External Dependencies in Core:** Core safety validation and CLI diagnostics run without external binaries or network calls.

## 5. Acceptance Criteria & Milestones

- **M1:** CLI `doctor`, core safety unit tests, `@spacejanitor/plugin-sdk` manifest validator, and `skills/spacejanitor-axi/SKILL.md` verified in CI.
- **M2:** Live collectors (`disk`, `memory`, `blockers`, `orphans`, `mcp-audit`) wired into CLI and consumed by both `apps/ui` and optional external exporter plugins.

---

## Implementation Status (as of `main`, PRs #10, #11, #15)

| Requirement | State | Where |
|---|---|---|
| FR-4.1 Zero-install Node CLI | Implemented from a clone: `summary`, `doctor`, `disk`, `memory`, `blockers`, `orphans`, `trash`, `mcp-audit`, `remediate`, `advise`. **`npx spacejanitor-axi` does not work: the package is unpublished** | `packages/cli/bin/spacejanitor.mjs` |
| FR-4.2 TOON and versioned JSON | Implemented (`spacejanitor.*.v1`); collectors call `sj` and fall back to read-only Node views | `packages/core/src/toon.mjs`, `sjGate.mjs` |
| FR-4.3 Agent skill | Implemented | `skills/spacejanitor-axi/SKILL.md` |
| FR-4.4 Plugin SDK | Partial: manifest validation for `rule-pack`, `collector`, `widget`, `exporter`; no plugin loader or runtime | `packages/plugin-sdk` |
| FR-4.5 Protected-target validation | Implemented: rules are checked through the Rust `sj protect` gate (no JS denylist) and fail closed | `packages/core/src/protect.mjs` |

The Node CLI cannot execute removals (`--execute` fails closed); the Rust `sj` and the desktop app are the only mutation paths. **Open:** npm publication (no release or tag exists), plugin loading.
