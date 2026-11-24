# ADR-003: AXI CLI Output & Extensible Plugin Contract

- **Status:** Accepted
- **Date:** 2026-11-24
- **Drivers:** Agent-friendly token-efficient CLI (`spacejanitor-axi`), decoupled dashboard & collector plugins, long-term maintainability.

---

## Context

SpaceJanitor serves two primary callers:
1. **Human operators** inspecting workstation health via CLI or desktop widgets.
2. **AI coding agents and external observability dashboards** needing compact, deterministic structured telemetry and pluggable rule packs without coupling custom integrations into SpaceJanitor's core.

## Decision

### 1. AXI CLI Standard (`packages/cli`, binary `spacejanitor`)

- **Default Human/Agent Mode (TOON):** Prints compact, scannable, line-oriented tables optimized for terminal readability and low LLM token cost.
- **Machine Contract Mode (`--json`):** Emits strict, additive, versioned JSON schemas:
  - `spacejanitor.storage.v1`
  - `spacejanitor.memory.v1`
  - `spacejanitor.blockers.v1`
  - `spacejanitor.orphans.v1`
  - `spacejanitor.mcp_audit.v1`
- **Diagnostics (`doctor [--json]`):** Verifies OS/arch platform capabilities, read-only probe permissions, git availability, and loaded plugin manifests without modifying state.
- **Exit Codes:**
  - `0`: Healthy (`OK`) or dry-run completed cleanly
  - `1`: Operational/runtime error or invalid confirmation flags
  - `2`: Threshold breach (`ALERT`/`CRITICAL`) when `--fail-on-alert` is specified for CI/cron hooks

### 2. Generic Plugin SDK (`packages/plugin-sdk`)

Third-party and operator-specific extensions register via a declarative `SpaceJanitorPlugin` manifest validated at load time:

```ts
export interface SpaceJanitorPlugin {
  id: string;                 // lowercase kebab-case identifier
  version: string;            // semver
  apiVersion: "1";
  capabilities: Array<"rule-pack" | "collector" | "widget" | "exporter">;
  rules?: StorageOrProcessRule[];
  widgets?: WidgetDescriptor[];
}
```

- **Rule Packs:** Add ecosystem cleanup targets (e.g., Xcode DerivedData, Rust Cargo cache, Docker/Podman buildx, Android AVDs) subject to `packages/core`'s immutable protected-path enforcement.
- **Collectors & Exporters:** External control planes or fleet dashboards consume SpaceJanitor JSON snapshots or attach custom exporters cleanly via plugin registration rather than forking core files.
- **Desktop Widgets:** Plugins contribute declarative widget cards (KPI, bar breakdown, blocker alert list, dry-run action trigger) rendered inside `apps/ui` without arbitrary script injection.

## Consequences

- **Positive:** One canonical telemetry engine powers coding agents, standalone desktop apps, and external monitoring portals without code duplication.
- **Negative / Mitigation:** Plugin schemas must stay backward-compatible within `apiVersion: "1"`; schema contract tests run in CI on every change.
