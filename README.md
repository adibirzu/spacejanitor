# SpaceJanitor

**Cross-platform workstation janitor for storage, orphan work, trash, true memory footprint, and OS-blocker forensics.**

Built for modern multi-agent engineering workstations across **macOS**, **Linux**, and **Windows** (`x86_64` and `ARM64`), packaged as a zero-telemetry CLI, an AI-agent AXI skill, a TypeScript Plugin SDK, and a lightweight cross-platform desktop app.

---

## Why SpaceJanitor Exists

Traditional disk cleaners clear browser caches. Developer disk cleaners delete `node_modules`. Neither protects against the failure modes that freeze AI-heavy engineering workstations:

1. **Orphan work & unpushed git worktrees** left behind by background coding agents, CI runners, and parallel IDE sessions.
2. **Hidden memory & swap thrash** where plain `ps` RSS hides tens of gigabytes of compressed RAM and encrypted swap.
3. **Kernel & VFS OS blockers** such as saturated macOS vnode tables, runaway `fseventsd` queues, Linux `inotify` exhaustion, recursive `lsof +D` tree locks, and orphaned `PPID=1` agent scripts.
4. **MCP server multiplication** where globally configured stdio MCP servers (`npx` / Node / Python) multiply across dozens of concurrent agent sessions.
5. **OS Trash & Recycle Bin bloat** sitting silently beside multi-gigabyte container and VM images.

SpaceJanitor **never deletes a file or signals a process by default**. Every sweep produces a deterministic dry-run plan and requires explicit, two-step confirmation gated behind an immutable protected-path denylist.

---

## Architecture Overview

```mermaid
flowchart LR
  CLI["packages/cli (spacejanitor-axi)\nTOON + --json CLI & Agent Skill"] --> Core["packages/core\nProtected Denylist, Redaction, Git Safety"]
  SDK["packages/plugin-sdk\nCustom Rules, Collectors, Widgets"] --> Core
  UI["apps/ui (React + TypeScript)\nWidgets, Dry-Run Diff, 2-Step Confirm"] --> Core
  Desktop["apps/desktop (ADR-001 Host)\nmacOS / Linux / Windows (x64 & ARM64)"] --> UI
  Desktop --> Core
```

---

## Safety Invariants

- **Dry-run by default:** Scans and reports never mutate files, git repositories, or processes.
- **Two-step confirmation:** Execution requires a single-use token bound to the exact dry-run plan plus explicit target selection.
- **Git safety proof:** Worktree and repository cleanup rules refuse any tree with uncommitted changes, missing remotes, or unpushed commits—including nested sub-repositories.
- **Immutable Protected Denylist:** Core protections (`.ssh`, `.gnupg`, keystores, active IDE sessions, user-configured protected paths) override all built-in and third-party plugin rules.
- **Zero telemetry & automatic redaction:** All telemetry stays local; CLI arguments matching credential shapes are redacted before leaving any collector.

---

## Documentation

### Research & Architecture Decisions
- [001 — Competitive Landscape & Desktop Runtime Research](./docs/research/001-landscape-and-runtime-research.md)
- [ADR-001 — Desktop Runtime Selection (Tauri v2 vs Electron)](./docs/adr/ADR-001-desktop-runtime-tauri-vs-electron.md)
- [ADR-002 — Cross-Platform OS Telemetry & Orphan Safety](./docs/adr/ADR-002-cross-platform-os-telemetry-and-orphan-safety.md)
- [ADR-003 — AXI CLI Output & Plugin SDK Contract](./docs/adr/ADR-003-axi-cli-and-plugin-contract.md)
- [ADR-004 — Zero-Leak Privacy & Two-Step Remediation Gate](./docs/adr/ADR-004-privacy-zero-leak-and-two-step-remediation.md)

### Product Requirements Documents (PRDs)
- [PRD-001 — Core Storage, Trash & Orphan Work Engine](./docs/prd/PRD-001-core-storage-and-orphan-work-engine.md)
- [PRD-002 — True Memory Footprint & OS-Blocker Forensics](./docs/prd/PRD-002-memory-footprint-and-os-blocker-forensics.md)
- [PRD-003 — Cross-Platform Desktop App (macOS, Linux, Windows x64/ARM64)](./docs/prd/PRD-003-cross-platform-desktop-app.md)
- [PRD-004 — AXI CLI (`spacejanitor-axi`) & Plugin Ecosystem](./docs/prd/PRD-004-axi-cli-and-plugin-ecosystem.md)

---

## Quick Start (Scaffold)

Requirements: Node.js `>=20`.

```bash
npm test
npm run hygiene
node packages/cli/bin/spacejanitor.mjs doctor --json
```

---

## License

[MIT](./LICENSE)
