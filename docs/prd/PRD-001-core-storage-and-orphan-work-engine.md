# PRD-001: Core Storage, Trash & Orphan Work Engine

**Version:** 1.0  
**Status:** Draft  
**Related ADRs:** [ADR-002](../adr/ADR-002-cross-platform-os-telemetry-and-orphan-safety.md), [ADR-004](../adr/ADR-004-privacy-zero-leak-and-two-step-remediation.md)

---

## 1. Objective & Problem

Developers running containers, multi-language toolchains, and AI coding agents accumulate orphaned git worktrees, unpushed scratch clones, large OS Trash / Recycle Bin folders, and bloated package/browser caches. Existing tools either delete blindly or ignore orphan worktree safety.

## 2. Target Personas

- **Solo Polyglot Engineer:** Wants safe one-command cache, Trash, and build artifact pruning (`npm`, `pnpm`, `uv`, `cargo`, Gradle, Playwright, Homebrew/apt/winget caches) without deleting active repos.
- **Multi-Agent Workstation Operator:** Runs 10–100+ parallel git worktrees and needs provable detection of abandoned worktrees vs. dirty/unpushed branches.

## 3. Functional Requirements

| ID | Requirement | Priority |
|---|---|---|
| **FR-1.1** | Measure filesystem capacity and mount usage across macOS APFS (`/System/Volumes/Data` + local snapshots), Linux (`/` and configured mounts), and Windows drive letters (`C:\`, etc.). | P0 |
| **FR-1.2** | Scan OS Trash / Recycle Bin (`~/.Trash` on macOS, `$XDG_DATA_HOME/Trash` on Linux, `$Recycle.Bin` on Windows) and report reclaimable size and age distribution. | P0 |
| **FR-1.3** | Classify storage targets into **Tier 1** (safe rebuildable caches), **Tier 2** (review-gated heavy artifacts, aged agent logs, idle clean worktrees), and **Keep / Protected** (never deleted). | P0 |
| **FR-1.4** | Inspect orphan git worktrees and pool checkouts using recursive `.git` tree proof (clean working tree + configured remote + zero unpushed branch commits + minimum idle age + zero active process CWDs, **never** using `lsof +D`). The orphan proof is **opt-in and off by default** (it runs git inside repositories found on disk; see issue #12). | P0 |
| **FR-1.5** | Flag `manual_review_only` bloat (VM images, Docker/Podman stores, Downloads, aged backups) without generating destructive commands for them. | P1 |
| **FR-1.6** | Detect newly appearing unclassified consumers above configurable size thresholds (`200 MiB` general, `100 MiB` cache roots) and track deltas between runs. | P1 |
| **FR-1.7** | Emit deterministic dry-run remediation plans and cross-platform preview scripts (`bash` / PowerShell) guarded by `isProtectedPath()` and two-step confirmation gates. | P0 |

## 4. Non-Functional Requirements

- **Zero accidental data loss:** Protected-path rules override every cleanup rule; dirty/unpushed git trees are always excluded and logged under `blocked_exclusions`.
- **Latency:** Full root + Tier 1/2 scan completes in `< 15s` on typical developer SSDs using bounded concurrency and pruned traversal (`.git`, `node_modules`, `target`, `.venv`).

## 5. Acceptance Criteria & Milestones

- **M1:** Core path protection, git clean/pushed validator, Trash scanner, and Tier 1/2 classification pass cross-platform unit tests on `ubuntu-latest`, `macos-15`, and `windows-latest`.
- **M2:** Dry-run script generator emits syntactically valid, idempotent cleanup plans with zero modifications during dry-run verification.
