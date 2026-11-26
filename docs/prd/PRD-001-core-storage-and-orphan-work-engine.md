# PRD-001: Core Storage, Trash & Orphan Work Engine

**Version:** 1.0  
**Status:** Partially implemented (core engine on `main`; Tier/idle-age/delta/script-generation items open)
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

---

## Implementation Status (as of `main`, after PRs #8, #10, #11, #15)

| Requirement | State | Where |
|---|---|---|
| FR-1.1 Capacity and mounts | Implemented | `sj scan` (`crates/sj-core/src/scan.rs`, `--same-fs`); capacity via AXI `disk` (`packages/core/src/telemetry.mjs`) |
| FR-1.2 Trash / Recycle Bin | Implemented (size and item list; age distribution not reported) | `sj trash` (`trash.rs`) |
| FR-1.3 Tiering | Partial: Trash items are `tier1`, verified orphan worktrees `tier2`; protected items excluded. No Tier-1 cache classifier in `sj`; caches are listed read-only in the desktop UI | `plan.rs` |
| FR-1.4 Orphan proof | Implemented, **opt-in and off by default**: clean tree, remote, stashes, unpushed commits, ignored files, detached/unborn HEAD, nested repos; never `lsof +D`. **Not implemented:** minimum idle age and active-process-CWD check | `orphans.rs`; hardening in [#12](https://github.com/adibirzu/spacejanitor/issues/12) |
| FR-1.5 `manual_review_only` bloat | Not implemented | n/a |
| FR-1.6 New-consumer detection and deltas | Not implemented | n/a |
| FR-1.7 Dry-run plans and preview scripts | Partial: deterministic plans with SHA-256 and selection digests are implemented; **bash/PowerShell preview scripts are not** | `plan.rs`, `sj plan --select` |
| NFR zero data loss | Implemented: Rust protection gate, no-follow handle-anchored removal, execute-time re-checks; **Unix-only** removal (Windows plans only) | `protect.rs`, `safe_remove.rs` |
| NFR latency `< 15 s` | Not benchmarked | n/a |

**Open items:** [#12](https://github.com/adibirzu/spacejanitor/issues/12) (git-proof hardening B35-B37; orphan scanning stays off by default until fixed), Windows removal, items marked "Not implemented" above, and the M7 release matrix (no tag yet, no published artifacts). Linux additions are in open [PR #18](https://github.com/adibirzu/spacejanitor/pull/18).
