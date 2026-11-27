# PRD-002: True Memory Footprint & OS-Blocker Forensics

**Version:** 1.0  
**Status:** Partially implemented (collectors, MCP audit and scoped reaper on `main`; owner grouping and action IDs open)
**Related ADRs:** [ADR-002](../adr/ADR-002-cross-platform-os-telemetry-and-orphan-safety.md), [ADR-004](../adr/ADR-004-privacy-zero-leak-and-two-step-remediation.md)

---

## 1. Objective & Problem

Workstations running multiple IDEs, local LLMs, VMs, and background agent workers freeze before physical disk fills up—because compressed memory, swap saturation, kernel vnode/`inotify` exhaustion, runaway file-event daemons (`fseventsd`), and multiplied stdio MCP server trees lock OS access while plain `ps` RSS reports look deceptively low.

## 2. Target Personas

- **AI-Agent Power User:** Experiences frozen terminals, SSH timeouts, and swap thrash and needs immediate attribution of *who* holds memory (including compressed/swapped pages) and *why* the OS is blocking.
- **Fleet Maintainer:** Needs an automated audit (`mcp-audit`) that catches duplicate local stdio MCP server configurations and Spotlight/indexer misconfigurations before they replicate across laptops and servers.

## 3. Functional Requirements

| ID | Requirement | Priority |
|---|---|---|
| **FR-2.1** | Capture **true process memory footprint** per process and logical owner group (`RSS + Compressed/Swap`: macOS `top` `MEM` + `CMPRS`, Linux `/proc/<pid>/smaps_rollup` `Pss` + `SwapPss`, Windows `PrivateBytes` + `WorkingSet` + pagefile). | P0 |
| **FR-2.2** | Measure **kernel & VFS pressure blockers**: macOS `kern.num_vnodes`/`maxvnodes`, `kern.num_files`, `kern.maxprocperuid`, Mach port inflation, `fseventsd` footprint, state `U` uninterruptible waits; Linux `inotify` watches/instances, FD limits, `D`-state/zombies; Windows handle counts, NonPaged pool, pagefile saturation. | P0 |
| **FR-2.3** | Detect **orphan process storms**: `PPID=1` orphaned agent scripts/subshells past age threshold, zombie parents, and runaway file-tree walkers (`lsof +D`, unexcluded indexers). | P0 |
| **FR-2.4** | Implement **MCP Fleet Auditor (`mcp-audit`)**: group running MCP server processes by parent agent family (`codex`, `claude`, `cursor`, `opencode`, etc.), detect `npx` double-spawning (`npm exec` + `node`), and audit local agent config files for duplicate stdio entries when remote HTTP endpoints exist. | P0 |
| **FR-2.5** | Automatically redact credentials from all captured command strings (`--api-key`, bearer tokens, vendor key prefixes) before persisting JSON or displaying UI. | P0 |
| **FR-2.6** | Generate dry-run memory remediation actions (`m1-reap-orphan-scripts`, `m1-reap-orphan-mcps`, `m1-stop-vfs-lock-walkers`, `m2-restart-leaked-daemon`, `m2-sudo-restart-fseventsd`) requiring explicit `--execute --confirm-memory --item <id>`. | P0 |

## 4. Non-Functional Requirements

- **Collection Overhead:** Memory & OS-blocker probe completes in `< 3s` using `< 25 MiB` working memory so it runs safely even on a heavily swapped machine.
- **No accidental kills:** Orphan process reaping re-verifies `PPID == 1` at execution time before signalling `SIGTERM`.

## 5. Acceptance Criteria & Milestones

- **M1:** macOS and Linux collectors accurately compute logical owner footprint (`MEM`/`Pss+SwapPss`), detect saturated vnodes/`inotify`/orphan storms in fixtures, and pass secret-redaction tests.
- **M2:** Windows CIM/PowerShell collector + cross-OS MCP config auditor pass matrix tests on `windows-latest`, `ubuntu-latest`, and `macos-15`.

---

## Implementation Status (as of `main`, PR #15)

| Requirement | State | Where |
|---|---|---|
| FR-2.1 True per-process footprint | Implemented per process (top-N) on macOS, Linux, Windows collectors; **no owner-group aggregation** | `sj memory` (`memory.rs`) |
| FR-2.2 Kernel and VFS blockers | Implemented: macOS vnodes/`fseventsd`/U-state, Linux `file-nr`/`inotify`/`D`-state, Windows handles/pagefile. Linux systemd/podman blockers are in open [PR #18](https://github.com/adibirzu/spacejanitor/pull/18) | `sj blockers` (`blockers.rs`) |
| FR-2.3 Orphan process storms | Implemented for `PPID=1` MCP-lineage processes of the current user, with PID, command-hash and start-time re-verification; unix-only execute. Zombie parents / walker detection not implemented | `sj reap` (`reap.rs`) |
| FR-2.4 MCP fleet auditor | Implemented (configs plus live processes, duplicates, orphans) plus `sj llm-audit` for unused MCP servers, plugins, skills and idle sessions (read-only, no execute) | `mcp_audit.rs`, `llm_audit.rs` |
| FR-2.5 Redaction | Implemented as a closed vocabulary (`crates/sj-core/data/redact_catalog.json`), not pattern matching | `redact.rs` |
| FR-2.6 Remediation action IDs (`m1-reap-*`, `m2-*`) | Not implemented as named; reaping uses `sj reap` with its own digest and confirm phrase. Daemon restart / `sudo` actions are intentionally absent | `reap.rs` |

**Open items:** PR #18 (Linux extension, unmerged), owner-group aggregation, FR-2.6 action IDs.
