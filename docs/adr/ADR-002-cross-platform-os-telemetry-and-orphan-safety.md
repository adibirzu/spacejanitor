# ADR-002: Cross-Platform OS Telemetry & Orphan Work Safety Model

- **Status:** Accepted
- **Date:** 2026-11-24
- **Drivers:** Accurate compressed/swapped memory attribution, VFS lock avoidance, zero accidental loss of uncommitted/unpushed developer work.

---

## Context

Disk cleaners and memory monitors routinely fail on developer machines for three reasons:
1. Reporting process `RSS` alone hides compressed and swapped memory on modern kernels.
2. Naive process-lock checks (such as `lsof +D` across large monorepos) trigger severe kernel vnode/VFS stalls.
3. Aggressive folder heuristics delete unpushed git branches, active worktrees, or nested sub-repositories.

## Decision

### 1. Platform Collector Matrix (`darwin`, `linux`, `win32` × `x86_64`, `arm64`)

Every collector emits normalized DTOs conforming to `spacejanitor.*.v1` contracts:

| Domain | macOS (`darwin`) | Linux (`linux`) | Windows (`win32`) |
|---|---|---|---|
| **True Memory Footprint** | `top -l 1` (`MEM` + `CMPRS` + `#PORTS`) + `vm_stat` + `sysctl vm.swapusage` | `/proc/<pid>/smaps_rollup` (`Pss` + `SwapPss`), `/proc/meminfo`, `swapon --show` | `Get-CimInstance Win32_Process` (`WorkingSetSize`, `PrivatePageCount`, `HandleCount`), OS pagefile, WSL2 `Vmmem` detection |
| **OS / VFS Blockers** | `kern.num_vnodes`/`maxvnodes`, `kern.num_files`/`maxfiles`, `kern.maxprocperuid`, `fseventsd` footprint, Mach port hogs, state `U` waits, Spotlight indexing checks | `fs.inotify.max_user_watches` & active watch pressure, `/proc/sys/fs/file-nr`, `D`-state & zombie counts, `systemd-journald` / cgroup OOM events | Open handle spikes, NonPaged/Paged kernel pool exhaustion, Windows Defender / Search indexer exclusions, pagefile saturation |
| **Storage & Trash** | `df -k`, fast inode-deduped tree scan, `tmutil listlocalsnapshots`, `~/.Trash` | `df -k` / `statvfs`, `$XDG_DATA_HOME/Trash`, `/var/log/journal`, Docker/Podman stores | PowerShell/Win32 volume free space, `$Recycle.Bin`, `%LOCALAPPDATA%\Temp`, WSL2 `.vhdx` virtual disks |
| **Orphan Work & Processes** | `git` status/remote/unpushed check + `PPID=1` orphan detection + MCP server parent tree grouping | `git` check + `/proc/<pid>/cwd` non-blocking open check + `PPID=1` & MCP grouping | `git` check + WMI parent PID tree + active CWD lock check via non-recursive handle inspection |

### 2. Non-Blocking Lock & Git Safety Invariants

- **Ban `lsof +D`:** SpaceJanitor **never** runs `lsof +D` recursive directory tree scans. Active directory usage is detected via O(N processes) CWD inspection (`/proc/<pid>/cwd` on Linux, `lsof -Fn -d cwd` without `+D` on macOS, process command/working-dir queries on Windows).
- **Recursive Git Safety Proof (opt-in, off by default, see issue #12):** the proof runs git inside repositories found on disk, so it is disabled unless explicitly enabled. A candidate worktree or directory flagged for pruning **must pass all checks** across the root and every nested `.git` repository up to depth 5:
  1. Valid git worktree (`git rev-parse --is-inside-work-tree`)
  2. Zero modified/untracked files (`git status --porcelain` is empty)
  3. At least one configured remote (`git remote` non-empty)
  4. Zero unpushed branch commits (`git rev-list --branches --not --remotes --count == 0`)
  5. Minimum idle age threshold met (`mtime` older than configured policy, e.g., `14d`)
  6. Not referenced by any active IDE/agent session or running process CWD.

### 3. Immutable Protected Denylist

`packages/core` enforces built-in protections that override all user rules and third-party plugins:
- System roots (`/`, `/System`, `/Windows`, `C:\Windows`, user home root)
- SSH, GPG, and cloud credential stores (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.config/gh`)
- User-declared `exact_paths`, `glob_patterns`, and runtime `dynamic_protected_paths`.

## Consequences

- **Positive:** Accurate memory attribution across all 3 OS families, zero VFS stalls induced by the scanner itself, and deterministic protection against deleting unpushed developer work.
- **Negative / Mitigation:** Gathering per-process `smaps_rollup` on Linux or `top` on macOS takes ~0.5–1.5s; SpaceJanitor caches snapshots briefly and runs scans asynchronously off the UI thread.
