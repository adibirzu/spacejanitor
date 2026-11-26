# SpaceJanitor Use Cases

Practical walkthroughs for the six core workstation failure modes SpaceJanitor is built to diagnose and resolve safely. Every workflow starts **read-only** and uses deterministic dry-run plans before any mutation occurs.

---

## 1. Runaway Disk Exhaustion

### Symptom
Your SSD hits 95%+ capacity unexpectedly during builds or parallel AI coding sessions, even though your active source repositories are small. Hidden culprits include stale `target/` or `node_modules` directories, abandoned git worktrees, multi-gigabyte OS Trash, and macOS APFS local Time Machine snapshots.

### Read-Only Commands

```bash
# Audit top directory consumers (bounded depth, same filesystem)
sj scan ~/dev --depth 3 --top 15 --same-fs

# Inspect OS Trash / Recycle Bin
sj trash

# Opt in: inspect git worktrees for safe-to-prune orphans.
# This runs git inside the repositories it finds (experimental, issue #12); use only on repos you trust.
sj orphans ~/dev --depth 5 --include-orphans
```

### Sample Output

```text
scan: /Users/<you>/dev (84210944000 bytes, 148230 files, status=Ok)
   28410220544  /Users/<you>/dev/project-alpha/target (dir)
   14205110272  /Users/<you>/dev/worktrees/feature-old (dir)
trash: /Users/<you>/.Trash (exists=true, items=42, total=9812031488B, reclaimable=9812031488B, protected=0)
orphans: /Users/<you>/dev (scanned=18, safe=1, blocked=2)   # only appears with --include-orphans; otherwise "not scanned (disabled by default)"
  SAFE    /Users/<you>/dev/worktrees/feature-old (48234496B)   # clean, pushed, attached branch with no ignored artifacts
  BLOCKED /Users/<you>/dev/worktrees/wip-branch [dirty_or_untracked]
  BLOCKED /Users/<you>/dev/scratch-notes [no_remote]
```

### How SpaceJanitor Solves It Safely
- **Recursive Git Proof (opt-in):** `sj orphans --include-orphans` enforces all seven safety gates in `crates/sj-core/src/orphans.rs` across the repository and any nested sub-repositories: (1) clean working tree (`dirty_or_untracked`), (2) configured remote (`no_remote`), (3) no stashes (`has_stashes`), (4) no unpushed commits across all branches, (5) no ignored files present (`ignored_files_present`), (6) not detached HEAD (`detached_head`), and (7) not unborn HEAD (`unborn_head`). Ignored build artifacts such as `target/` or `node_modules/` cause `BLOCKED [ignored_files_present]` (not cleared by committing or pushing), so only a clean, pushed, attached branch checkout with no ignored artifacts is marked `SAFE`.
- **Protected Path Enforcement:** Even if Trash or a scan root contains `.ssh`, `.env`, or VM images (`*.qcow2`, `*.vmdk`), `sj-core` excludes them deterministically. Add your own rules with `--exact`, `--dynamic` and `--glob` (they can only add protection).
- **APFS snapshots:** snapshot-held space is not yet reported; this is a planned enhancement, not shipped.

### Verification

```bash
# 1. Dry-run for exactly the items you pick (zero mutations); note selection.selection_sha256
#    (add --include-orphans only if you opted in to orphan scanning)
sj plan ~/dev --include-trash --select ~/.Trash/old.zip --json

# 2. Execute only that selection (macOS/Linux); sj refuses if the digest no longer matches
sj plan ~/dev --include-trash --select ~/.Trash/old.zip \
  --execute --confirm --selection-sha256 <selection_sha256>
```

---

## 2. Hidden Memory & Swap Thrashing

### Symptom
macOS, Linux, or Windows becomes sluggish, UI animations stutter, and terminals lag—yet `ps` or Task Manager RSS columns only account for a fraction of physical RAM. Modern kernels compress inactive pages in RAM and spill pages into encrypted swap/pagefiles.

### Read-Only Command

```bash
sj memory --top 15
```

### Sample Output

```text
memory (macos): total=34359738368B used=29000000000B compressed=12000000000B swap_used=15000000000B pressure=critical
  pid=4101   ppid=1      footprint=6200000000B  <command>
  pid=3320   ppid=1      footprint=3100000000B  <command>
```

(Illustrative values; pass `--json` for the full `spacejanitor.memory.v1` report including per-process resident, compressed and swap bytes.)

### How SpaceJanitor Solves It Safely
- **Cross-Platform True Footprint:**
  - **macOS:** Combines `top -l 1` (`MEM` + `CMPRS` + `#PORTS`), `vm_stat`, and `sysctl vm.swapusage`.
  - **Linux:** Reads `/proc/<pid>/smaps_rollup` (`Pss` + `SwapPss`), `/proc/meminfo`, and `swapon --show`.
  - **Windows:** Queries `Win32_Process` (`WorkingSetSize`, `PrivatePageCount`, `HandleCount`), OS pagefile, and WSL2 `Vmmem`.
- **Per-process true footprint:** the top-N processes are ranked by `Resident + Compressed + Swap`, not by RSS alone, so a process hiding in compressed memory still shows up. Process names pass through the redaction catalog.

### Verification
Re-run `sj memory --top 10 --json` after closing or reaping the heavy processes and confirm `compressed` and `swap` drop below alert thresholds.

---

## 3. Kernel & VFS OS Blockers

### Symptom
CPU is mostly idle and disk has free space, but `git status`, terminal spawns, or SSH logins freeze for seconds or minutes. Common causes are macOS vnode table exhaustion (`kern.num_vnodes` near `maxvnodes`), `fseventsd` backlog storms, Linux `inotify` watch exhaustion, `D`/`U`-state uninterruptible I/O waits, or recursive `lsof +D` walkers.

### Read-Only Command

```bash
sj blockers
```

### Sample Output

```text
blockers (macos): status=CRITICAL count=2
  [CRITICAL] macos-vnode-pressure: Kernel vnode table saturation (263168/263168, 100.0%)
  [WARN] macos-uninterruptible-waits: Uninterruptible (U-state) process detected (2 process(es) in uninterruptible wait)
```

### How SpaceJanitor Solves It Safely
- **Never Runs `lsof +D`:** SpaceJanitor explicitly bans recursive `lsof +D` tree walks in its own collectors (`O(N processes)` `/proc/<pid>/cwd` or non-recursive `lsof -Fn -d cwd` instead) so diagnostics never worsen a VFS lock.
- **Actionable Root-Cause Surfacing:** Pinpoints whether the freeze is caused by `inotify` watch exhaustion, macOS vnode/Mach port saturation, Windows NonPaged pool/handle spikes, or a runaway file-tree indexer.

### Verification
Run `sj blockers --json` after stopping a runaway watcher or raising `fs.inotify.max_user_watches` and confirm status returns to `OK`.

---

## 4. AI Agent MCP Server Sprawl & Inline Secret Leaks

### Symptom
Running multiple AI editors and CLI agents spawns dozens or hundreds of duplicate stdio MCP servers (`npx` -> `npm exec` -> `node`, or `uvx` -> `python`). Worse, some MCP configs pass API keys or bearer tokens as CLI flags (`--api-key=...`, `--token=...`), exposing them in `ps` output.

### Read-Only Command

```bash
sj mcp-audit --config-dir ~/.config
```

### Sample Output

```text
mcp-audit: files=4 servers=40 running=45 duplicates=24 orphans=9 secret_findings=3
```

Add `--json` for the `spacejanitor.mcp_audit.v1` report: per-config servers (user-chosen labels shown only when they pass the label rules), duplicate groups, orphaned processes and `secret_findings` that name the *kind* of signal, never the value.

### How SpaceJanitor Solves It Safely
- **Config-to-process matching:** live MCP processes are matched back to the configured server entries so duplicates, orphans (`PPID=1`) and unused servers stand out; `npx` double-spawning shows up as duplicates.
- **Closed-vocabulary output:** commands, packages, flag names and URLs are printed only from a fixed catalog or reduced to a hash; flag values are always `<REDACTED>` and URL userinfo, paths and queries are never shown. Raw secrets never appear in `sj` output (see [SECURITY.md](./SECURITY.md)). `sj llm-audit` extends the same audit to unused plugins, skills, MCP servers and idle sessions, read-only.

### Verification
Consolidate duplicate stdio entries or move shared servers to a single daemon/HTTP endpoint, then re-run `sj mcp-audit --json` to confirm duplicate counts drop to `0`.

---

## 5. Safe `PPID=1` Orphan Process Reaping

### Symptom
Background subagents, test runners, or MCP child processes detach from terminated parent sessions and linger with `PPID=1`, holding gigabytes of RAM or open file descriptors. Blindly running `pkill -f node` risks killing active editors, dev servers, or other agents.

### Read-Only & Gated Commands

```bash
# Step 1: Dry-run discovery (default; zero signals sent). Prints the confirm phrase and plan SHA-256.
sj reap --min-age-mins 30 --dry-run

# Step 2: Execute ONLY with that exact confirmation phrase and plan SHA-256 (macOS/Linux)
sj reap --min-age-mins 30 --execute \
  --confirm "<phrase printed by the dry-run>" \
  --plan-sha256 <sha256>
```

### How SpaceJanitor Solves It Safely
- **No Wildcard Kills:** SpaceJanitor never uses `pkill` or `killall`. Only processes owned by you and in an MCP lineage are eligible; foreign-UID, protected and too-young processes are listed as excluded with a reason.
- **TOCTOU Re-Verification:** At `--execute` time, `sj-core` re-verifies each target's exact **PID**, **PPID == 1**, **command hash**, and **process start time** against the SHA-256-hashed dry-run plan before sending `SIGTERM`. If a PID was recycled or no longer matches, execution aborts safely.

### Verification
Re-run `sj reap --min-age-mins 30 --dry-run --json` and confirm the reaped PIDs are no longer present and active sessions remain untouched.

---

## 6. Agent-First Automation (AXI) & Optional Local SLM Advisor

### Symptom
AI coding agents waste thousands of context tokens parsing verbose `du`/`top`/`ps` output before spawning parallel worktrees, while human operators sometimes encounter unfamiliar cache directories and want a plain-English explanation without sending workstation paths to a cloud LLM.

### Read-Only Commands

`spacejanitor-axi` is not published to npm yet; run it from a clone (see [INSTALL.md](./INSTALL.md)).

```bash
node packages/cli/bin/spacejanitor.mjs summary
node packages/cli/bin/spacejanitor.mjs memory --json
node packages/cli/bin/spacejanitor.mjs doctor --json

# Optional local SLM advisor (loopback only, off unless you pass an endpoint)
node packages/cli/bin/spacejanitor.mjs advise --slm-url http://127.0.0.1:11434/v1/chat/completions
```

### How SpaceJanitor Solves It Safely
- **AXI Contract:** `spacejanitor-axi` defaults to compact line-oriented TOON tables and supports `--json` for `spacejanitor.*.v1` schemas. Agent skills ([skills/spacejanitor-axi/SKILL.md](../skills/spacejanitor-axi/SKILL.md)) enforce never passing `--execute` automatically.
- **Zero-Cloud, Zero-Idle SLM:** When enabled, the optional Local SLM Advisor (`0.5B`–`1.5B` GGUF or local `127.0.0.1` Ollama) runs only on explicit request, receives only redacted metadata, checks that free RAM is `>= 2.5 GiB`, and has **zero execution capability**—every suggestion is re-validated by `sj-core` and requires standard two-step human confirmation.

### Verification
Run `node packages/cli/bin/spacejanitor.mjs doctor --json` to confirm `safetyMode: "dry-run-default"` and verify local contract readiness.
