# SpaceJanitor Usage Guide

Complete reference for the Rust `sj` CLI, the `spacejanitor-axi` agent CLI, the desktop app and the protected-path gate. Everything here is available from source; **no installer or npm package is published yet** (see [INSTALL.md](./INSTALL.md)).

---

## 1. Rust `sj` CLI Reference

All commands are **read-only by default** and take `--json` for versioned machine output. Only `plan --execute`, `reap --execute` and `serve-stdio`'s `execute_*` methods mutate anything.

| Command | Flags | JSON schema |
|---|---|---|
| `sj doctor` | `[--json]` | `spacejanitor.doctor.v1` |
| `sj scan [path]` | `[--depth N] [--top N] [--same-fs] [--json]` | `spacejanitor.storage.v1` |
| `sj trash` | `[--path <dir>] [--json]` | `spacejanitor.trash.v1` |
| `sj orphans [path]` | `[--depth N] [--include-orphans] [--json]` (**scans nothing without `--include-orphans`**) | `spacejanitor.orphans.v1` |
| `sj memory` | `[--top N] [--json]` | `spacejanitor.memory.v1` |
| `sj blockers` | `[--json]` | `spacejanitor.blockers.v1` |
| `sj mcp-audit` | `[--config-dir <dir>] [--json]` | `spacejanitor.mcp_audit.v1` |
| `sj llm-audit` | `[--home <dir>] [--idle-hours N] [--unused-skill-days N] [--keep-plugin <id>] [--keep-skill <name>] [--keep-mcp <name>] [--json]` (dry-run only, no execute path) | `spacejanitor.llm_audit.v1` |
| `sj reap` | `[--min-age-mins N] [--dry-run] [--execute --confirm <phrase> --plan-sha256 <sha>] [--json]` | `spacejanitor.reap.v1` |
| `sj plan [path]` | `[--include-trash] [--include-orphans] [--trash-path <dir>] [--depth N] [--select <path>...] [--exact/--dynamic/--glob <rule>...] [--execute --confirm (--plan-sha256 <sha> --item <id> \| --selection-sha256 <sha> --select <path>...)] [--json]` | `spacejanitor.proposal.v1` (selection digest in `selection`) |
| `sj protect` | `[--exact/--dynamic/--glob <rule>...] [--descendants] [--max-entries N] [--json] -- <paths>...` | `spacejanitor.protect.v1` |
| `sj serve-stdio` | NDJSON JSON-RPC 2.0 on stdin/stdout | `spacejanitor.*.v1` |

Notes:
- `--execute` on `sj plan` and `sj reap` is **Unix-only (macOS, Linux)**. On Windows `sj` plans and refuses to execute.
- `sj reap` only targets processes **owned by you** and in an MCP lineage; foreign-UID, protected, too-young and non-MCP processes appear under `excluded` with a reason. The confirm phrase is printed by the dry-run (for example `REAP 4 ORPHAN PROCESS(ES)`).
- `sj llm-audit` has no `--execute`: it only reports planned actions.
- Output of `mcp-audit`, `llm-audit`, `reap`, `memory` and `serve-stdio` is built from a closed vocabulary; see [SECURITY.md](./SECURITY.md).

### Exit codes
- `0`: success (including a clean dry-run).
- `1`: operational error (I/O, git, serialization) or protected-path refusal.
- `2`: usage error or failed execution gate (for example `--execute` without `--confirm` or without the matching digest).

### Examples

```bash
sj doctor --json
sj scan ~/dev --depth 3 --top 20 --same-fs
sj trash --json
sj memory --top 15
sj blockers
sj mcp-audit --config-dir ~/.config
sj llm-audit --idle-hours 4

# Orphan proof is opt-in (it runs git inside the repositories it finds)
sj orphans ~/dev --depth 5 --include-orphans

# Is this path protected? (read-only)
sj protect --json --descendants -- ~/dev/some-dir

# Step 1: dry-run for exactly the items you pick; note selection.selection_sha256
sj plan ~/dev --include-trash --select ~/.Trash/old.zip --json

# Step 2: execute only that selection (macOS/Linux)
sj plan ~/dev --include-trash --select ~/.Trash/old.zip \
  --execute --confirm --selection-sha256 <selection_sha256>

# Single-item form from the full plan
sj plan ~/dev --include-trash --execute --confirm --plan-sha256 <sha256> --item <item_id>

# Orphaned MCP-lineage processes: plan first, then confirm with the printed phrase and digest
sj reap --min-age-mins 30
sj reap --min-age-mins 30 --execute --confirm "<phrase from dry-run>" --plan-sha256 <sha256>
```

---

## 2. `spacejanitor-axi` CLI Reference

Built for AI coding agents. Default output is compact **TOON**; `--json` emits `spacejanitor.*.v1` envelopes. Collectors call `sj <cmd> --json` (absolute path, bounded timeout) and fall back to read-only Node views (`source: node-fallback`).

```bash
node packages/cli/bin/spacejanitor.mjs <command> [flags]   # from a clone; not published to npm yet
```

| Command | Purpose |
|---|---|
| `summary` | Aggregated health: disk, memory, blockers, MCP (orphans reported as not scanned unless opted in) |
| `doctor` | Platform readiness and contract versions |
| `disk` | Capacity and top consumers (`--path <dir>`) |
| `memory` | True footprint (RSS + compressed/swap) |
| `blockers` | Kernel / VFS blockers |
| `orphans` | Worktree proofs; **off by default**, needs `--include-orphans` |
| `trash` | OS Trash / Recycle Bin |
| `mcp-audit` | MCP fan-out, duplicates, redacted secret risks |
| `remediate` | Dry-run plan preview only; `--execute` **fails closed** in the Node CLI (use the desktop app or `sj`) |
| `advise` | Optional local SLM advisor; off unless `--slm-url <loopback url>` |

Flags: `--json`, `--fail-on-alert` (exit `2` on `ALERT`/`CRITICAL`), `--path <dir>`, `--include-orphans`, `--execute` (guard only), `--confirm <phrase>`, `--plan-sha256 <sha>`, `-h/--help`, `-v/--version`.

> **Agent safety rule:** agents must never pass `--execute`. Present the dry-run plan to the human operator.

---

## 3. Desktop UI & OS Tray Mode

- **Tray badge:** worst active status across disk, true memory/swap and OS blockers (`OK`, `CHECK`, `ALERT`, `CRITICAL`).
- **Tabs:** Overview (gauges), Disk (top consumers, Trash, candidates), Memory (stacked Resident vs. Compressed/Swap), MCP (fleet counts and duplicates).
- **Orphans:** shown as "not scanned (disabled by default)" until you turn on the Disk-view toggle, which asks for native confirmation first.
- **Selection-bound confirmation:** only items accepted by `sj` are selectable; blocked items show the reason and cache directories are listed as "Not removable from the desktop". **Review Plan** shows targets, bytes and the selection digest; execution needs the typed `CONFIRM-XXXXXXXX` phrase within 5 minutes, single use.
- **Fail closed:** if `sj` is missing or fails, every destructive action is refused with a message; dashboards keep working.
- **Optional SLM drawer:** disabled by default; loopback endpoint only; suggestions are annotations and have no execution path.
- **Zero-idle renderer:** closing the window destroys the renderer while the tray stays.
- On Windows the app plans but cannot execute removals.

---

## 4. Protection Gate & FAQ

`sj` (Rust) is the only component that decides what is protected. It refuses to stage or delete:
- System roots (`/`, `/System`, `/usr`, `/bin`, `/sbin`, `/etc`, `/Library`, `/private/etc`, `/private/var/db`, `/Windows`, `C:\Windows`) and `$HOME`
- Credential & agent directories (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.claude`, `~/.config/gh`)
- Secret & key files (`.env`, `.env.*`, `*.env`, `*.private.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa`, `id_rsa.*`, `id_ed25519`, `id_ed25519.*`, `id_ecdsa`, `id_ecdsa.*`, `id_dsa`, `id_dsa.*` — custom suffix names without a dot such as `id_rsa_work` or `.envrc` are **not** matched by the default filename rule unless placed inside a protected directory such as `~/.ssh`)
- VM disk images (`*.vmdk`, `*.qcow2`, `*.vhdx`, `*.vdi`, `*.raw`, `*.img`)
- Any path containing a `.sj-stage-*` quarantine staging segment or dangling/unresolvable symlinks

### Troubleshooting FAQ

- **Why does `sj orphans` print "not scanned"?**
  Orphan scanning is off by default because it runs git inside repositories found on disk (issue #12). Pass `--include-orphans` for repositories you trust.
- **Why was my worktree marked `BLOCKED` in `sj orphans --include-orphans`?**
  `sj orphans` enforces all seven safety gates in `crates/sj-core/src/orphans.rs` across the repository and any nested sub-repositories: (1) clean working tree (`dirty_or_untracked`), (2) at least one configured remote (`no_remote`), (3) no git stashes (`has_stashes`), (4) no unpushed commits across all branches, (5) no ignored files present (`ignored_files_present`), (6) not in detached HEAD (`detached_head`), and (7) not an unborn HEAD (`unborn_head`). Note that ignored build artifacts such as `target/` or `node_modules/` trigger `BLOCKED [ignored_files_present]`—which is **not** cleared by committing or pushing—so clean or remove ignored artifacts (and commit/push changes or clear stashes) before pruning.
- **Why does `sj plan --execute` exit with code `2`?**
  Execution needs `--execute --confirm` plus either `--plan-sha256 <sha> --item <id>` or `--selection-sha256 <sha> --select <path>...` from a dry run of the same selection (and `--trash-path` cannot be combined with `--execute`). Execution is **Unix-only**: on Windows `crates/sj-core/src/safe_remove.rs` returns an `ExecutionGate` refusal (exit `2`).
- **Why did the Local SLM Advisor fall back to deterministic rules?**
  Either no loopback endpoint is configured (`--slm-url`), or free RAM is below `2.5 GiB`, triggering the memory-pressure self-guard so the advisor never worsens swap thrashing.
