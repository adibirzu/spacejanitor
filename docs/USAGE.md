# SpaceJanitor Usage Guide

Complete reference for the Rust `sj` CLI, the `spacejanitor-axi` agent CLI, the Desktop Tray UI, and the Protected Never-Touch Denylist.

---

## 1. Rust `sj` CLI Reference

All `sj` commands are **read-only by default** and support `--json` for machine-readable output.

| Command | Flags | JSON Schema | Status |
|---|---|---|---|
| `sj doctor` | `[--json]` | `spacejanitor.doctor.v1` | M1 (shipped) |
| `sj scan [path]` | `[--depth N] [--top N] [--same-fs] [--json]` | `spacejanitor.storage.v1` / `spacejanitor.disk.v1` | M1 (shipped) |
| `sj trash` | `[--path <dir>] [--json]` | `spacejanitor.trash.v1` | M1 (shipped) |
| `sj orphans [path]` | `[--depth N] [--json]` | `spacejanitor.orphans.v1` | M1 (shipped) |
| `sj plan [path]` | `[--include-trash] [--include-orphans] [--trash-path <dir>] [--depth N] [--execute --confirm --plan-sha256 <sha> --item <id>] [--json]` | `spacejanitor.proposal.v1` / `spacejanitor.plan.v1` | M1 (shipped) |
| `sj memory` | `[--top N] [--json]` | `spacejanitor.memory.v1` | M2 |
| `sj blockers` | `[--json]` | `spacejanitor.blockers.v1` | M2 |
| `sj mcp-audit` | `[--config-dir <path>...] [--json]` | `spacejanitor.mcp_audit.v1` | M2 |
| `sj reap` | `[--min-age-mins 30] [--dry-run] [--execute --confirm <phrase> --plan-sha256 <sha>] [--json]` | `spacejanitor.reap.v1` | M3 |
| `sj serve-stdio` | *(NDJSON JSON-RPC 2.0 on stdin/stdout)* | `spacejanitor.*.v1` | M4 |

### Exit Codes

- `0`: Success (healthy or dry-run completed cleanly).
- `1`: Operational/runtime error (I/O error, git error, JSON serialization error, or protected path refusal).
- `2`: Usage or invalid execution gate error (e.g., `--execute` without `--confirm` / matching `--plan-sha256` / `--item`), or threshold breach when `--fail-on-alert` is set.

### Examples

```bash
# Verify Rust core, git availability, and home directory resolution
sj doctor --json

# Scan ~/dev up to depth 3, staying on the same filesystem
sj scan ~/dev --depth 3 --top 20 --same-fs

# Inspect OS Trash / Recycle Bin without deleting anything
sj trash --json

# Discover clean + pushed vs dirty/unpushed git worktrees
sj orphans ~/dev --depth 5

# Build a deterministic dry-run remediation plan
sj plan ~/dev --include-trash --include-orphans --json

# Execute ONE allowlisted item from the plan using its exact SHA-256
sj plan ~/dev --include-trash --include-orphans \
  --execute --confirm --plan-sha256 <sha256> --item <item_id>
```

---

## 2. `spacejanitor-axi` CLI Reference

`spacejanitor-axi` is designed for AI coding agents and terminal operators. It prints compact **TOON** tables by default to minimize token usage, and emits `spacejanitor.*.v1` JSON with `--json`.

```bash
npx spacejanitor-axi <command> [--json]
```

Supported subcommands:
- `summary` — Combined health overview across storage, memory, blockers, and orphans
- `disk` — Storage capacity and tiered cleanup candidates
- `memory` — True memory footprint (`RSS + Compressed + Swap`) by owner group
- `blockers` — Kernel vnode, `inotify`, handle, and VFS lock diagnostics
- `mcp-audit` — MCP server fan-out and redacted secret audit
- `orphans` — Clean/pushed vs dirty git worktrees
- `remediate` — Dry-run preview (never mutates without explicit confirmation flags)
- `doctor` — Platform readiness and contract versions

> **Agent Safety Rule:** Agents must **never** pass `--execute` automatically. Use read-only diagnostics or dry-run previews and present the plan to the human operator.

---

## 3. Desktop UI & OS Tray Mode *(M5 / M7)*

- **Menu Bar / System Tray Badge:** Displays the worst active status across Disk, True Memory/Swap, and OS Blockers (`OK`, `CHECK`, `ALERT`, `CRITICAL`).
- **Tabs & Threshold Gauges:**
  - **Overview:** Host health summary and active threshold gauges.
  - **Storage & Orphans:** Top directories, OS Trash, and git worktree safety proofs (showing exact `BLOCKED` reasons for dirty or unpushed trees).
  - **Memory & Blockers:** Stacked Resident vs. Compressed/Swap bars by owner group alongside kernel vnode/`inotify`/handle gauges.
  - **MCP Fleet:** Running MCP server counts per parent agent and duplicate stdio warnings.
- **2-Step SHA-256 Confirmation Modal:** Clicking **Review Plan** displays exact targets, reclaimable bytes, and the plan's SHA-256 digest. Execution requires typing the confirmation phrase and submitting a single-use, 5-minute confirmation token.
- **Optional Local SLM Advisor:** Disabled by default. Enable in Settings with a loopback (`127.0.0.1`) Ollama or `llama-server` endpoint, then click **Analyze Plan** for on-demand plain-English explanations.
- **Zero-Idle Renderer:** Closing the window destroys the Chromium renderer process while keeping the lightweight tray indicator active.

---

## 4. Protected Never-Touch Denylist & FAQ

SpaceJanitor refuses to stage or delete:
- System roots (`/`, `/System`, `/usr`, `/bin`, `/sbin`, `/etc`, `/Library`, `/private/etc`, `/private/var/db`, `/Windows`, `C:\Windows`) and `$HOME`
- Credential & agent directories (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.claude`, `~/.config/gh`)
- Secret & key files (`.env`, `.env.*`, `*.private.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `id_dsa*`)
- VM disk images (`*.vmdk`, `*.qcow2`, `*.vhdx`, `*.vdi`, `*.raw`, `*.img`)
- Any path containing a `.sj-stage-*` quarantine staging segment or dangling/unresolvable symlinks

### Troubleshooting FAQ

- **Why was my worktree marked `BLOCKED` in `sj orphans`?**
  `sj orphans` requires a clean working tree (`git status --porcelain` empty), at least one configured remote, and zero unpushed commits across all branches—including nested sub-repositories. Commit/push or stash your work, or inspect it manually.
- **Why does `sj plan --execute` exit with code `2`?**
  Execution requires all three gates: `--execute`, `--confirm`, `--plan-sha256 <exact_sha>`, and `--item <exact_id>` (and `--trash-path` cannot be combined with `--execute`).
- **Why did the Local SLM Advisor fall back to deterministic rules?**
  Either no loopback endpoint is configured, or available system RAM is below `2.5 GiB`, triggering the memory-pressure self-guard so the advisor never worsens swap thrashing.
