---
name: spacejanitor-axi
description: >
  Cross-platform workstation janitor AXI CLI for auditing storage, OS Trash,
  orphan git worktrees, true memory footprint (RSS + compressed/swapped),
  kernel/VFS OS blockers, and MCP server process multiplication. Dry-run by default.
---

# spacejanitor-axi

Read-only workstation diagnostics and dry-run remediation planner for macOS, Linux, and Windows (`x86_64` and `ARM64`).

## When to Use

- Before spawning parallel AI coding agents or heavy local builds, check whether disk space, compressed memory, kernel vnodes / `inotify` watches, or MCP process counts are near saturation.
- When diagnosing why terminals, SSH, or UI are stalling under swap or VFS lock pressure.
- When locating orphaned clean/pushed git worktrees, OS Trash bloat, or orphaned `PPID=1` background scripts.

## Commands

Default output is compact **TOON** (token-efficient line format). Pass `--json` for versioned `spacejanitor.*.v1` JSON envelopes.

```sh
npx spacejanitor-axi summary [--json]     # aggregated health across disk, memory, blockers, orphans, mcp
npx spacejanitor-axi doctor [--json]      # verify platform, Node runtime, and schema versions
npx spacejanitor-axi disk [--json]        # storage capacity, thresholds, and top consumers
npx spacejanitor-axi memory [--json]      # true footprint (RSS + compressed/swap) by process
npx spacejanitor-axi blockers [--json]    # kernel vnodes / inotify / handles / VFS lock blockers
npx spacejanitor-axi mcp-audit [--json]   # MCP process fan-out, duplicates & redacted secret risks
npx spacejanitor-axi orphans [--json]     # git worktrees (clean + pushed proof) & stale build trees
npx spacejanitor-axi trash [--json]       # OS Trash / Recycle Bin audit
npx spacejanitor-axi remediate [--json]   # dry-run SHA-256 plan preview only (zero deletions)
```

## Exit Codes

- `0`: Healthy (`OK`/`CHECK`) or dry-run completed cleanly.
- `1`: Operational/runtime error, missing/invalid remediation confirmation flags, or `--execute` in read-only Node AXI CLI (`not_implemented`).
- `2`: Threshold breach (`ALERT`/`CRITICAL`) when `--fail-on-alert` is passed.

## Engine Notes (`sj-core` vs `node-fallback`)

- When the Rust `sj` binary is present, `doctor`, `disk` (`spacejanitor.storage.v1`), `trash` (`spacejanitor.trash.v1`), and `orphans` (`spacejanitor.orphans.v1`) are backed by `sj-core` and normalized to the shared v1 contract.
- When `sj` is absent, `@spacejanitor/core` provides `node-fallback` telemetry (`spacejanitor.disk.v1`, `memory.v1`, `blockers.v1`, `mcp_audit.v1`, `orphans.v1`, `trash.v1`, `summary.v1`).

## Safety Rules for Agents

- **Never pass `--execute` automatically.** `spacejanitor-axi remediate` is a dry-run SHA-256 planner only (`--execute` fails closed in Node fallback with `executed: false` and exit `1`).
- **Respect protected paths and git proofs.** Never suggest deleting dirty or unpushed git repositories or credential directories (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`).
- **Zero raw secrets.** All process arguments and MCP configs are redacted before output.
