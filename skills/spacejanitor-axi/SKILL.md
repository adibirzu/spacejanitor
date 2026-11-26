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
- When locating OS Trash bloat or orphaned `PPID=1` background scripts. (Orphan git worktree scanning is experimental and **off by default**: it runs git inside repositories found on disk; pass `--include-orphans` only for repositories you trust.)

## Commands

Run from a clone (the package is not published to npm yet). Default output is compact **TOON** (token-efficient line format). Pass `--json` for versioned `spacejanitor.*.v1` JSON envelopes.

```sh
node packages/cli/bin/spacejanitor.mjs summary [--json]     # aggregated health across disk, memory, blockers, mcp (orphans: not scanned unless --include-orphans)
node packages/cli/bin/spacejanitor.mjs doctor [--json]      # verify platform, Node runtime, and schema versions
node packages/cli/bin/spacejanitor.mjs disk [--json]        # storage capacity, thresholds, and top consumers
node packages/cli/bin/spacejanitor.mjs memory [--json]      # true footprint (RSS + compressed/swap) by process
node packages/cli/bin/spacejanitor.mjs blockers [--json]    # kernel vnodes / inotify / handles / VFS lock blockers
node packages/cli/bin/spacejanitor.mjs mcp-audit [--json]   # MCP process fan-out, duplicates & redacted secret risks
node packages/cli/bin/spacejanitor.mjs orphans --include-orphans [--json]  # EXPERIMENTAL, opt-in: runs git inside repos found on disk; without the flag reports "not scanned"
node packages/cli/bin/spacejanitor.mjs trash [--json]       # OS Trash / Recycle Bin audit
node packages/cli/bin/spacejanitor.mjs remediate [--json]   # dry-run SHA-256 plan preview only (zero deletions)
node packages/cli/bin/spacejanitor.mjs advise --slm-url <loopback url>  # optional local SLM advisor; off without a loopback endpoint
```

## Exit Codes

- `0`: Healthy (`OK`/`CHECK`) or dry-run completed cleanly.
- `1`: Operational/runtime error, or `--execute` in the read-only Node AXI CLI (`not_implemented`).
- `2`: Threshold breach (`ALERT`/`CRITICAL`) when `--fail-on-alert` is passed.

## Engine Notes (`sj-core` vs `node-fallback`)

- When the Rust `sj` binary is present, `doctor`, `disk`, `trash`, `orphans`, `memory`, `blockers` and `mcp-audit` are backed by `sj-core` and normalized to the shared v1 contract.
- When `sj` is absent, `@spacejanitor/core` provides `node-fallback` telemetry (`spacejanitor.disk.v1`, `memory.v1`, `blockers.v1`, `mcp_audit.v1`, `orphans.v1`, `trash.v1`, `summary.v1`).

## Safety Rules for Agents

- **Never pass `--execute` automatically.** `spacejanitor-axi remediate` is a dry-run SHA-256 planner only (`--execute` fails closed in Node fallback with `executed: false` and exit `1`).
- **Respect protected paths and git proofs.** Never suggest deleting dirty or unpushed git repositories or credential directories (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`).
- **Zero raw secrets.** All process arguments and MCP configs are redacted before output.
