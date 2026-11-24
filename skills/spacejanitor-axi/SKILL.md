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

```sh
spacejanitor doctor --json     # verify platform, Node runtime, and schema versions
spacejanitor disk --json       # storage capacity, snapshots, and Tier 1/2 dry-run plan
spacejanitor memory --json     # true footprint (RSS + compressed/swap) by owner group
spacejanitor blockers --json   # kernel vnodes / inotify / handles / VFS locks / orphans
spacejanitor orphans --json    # git worktrees (clean + pushed proof) & stale build trees
spacejanitor trash --json      # OS Trash / Recycle Bin audit
spacejanitor mcp-audit --json  # MCP process multiplication & duplicate stdio check
spacejanitor remediate         # dry-run preview only (zero deletions or kills)
```

## Safety Rules for Agents

- **Never pass `--execute` automatically.** Only run read-only diagnostics or dry-run previews (`remediate` without `--execute`) unless the human operator explicitly approves specific item IDs.
- **Respect protected paths and git proofs.** Never suggest deleting dirty or unpushed git repositories or credential directories.
