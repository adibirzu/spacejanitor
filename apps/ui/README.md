# SpaceJanitor Shell-Agnostic UI (`apps/ui`)

This directory will hold the shared React + TypeScript UI consumed by the desktop application (`apps/desktop`) and optional local browser preview, built against the `spacejanitor.*.v1` contracts (see [PRD-003](../../docs/prd/PRD-003-cross-platform-desktop-app.md)).

## Planned Views

- **Overview & System Tray Summary:** Worst active status across storage, true RAM footprint, and OS blockers.
- **Storage, Trash & Orphan Work:** Top consumers, OS Trash / Recycle Bin, Tier 1/2 rules. Git worktree orphans show as "not scanned (disabled by default)" until the experimental opt-in is enabled (runs git inside repositories found on disk; see the root README, Known limitations).
- **Memory & OS-Blocker Forensics:** Resident (`RSS`) vs. compressed/swapped bar breakdowns, kernel vnode/`inotify`/handle gauges, and MCP fan-out inspection.
- **Dry-Run & Two-Step Confirmation Drawer:** Exact target diff preview + single-use token confirmation before any execution.
