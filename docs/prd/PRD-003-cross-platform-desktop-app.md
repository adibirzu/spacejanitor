# PRD-003: Cross-Platform Desktop App (macOS, Linux, Windows x64/ARM64)

**Version:** 1.0  
**Status:** Draft (Pending ADR-001 Runtime Selection)  
**Related ADRs:** [ADR-001](../adr/ADR-001-desktop-runtime-tauri-vs-electron.md), [ADR-004](../adr/ADR-004-privacy-zero-leak-and-two-step-remediation.md)

---

## 1. Objective & Problem

Engineers want the clarity of live visual widgets—storage breakdown, resident vs. compressed RAM bars, kernel OS-blocker badges, orphan worktree git safety proofs, and one-click dry-run previews—in a small, always-available tray utility that works identically across macOS, Linux, and Windows on both `x86_64` and `ARM64`.

## 2. Target Personas

- **Workstation Developer:** Keeps SpaceJanitor minimized in the menu bar / system tray for instant status at a glance (`OK`, `CHECK`, `ALERT`, `CRITICAL`) and visual triage when the system slows down.

## 3. Functional Requirements

| ID | Requirement | Priority |
|---|---|---|
| **FR-3.1** | **Overview & Tray Indicator:** Menu bar / tray badge showing worst active status across Disk, True Memory/Swap, and OS Blockers, with local threshold notifications (zero external push services). | P0 |
| **FR-3.2** | **Storage, Trash & Orphan Work View:** Interactive breakdown of top disk consumers, Trash / Recycle Bin size, Tier 1/2 candidates, and protected/dirty git worktree exclusion reasons. | P0 |
| **FR-3.3** | **Memory & OS-Blocker Forensics View:** KPI cards (Kernel Vnodes / `inotify` / Handles, Swap/Pagefile, Process & Port Counts) and stacked Resident (`RSS`) vs. Compressed/Swapped bar charts by owner group (`MCP Fleet`, `VMs`, `Agent CLIs`, `OS Daemons`). | P0 |
| **FR-3.4** | **MCP & Indexer Hygiene Panel:** Shows MCP process count per agent family, highlights duplicate stdio servers (`npx` pairs), and previews Spotlight / Windows Search / `inotify` exclusion actions. | P1 |
| **FR-3.5** | **Two-Step Dry-Run Remediation Flow:** Displays exact files/PIDs/commands in dry-run preview before issuing a 5-minute single-use confirmation token bound to the plan SHA-256 and target scope. | P0 |
| **FR-3.6** | **Plugin Slot Rendering:** Renders declarative widgets registered by `@spacejanitor/plugin-sdk` modules cleanly in light and dark system themes. | P1 |

## 4. Non-Functional Requirements

- **Resource Budget (Primary Tauri v2 target):** `< 100 MiB` idle RAM, `< 15 MiB` compressed installer, `< 1%` background CPU while polling every `30s` (pauses polling when tray window is closed unless threshold alerts are enabled).
- **Portability Matrix:** Native builds for `darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`, `win32-x64`, and `win32-arm64`.
- **Accessibility:** Full keyboard navigation, semantic landmarks, and high-contrast accessible status badges (never color-only).

## 5. Acceptance Criteria & Milestones

- **M1:** Shell-agnostic React UI (`apps/ui`) renders mock and live `spacejanitor.*.v1` fixtures with working dry-run preview and two-step confirmation flow.
- **M2:** Desktop shell (`apps/desktop`) builds installers on all 6 target platforms via GitHub Actions CI matrix and stays within idle RAM budget.
