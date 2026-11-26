# PRD-003: Cross-Platform Desktop App (macOS, Linux, Windows x64/ARM64)

**Version:** 1.0  
**Status:** Implemented from source (no installer published; owner grouping, plugin widgets and exclusion previews open)
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

---

## Implementation Status (as of `main`, PRs #10, #11)

| Requirement | State | Where |
|---|---|---|
| FR-3.1 Overview and tray | Implemented: tray badge, Overview gauges, close-to-tray destroys the renderer. No external push services | `apps/desktop/src/main.ts`, `apps/ui/src/components/Gauges.tsx` |
| FR-3.2 Storage / Trash / orphan view | Implemented: Disk view; orphans "not scanned (disabled by default)" until the confirmed opt-in; blocked items show reasons; caches listed read-only | `apps/ui/src/App.tsx`, `candidateAnnotations.ts`, `orphanSetting.ts` |
| FR-3.3 Memory and blockers | Partial: gauges and a Memory tab; **no owner-group stacked chart** | `apps/ui` |
| FR-3.4 MCP and indexer panel | Partial: MCP fleet and secret audit tab; Spotlight / Search / `inotify` exclusion previews not implemented | `apps/ui` |
| FR-3.5 Two-step remediation | Implemented and selection-bound: digest from `sj plan --select`, `CONFIRM-XXXXXXXX` phrase, 5-minute TTL, single use, mutex; every removal runs in `sj` and fails closed without it | `remediationGate.ts`, `sjBridge.ts` |
| FR-3.6 Plugin widgets | Not implemented in the UI | `packages/plugin-sdk` declares widgets only |

**Platform notes:** removal is Unix-only (Windows plans but cannot execute). **No installer exists:** no tag has been pushed and the M7 release matrix (`release.yml`) has not run, so macOS/Linux/Windows `x64`/`arm64` artifacts and `SHA256SUMS.txt` are unverified. Unsigned until signing and notarization are enabled.
