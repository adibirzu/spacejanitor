# SpaceJanitor Electron Desktop Shell (`apps/desktop`)

Per [ADR-001](../../docs/adr/ADR-001-desktop-runtime-tauri-vs-electron.md), SpaceJanitor uses a **Rust core binary (`crates/sj-cli`)** wrapped by a **thin Electron desktop shell** hosting `apps/ui` for consistent rendering across:
- **macOS:** Apple Silicon (`darwin-arm64`) and Intel (`darwin-x64`)
- **Linux:** `linux-x64` and `linux-arm64` (`.AppImage` / `.deb`, zero WebKitGTK version lock)
- **Windows:** `win32-x64` and `win32-arm64` (`.msi` / `.exe` / NSIS)

## Tray Memory Discipline

When minimized/closed to the menu bar or system tray, the Electron main process destroys the `BrowserWindow` renderer and keeps only the lightweight Rust telemetry daemon active (`~8–20 MiB`), recreating the UI window on demand.

## Orphan scanning is opt-in

The desktop app does **not** scan for orphan git worktrees by default: that scan (and the worktree prune) runs `git` inside repositories found on disk and is unreviewed, experimental behavior. The setting lives in the main process (`orphanScan` in `settings.json` under the app data folder, default `false`), is changed through the toggle in the Disk view, and turning it ON additionally shows a native confirmation dialog (Cancel is the default) that only the main process can open; a renderer script cannot enable it without that user confirmation, nor through the generic invoke channel. Turning it off needs no dialog. While it is off, no git process is spawned for scanning, planning or executing, and the UI shows orphans as "not scanned (disabled by default)". See Known limitations in the root README.

## Safety gate: every remediation decision is made by Rust `sj`

The desktop app contains **no** protected-path list, descendant walk or worktree proof. Plans and deletions go through the bundled Rust binary:

| Step | Call |
|------|------|
| Dry-run plan | `sj plan <root> --json` (add `--include-orphans` only when the opt-in above is on) |
| Protected-path / descendant checks (read-only annotations) | `sj protect --json [--descendants] -- <path>` |
| Execute one confirmed item | `sj plan <root> --execute --confirm --plan-sha256 <sha> --item <id>` (no-follow, entry-by-entry removal with execute-time re-checks, done inside sj) |

The Electron main process only keeps the two-step session (digest, `CONFIRM-XXXXXXXX` phrase, 5-minute TTL, single use, mutex).

**Fail closed.** If `sj` is missing, not executable, times out, exits non-zero or returns anything unparseable, every destructive action is refused with a visible message; read-only dashboards keep working. `SPACEJANITOR_NO_SJ=1` forces this state.

**Binary location.** Absolute path only, never `PATH` or the cwd: a packaged app uses `<resources>/bin/sj` (`sj.exe` on Windows) and nothing else; unpackaged dev builds also accept an absolute `SPACEJANITOR_SJ_BIN` and `target/{release,debug}`.

**Packaging.** `resources/bin/sj` is staged per target by the release workflow (darwin: `lipo` universal; linux x64/arm64; win32 x64/arm64) and shipped via `extraResources`. `scripts/before-pack.cjs` aborts the build when it is missing, not executable or the wrong architecture, and `scripts/verify-packaged-sj.cjs` re-checks the packaged app (and smoke-runs it on native runners).

**Platform note.** `sj` executes removals with handle-anchored Unix APIs; on Windows it plans but refuses to execute, so cleanup is unavailable there until sj supports it.
**Cache candidates.** `sj plan` covers OS Trash items and, only with the orphan opt-in, verified orphan worktrees; cache directories listed by the read-only telemetry are shown in the UI under "Not removable from the desktop" (never selectable) and cannot be removed from the desktop. The UI only offers items the gate accepted: the main process annotates every candidate with `selectable` / `blockedReason` from `sj protect` before the renderer sees it.
