# SpaceJanitor Electron Desktop Shell (`apps/desktop`)

Per [ADR-001](../../docs/adr/ADR-001-desktop-runtime-tauri-vs-electron.md), SpaceJanitor uses a **Rust core binary (`crates/sj-cli`)** wrapped by a **thin Electron desktop shell** hosting `apps/ui` for consistent rendering across:
- **macOS:** Apple Silicon (`darwin-arm64`) and Intel (`darwin-x64`)
- **Linux:** `linux-x64` and `linux-arm64` (`.AppImage` / `.deb`, zero WebKitGTK version lock)
- **Windows:** `win32-x64` and `win32-arm64` (`.msi` / `.exe` / NSIS)

## Tray Memory Discipline

When minimized/closed to the menu bar or system tray, the Electron main process destroys the `BrowserWindow` renderer and keeps only the lightweight Rust telemetry daemon active (`~8–20 MiB`), recreating the UI window on demand.

## Orphan scanning is opt-in

The desktop app does **not** scan for orphan git worktrees by default: that scan (and the worktree prune) runs `git` inside repositories found on disk and is unreviewed, experimental behavior. The setting lives in the main process (`orphanScan` in `settings.json` under the app data folder, default `false`), is changed through the toggle in the Disk view, and turning it ON additionally shows a native confirmation dialog (Cancel is the default) that only the main process can open; a renderer script cannot enable it without that user confirmation, nor through the generic invoke channel. Turning it off needs no dialog. While it is off, no git process is spawned for scanning, planning or executing, and the UI shows orphans as "not scanned (disabled by default)". See Known limitations in the root README.
