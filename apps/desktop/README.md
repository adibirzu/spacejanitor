# SpaceJanitor Electron Desktop Shell (`apps/desktop`)

Per [ADR-001](../../docs/adr/ADR-001-desktop-runtime-tauri-vs-electron.md), SpaceJanitor uses a **Rust core binary (`crates/sj-cli`)** wrapped by a **thin Electron desktop shell** hosting `apps/ui` for consistent rendering across:
- **macOS:** Apple Silicon (`darwin-arm64`) and Intel (`darwin-x64`)
- **Linux:** `linux-x64` and `linux-arm64` (`.AppImage` / `.deb`, zero WebKitGTK version lock)
- **Windows:** `win32-x64` and `win32-arm64` (`.msi` / `.exe` / NSIS)

## Tray Memory Discipline

When minimized/closed to the menu bar or system tray, the Electron main process destroys the `BrowserWindow` renderer and keeps only the lightweight Rust telemetry daemon active (`~8–20 MiB`), recreating the UI window on demand.
