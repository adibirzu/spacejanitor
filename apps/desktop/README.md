# SpaceJanitor Cross-Platform Desktop Shell (`apps/desktop`)

Target platforms (`x86_64` and `ARM64`):
- **macOS:** Apple Silicon (`darwin-arm64`) and Intel (`darwin-x64`)
- **Linux:** `linux-x64` and `linux-arm64` (`.AppImage` / `.deb`)
- **Windows:** `win32-x64` and `win32-arm64` (`.msi` / `.exe`)

See [ADR-001](../../docs/adr/ADR-001-desktop-runtime-tauri-vs-electron.md) for the **Tauri v2** recommendation vs. thin **Electron** fallback comparison, and [PRD-003](../../docs/prd/PRD-003-cross-platform-desktop-app.md) for resource budgets and tray requirements.
