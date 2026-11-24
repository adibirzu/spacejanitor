# ADR-001: Desktop Application Runtime (Tauri v2 vs. Electron)

- **Status:** Proposed (Recommended: Tauri v2 primary, Shell-Agnostic UI)
- **Date:** 2026-11-24
- **Drivers:** Low idle memory footprint, cross-platform portability (`macOS`, `Linux`, `Windows` on `x86_64` and `ARM64`), deterministic safe execution.

---

## Context

SpaceJanitor needs a cross-platform desktop UI with a system tray indicator, live storage and memory telemetry widgets, orphan-work diff previews, and gated two-step remediation dialogs. Unlike generic desktop utilities, SpaceJanitor specifically investigates and mitigates workstation RAM exhaustion—meaning the desktop app itself will often launch when a host is already under severe memory and swap pressure.

## Options Considered

### Option A: Tauri v2 (Rust Backend + OS Native WebView) — **Recommended**
- Uses the host OS WebView (`WKWebView` on macOS, `WebView2` on Windows, `WebKitGTK 4.1` on Linux) and a compiled Rust host process.
- Typical idle memory is **~50–90 MiB** and compressed installers are **~2–10 MiB**.
- Native Rust telemetry (`sysinfo` + OS syscalls) or structured invocation of the SpaceJanitor engine executes safely behind Tauri v2's fine-grained capabilities permission model.
- Supports `aarch64` and `x86_64` across macOS, Linux, and Windows via native GitHub Actions runners.

### Option B: Electron (Bundled Chromium + Node.js)
- Bundles Chromium and Node.js, offering identical rendering across Linux distributions without relying on `libwebkit2gtk-4.1`, and allows 100% TypeScript/Node code sharing between `packages/core` and the desktop main process.
- Baseline idle RAM is **~150–300+ MiB** and installers are **~100–150+ MiB** (`250+ MiB` unpacked).

### Option C: Local Web UI Only (No Native App)
- Zero native tray icon, OS notifications, or native single-binary installer.

## Decision

1. **Architecture Separation:** Keep all business logic, safety invariants, rule registries, and collector schemas in headless engine packages (`packages/core`, `packages/plugin-sdk`, `packages/cli`), and keep the frontend (`apps/ui`) a pure React/TypeScript SPA communicating through a minimal `TransportBridge` interface (`invoke` / `subscribe`).
2. **Recommended Primary Desktop Shell:** Target **Tauri v2** (`apps/desktop`) as the primary production runtime so the janitor consumes `<100 MiB` RAM while resident in the tray.
3. **Interchangeability:** Because `apps/ui` and `packages/core` carry zero Tauri-specific imports, an Electron wrapper (`apps/desktop-electron`) can be added with ~100 lines of IPC glue if pure-Node packaging or minimal Linux WebKitGTK-less environments require it.
4. **Multi-Arch Release Pipeline:** Build all 6 targets (`darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`, `win32-x64`, `win32-arm64`) natively on GitHub Actions matrix runners rather than fragile cross-OS linking.

## Consequences

- **Positive:** Lowest possible memory footprint (~3–5× lighter than Electron) and smallest binary distribution; strict capability boundary between UI and destructive actions.
- **Negative / Mitigation:** Requires Rust toolchain in CI and `libwebkit2gtk-4.1` on Linux desktop targets; mitigated by native GitHub Actions runners, AppImage bundling, and maintaining the headless CLI + local web preview as fallback.
