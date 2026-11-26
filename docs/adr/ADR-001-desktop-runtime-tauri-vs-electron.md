# ADR-001: Desktop & Core Architecture (Rust Core Engine + Electron Desktop Shell)

- **Status:** Accepted and implemented (Electron shell plus Rust core; decision closed)
- **Date:** 2026-11-24
- **Drivers:** Maximum filesystem/telemetry speed, zero-GC native cross-platform binaries (`macOS`, `Linux`, `Windows` on `x86_64` and `ARM64`), uniform cross-platform desktop UI rendering, and bounded background memory usage.

---

## Context

SpaceJanitor needs two distinct capabilities:
1. **High-speed, ultra-low-overhead workstation scanning** across hundreds of thousands of files, nested git repositories, OS process tables, and kernel counters on `macOS`, `Linux`, and `Windows` (`x86_64` and `ARM64`).
2. **A portable visual desktop app** with system tray controls, stacked memory-footprint charts, OS-blocker badges, and interactive two-step dry-run remediation dialogs that render consistently across every Linux, Windows, and macOS environment without distro-specific WebKitGTK dependencies.

## Decision

Adopt a **two-layer hybrid architecture**:

1. **Rust Core & CLI Engine (`crates/sj-core`, `crates/sj-cli`):**
   - Written in Rust for parallel directory walking (`jwalk` / `ignore`), zero-runtime-overhead memory/OS-blocker telemetry (`sysinfo` + OS native APIs), git safety verification, immutable protected-path enforcement, and secret redaction.
   - Compiles to a single small native binary (`~8–20 MiB` headless memory) per target (`darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`, `win32-x64`, `win32-arm64`).
   - Exposes both human/agent **AXI CLI (`spacejanitor`)** and an **NDJSON / JSON-RPC stdio transport** for GUI hosts.

2. **Thin Electron Desktop Shell (`apps/desktop` + `apps/ui`):**
   - Hosts the React + TypeScript UI (`apps/ui`) using Electron so desktop widgets, charts, and CSS render identically across Windows `x64`/`ARM64`, Linux `x64`/`ARM64`, and macOS without WebKitGTK version mismatches on Linux.
   - **Tray-First Memory Discipline:** When the user closes or minimizes the window to the system tray, Electron destroys the `BrowserWindow` renderer process—keeping only the Rust collector/tray bridge resident until reopened, eliminating Chromium's ~150–300 MiB idle renderer footprint.

3. **AXI CLI & TypeScript Plugin SDK (`packages/core`, `packages/cli`, `packages/plugin-sdk`):**
   - Remains available as a zero-install `npx` AXI entrypoint (`spacejanitor-axi`) and plugin contract layer that invokes the native Rust binary when installed or falls back gracefully on diagnostics.

## Consequences

- **Positive:** Native Rust scanning speed and tiny background tray footprint paired with battle-tested Electron cross-platform packaging (`electron-builder`) for `x86_64` and `ARM64`.
- **Negative / Mitigation:** Dual build graph (Cargo + Node/Electron) requires both Rust and Node in CI; mitigated cleanly by native GitHub Actions matrix runners (`ubuntu-latest`, `ubuntu-24.04-arm`, `macos-15`, `windows-latest`) and strict JSON contract versioning (`spacejanitor.*.v1`) between Rust and Electron.

---

## Implementation Status (as of `main`)

**Decision: Electron plus Rust core.** The Tauri alternative is closed.

| Item | State |
|---|---|
| Rust core and `sj` CLI | Implemented (`crates/sj-core`, `crates/sj-cli`) |
| `sj serve-stdio` NDJSON JSON-RPC sidecar | Implemented; the Electron main process spawns it as a sidecar and also runs one-shot `sj` calls for plans and execution (`apps/desktop/src/sjBridge.ts`) |
| Electron shell, tray and close-to-tray renderer destruction | Implemented (`apps/desktop`, `apps/ui`) |
| `sj` bundled into the app as `resources/bin/sj`, staged per target | Implemented in `release.yml` / `before-pack.cjs`; **never run**: no tag, no published installers |
| AXI entrypoint | Implemented as `spacejanitor-axi` from a clone (not on npm) |
| `~8-20 MiB` headless footprint claim | Not measured |

The Node layer holds **no** protection logic; everything delegates to the Rust gate (PR #11). Open: first release run (M7), Windows removal.
