# 001 — Competitive Landscape & Cross-Platform Runtime Research

**Date:** 2026-11-24  
**Status:** Baseline Research for ADR-001 through ADR-004

---

## 1. Problem Statement

Modern software engineers running multiple AI coding agents, container runtimes, and parallel git worktrees experience two distinct degradation modes that existing cleaners treat separately or ignore:

1. **Orphan work & disk accumulation:** Abandoned git worktrees, unpushed feature branches, `node_modules`/`.venv`/`target` build artifacts, stale container images, and unemptied OS Trash / Recycle Bin entries quietly consume tens or hundreds of gigabytes. Deleting a worktree blindly destroys uncommitted or unpushed work.
2. **Hidden memory bloat & OS/VFS stalls:** Plain resident-memory (`RSS`) views miss tens of gigabytes of compressed RAM and encrypted swap. Meanwhile, global stdio MCP configurations multiplied across dozens of agent sessions, recursive directory locks (`lsof +D`), unexcluded OS search indexers (`mdworker`, Windows Search), and orphaned `PPID=1` background scripts exhaust kernel vnodes, `inotify` watches, and process tables until SSH, shells, and desktop UI stall.

---

## 2. Competitive Landscape Matrix

| Tool | License | Storage Caches | Git Worktree Orphan Check | OS Trash Audit | True Memory / Swap Footprint | Kernel / VFS OS Blockers | MCP Process Audit | Cross-Platform (`macOS/Linux/Win`, `x64/ARM64`) |
|---|---|---|---|---|---|---|---|---|
| **BleachBit** | GPLv3 | Yes | No | Partial | No | No | No | Linux, Windows |
| **Czkawka** | MIT | Duplicates / Big files | No | Partial | No | No | No | macOS, Linux, Windows |
| **Mole (`tw93/mole`)** | MIT | Yes | No | Yes | Basic live stats | No | No | macOS-first |
| **npkill** | MIT | `node_modules` | No | No | No | No | No | Node CLI (all) |
| **kondo** | MIT | Multi-lang build dirs | No | No | No | No | No | Rust CLI (all) |
| **residue-cli** | MIT | Agent worktrees | Uses `lsof` check | No | No | No | No | macOS / Linux |
| **gwt / wtp** | MIT | Worktree lifecycle | Manual | No | No | No | No | macOS / Linux / Win |
| **mcp-cli / mcpjam** | MIT | No | No | No | No | No | Tool inspection only | Node CLI |
| **SpaceJanitor (Target)** | **MIT** | **Tiered + Protected Denylist** | **Dirty/Remote/Unpushed/Nested Git Proof** | **Yes** | **Footprint (`RSS + Compressed/Swap`)** | **Vnodes / `inotify` / Locks / Orphans** | **Per-agent & Orphan Audit** | **macOS, Linux, Windows (`x86_64` & `ARM64`)** |

### Key Gaps Identified

- **Recursive `lsof +D` hazard:** Scanning git worktrees with `lsof +D` on busy systems contends on kernel VFS locks and accelerates vnode starvation. SpaceJanitor must inspect process open-file tables or CWD symlinks non-recursively (`/proc/<pid>/cwd`, targeted `lsof -d cwd` without `+D`, or Windows Restart Manager / handle checks).
- **RSS vs True Footprint blindness:** Reporting `ps` RSS alone masks memory hogs whose anonymous pages have been compressed or pushed to swap (`top` `MEM` on macOS, `smaps_rollup` `Pss + SwapPss` on Linux, `PrivateMemorySize64 + Virtual/Commit` on Windows).
- **Lack of an agent-consumable + GUI dual surface:** CLI-only cleaners cannot sit in the menu bar / system tray for non-CLI triage, while GUI-only cleaners cannot be queried deterministically by AI agents via TOON/JSON contracts.

---

## 3. Desktop Runtime Evaluation: Tauri v2 vs. Electron

Because SpaceJanitor's core purpose includes **diagnosing and relieving memory pressure**, the desktop shell's own RAM footprint, installer size, and cross-architecture (`x86_64` + `ARM64`) build story are first-class constraints.

| Criterion | Tauri v2 (Rust Core + OS WebView) | Electron (Chromium + Node.js) | Impact on SpaceJanitor |
|---|---|---|---|
| **Idle RAM Footprint** | **~50–90 MiB** (native Rust polling + system WebView) | **~150–300+ MiB** (bundled Chromium + Node main process) | **Tauri v2 wins decisively.** Running a 250 MiB Chromium browser to warn a user about RAM exhaustion undermines trust. |
| **Installer / Binary Size** | **~2–10 MiB** | **~100–150+ MiB** compressed (`250+ MiB` unpacked) | **Tauri v2 wins.** Fast downloads and negligible disk overhead on tight disks. |
| **System Telemetry (`x64`/`ARM64`)** | Native Rust crates (`sysinfo`, `mach2`, `procfs`, `windows-sys`) with zero `node-gyp` rebuild fragility | Node.js `child_process` (`top`, `/proc`, PowerShell CIM) or C++ N-API native addons | Native Rust avoids C++ toolchain mismatches; shared CLI/Node collectors can also run as pure-JS or sidecar binary. |
| **Windows ARM64 (`aarch64`)** | Supported (`aarch64-pc-windows-msvc`); uses built-in WebView2 | Official prebuilt Windows ARM64 Electron binaries | Tie on target support; both run natively on Windows on ARM. |
| **Linux ARM64 (`aarch64`)** | Supported (`aarch64-unknown-linux-gnu`); requires host `libwebkit2gtk-4.1` | Supported; bundles Chromium so zero WebKitGTK dependency quirks | Electron has more uniform Linux WebGL/CSS rendering; Tauri `.deb`/`.AppImage` must declare `webkit2gtk-4.1`. |
| **Cross-Compilation DX** | Native CI matrix recommended (`ubuntu-latest`, `ubuntu-24.04-arm`, `macos-15`, `windows-latest`) because cross-OS linker/WebKit packaging is brittle | `electron-builder` handles JS bundling cleanly, though native N-API addons still require native CI runners | Native GitHub Actions matrix builds solve multi-arch packaging cleanly for **both** frameworks. |

### Architectural Takeaway

Separating **engine + telemetry (`packages/core`, `packages/cli`, optional Rust `sysinfo` crate)** from a **pure React UI (`apps/ui`)** eliminates lock-in:

1. **Primary recommended shell:** **Tauri v2** (`apps/desktop`) for `<100 MiB` idle RAM, `<15 MiB` installers, granular capability permissions, and native tray support.
2. **Optional fallback shell:** A thin Electron wrapper (`~100 LOC` main/preload bridge) remains trivial to maintain if contributors require pure-TypeScript-only builds or encounter WebKitGTK issues on headless/minimal Linux ARM64 desktops.
