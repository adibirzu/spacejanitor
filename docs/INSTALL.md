# Installing SpaceJanitor

SpaceJanitor is distributed as:
1. **Desktop Applications** (macOS, Linux, Windows on `x64` & `arm64`) via [GitHub Releases](https://github.com/adibirzu/spacejanitor/releases) *(M5 / M7)*
2. **Standalone `sj` Rust CLI** binaries or source builds *(M1 ready today)*
3. **`spacejanitor-axi` Node CLI & Agent Skill** for AI coding agents

---

## 1. Desktop Application (GitHub Releases)

Download the installer for your OS and architecture from `https://github.com/adibirzu/spacejanitor/releases`.

### macOS (Universal: Apple Silicon `arm64` + Intel `x64`)
- **Artifacts:** `SpaceJanitor-<version>-universal.dmg` or `SpaceJanitor-<version>-universal-mac.zip`
- **Install:** Open the `.dmg` and drag **SpaceJanitor.app** into `/Applications`.
- **Unsigned Gatekeeper Note:** Until Apple Developer ID notarization is enabled on release builds, macOS Gatekeeper may quarantine the downloaded `.app`. After verifying `SHA256SUMS.txt`, clear the quarantine attribute:

```bash
xattr -cr /Applications/SpaceJanitor.app
```

### Linux (`x86_64` & `arm64`)
- **AppImage (`SpaceJanitor-<version>-x86_64.AppImage` / `arm64.AppImage`):**
  ```bash
  chmod +x SpaceJanitor-*-x86_64.AppImage
  ./SpaceJanitor-*-x86_64.AppImage
  ```
  > **FUSE Note:** AppImage requires `libfuse2` (`sudo apt install libfuse2` on Ubuntu 22.04+/Debian). If FUSE is unavailable (e.g., inside containers), extract and run with `--appimage-extract-and-run`.
- **Debian / Ubuntu (`.deb`):**
  ```bash
  sudo apt install ./SpaceJanitor-*_amd64.deb
  # or on ARM64:
  sudo apt install ./SpaceJanitor-*_arm64.deb
  ```

### Windows (`x64` & `arm64`)
- **NSIS Installer (`.exe`):** Run `SpaceJanitor-Setup-<version>.exe` for per-user or machine-wide installation with Start Menu and tray integration.
- **Enterprise MSI (`.msi`):** Deploy `SpaceJanitor-<version>.msi` interactively or silently via `msiexec /i SpaceJanitor-<version>.msi /quiet`.

---

## 2. Verifying Downloads with `SHA256SUMS.txt`

Every release includes `SHA256SUMS.txt` covering all desktop installers and standalone `sj` CLI binaries.

```bash
# macOS
shasum -a 256 -c SHA256SUMS.txt --ignore-missing

# Linux
sha256sum -c SHA256SUMS.txt --ignore-missing
```

```powershell
# Windows PowerShell
Get-FileHash .\SpaceJanitor-Setup-0.1.0.exe -Algorithm SHA256
# Compare the Hash output with the matching line in SHA256SUMS.txt
```

---

## 3. Installing the Rust `sj` CLI

### Option A: Prebuilt Release Binary *(M7)*
Download the `sj-<target>` archive from GitHub Releases, verify `SHA256SUMS.txt`, and place `sj` (or `sj.exe`) on your `PATH`.

### Option B: Build from Source *(M1 Ready Today)*
Requires **Rust** (stable toolchain via `rustup`):

```bash
git clone https://github.com/adibirzu/spacejanitor.git
cd spacejanitor
cargo build --release --workspace

# Optional: install into ~/.cargo/bin
cargo install --path crates/sj-cli

sj doctor --json
```

---

## 4. Installing `spacejanitor-axi` CLI & Agent Skill

Requires **Node.js `>= 20`** (`22` recommended):

```bash
# Run directly via npx (once published)
npx -y spacejanitor-axi doctor

# Or run from a local clone
git clone https://github.com/adibirzu/spacejanitor.git
cd spacejanitor
node packages/cli/bin/spacejanitor.mjs doctor
```

To equip AI coding agents with SpaceJanitor's read-only diagnostic workflow, copy or reference [`skills/spacejanitor-axi/SKILL.md`](../skills/spacejanitor-axi/SKILL.md) in your agent's skills directory.

---

## 5. Optional Local SLM Advisor Setup *(M6)*

The Local SLM Advisor is **100% optional** and **loopback-only** (`127.0.0.1` — zero cloud egress):

- **Ollama (local loopback):**
  ```bash
  ollama pull qwen2.5:1.5b
  # SpaceJanitor connects only to http://127.0.0.1:11434 when you click "Analyze"
  ```
- **Local `llama-server` / GGUF:**
  Download a `Q4_K_M` GGUF (`0.5B` Ultra-Tiny or `1.5B` Standard) and point SpaceJanitor to `http://127.0.0.1:<port>` or configure the local GGUF path. SpaceJanitor keeps `0 MiB` idle RAM and refuses to load weights if available system RAM is `< 2.5 GiB`.

---

## 6. Building Desktop Installers from Source *(M5 / M7)*

Requires **Rust (stable)** and **Node.js 22**:

```bash
git clone https://github.com/adibirzu/spacejanitor.git
cd spacejanitor
npm ci
cargo build --release --workspace
npm run desktop:build
npm run desktop:pack
```

> Note: On branches before M5 lands, `cargo test --workspace`, `npm test`, and `npm run hygiene` validate the core engine and CLI packages.
