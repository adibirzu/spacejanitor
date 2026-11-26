# Installing SpaceJanitor

> **No installer or npm package is published yet.** There is no release tag, the M7 release matrix (`.github/workflows/release.yml`) has never run, and GitHub Releases is empty. The only supported install path today is **building from source**. The "Planned installers" section describes what the release workflow will produce; none of it exists yet.

SpaceJanitor consists of:
1. The Rust **`sj`** CLI (the only component that protects paths or removes anything).
2. The **`spacejanitor-axi`** Node CLI and agent skill.
3. The **Electron desktop app**, which bundles `sj`.

Prerequisites: Rust stable (`rustup`), Node.js `>= 20` (22 recommended), `git`.

---

## 1. Build the `sj` CLI from source

```bash
git clone https://github.com/adibirzu/spacejanitor.git
cd spacejanitor
cargo build --release --workspace

./target/release/sj doctor
./target/release/sj --help
```

Optional install into `~/.cargo/bin`:

```bash
cargo install --path crates/sj-cli
```

---

## 2. Run the `spacejanitor-axi` CLI from a clone

The package is `private` and not published to npm, so `npx spacejanitor-axi` does not work yet.

```bash
node packages/cli/bin/spacejanitor.mjs summary
node packages/cli/bin/spacejanitor.mjs doctor --json
```

It locates `sj` by **absolute path** only (`SPACEJANITOR_SJ_BIN`, or `target/release` / `target/debug` of the clone) and otherwise falls back to read-only Node collectors. Set `SPACEJANITOR_NO_SJ=1` to force the fallback.

To give an AI agent the read-only workflow, copy or reference [`skills/spacejanitor-axi/SKILL.md`](../skills/spacejanitor-axi/SKILL.md).

---

## 3. Build and run the desktop app from source

```bash
npm install
cargo build --release -p sj-cli          # the app needs sj; it fails closed without it
npm run desktop:build
npm run desktop:pack                      # unpacked app under apps/desktop/ (see electron-builder.yml)
```

There is no `start` script yet. `desktop:pack` builds an unpacked, unsigned app for your own OS (its `before-pack` check requires a staged `resources/bin/sj` of the right architecture) and `npm run desktop:dist` builds local installers. Nothing is signed or published; the packaging flow is exercised by the release workflow and `apps/desktop` tests, not by a published artifact.

---

## 4. Optional Local SLM Advisor

The advisor is optional, loopback-only (`127.0.0.1` / `localhost` / `::1`) and has no execution capability.

```bash
ollama pull qwen2.5:1.5b
node packages/cli/bin/spacejanitor.mjs advise --slm-url http://127.0.0.1:11434/v1/chat/completions
```

It refuses to run when free RAM is below `2.5 GiB` and falls back to deterministic summaries.

---

## 5. Verify the build

```bash
cargo test --workspace
npm test
npm run desktop:test
npm run hygiene
```

---

## 6. Planned installers (not yet published)

When a `vX.Y.Z` tag is pushed, `release.yml` is designed to build and attach, for `x64` and `arm64` where applicable:
- macOS universal `.dmg` / `.zip` (unsigned until notarization is enabled; you would need `xattr -cr` after verifying checksums)
- Linux `.AppImage` and `.deb`
- Windows NSIS `.exe` and `.msi`
- `SHA256SUMS.txt` covering every artifact

Verification will be `sha256sum -c SHA256SUMS.txt --ignore-missing` (Linux), `shasum -a 256 -c SHA256SUMS.txt --ignore-missing` (macOS) or `Get-FileHash` (Windows). Until a release exists, do not download "installers" from any other source claiming to be SpaceJanitor.
