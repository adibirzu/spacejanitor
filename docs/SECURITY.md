# SpaceJanitor Security Policy & Invariants

SpaceJanitor inspects local filesystems, git repositories, running process arguments, and kernel counters, and optionally cleans operator-approved targets. Because a workstation janitor operates on sensitive local state, security invariants are enforced deterministically in `crates/sj-core`.

> **Implementation status:** everything below is implemented on `main` unless marked otherwise. The root [SECURITY.md](../SECURITY.md) is the disclosure policy and the shorter threat model; this page is the detailed reference.

---

## 1. Threat Model & Core Invariants

1. **Read-only default.** Audit commands (`doctor`, `scan`, `trash`, `memory`, `blockers`, `mcp-audit`, `llm-audit`) and dry-run plans perform zero deletions, zero git mutations and zero signals. The one exception to "no git" is the opt-in orphan scan (section 6).
2. **Rust `sj` is the only protection gate.** The Node denylist was removed. The desktop app and `packages/core` forward every path to `sj protect` / `sj plan --select` and treat any failure, timeout or unparseable reply as "protected". With `sj` unavailable every destructive action is refused.
3. **Two-step, selection-bound execution.** `sj plan --select` reports a digest over exactly the selected items (path, dev/ino, size, mtime and a content snapshot). `--execute --confirm --selection-sha256` rebuilds the plan and refuses unless it hashes to that digest. The desktop session adds a typed phrase, a 5-minute TTL, single use and a mutex. `sj reap` binds execution to its own digest and re-verifies PID, command hash and start time.
4. **Unix-only removal.** Removal is handle-anchored and no-follow (macOS, Linux). On Windows `sj plan --execute` is refused and `sj reap` finds no eligible targets.
5. **Zero cloud telemetry.** No analytics, crash reports or workstation metadata leave the machine.

---

## 2. Protected-Path Gate (`crates/sj-core/src/protect.rs`)

`check_path_protection()` (exposed as `sj protect`) enforces built-in rules that cannot be overridden by CLI flags, plugins, or SLM proposals. User rules (`--exact`, `--dynamic`, `--glob`) can only add protection:

- **Protected Roots:** `/`, `$HOME`, `/System`, `/usr`, `/bin`, `/sbin`, `/etc`, `/Library`, `/private/etc`, `/private/var/db`, `/Windows`, `C:\Windows` (including macOS `/System/Volumes/Data` prefix stripping so APFS data volume paths cannot bypass system root checks).
- **Credential & Agent Directories:** `.ssh`, `.gnupg`, `.aws`, `.kube`, `.claude`, `.config/gh` (checked both under `$HOME` and as any path segment, case-insensitively).
- **Secret & Key Files:** `.env`, `.env.*`, `*.env`, `*.private.*`, `id_rsa`, `id_rsa.*`, `id_ed25519`, `id_ed25519.*`, `id_ecdsa`, `id_ecdsa.*`, `id_dsa`, `id_dsa.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`. Key names are prefix-matched (`id_rsa_work` is protected); `.envrc` is **not** matched unless it sits inside a protected directory such as `~/.ssh`.
- **VM Disk Images:** `*.vmdk`, `*.qcow2`, `*.vhdx`, `*.vdi`, `*.raw`, `*.img`.
- **Quarantine Staging Protection:** Any path segment beginning with `.sj-stage-` is protected to prevent double-mutation during staged recovery.

### Path Canonicalization & Symlink Traversal Defense
- **Lexical Normalization:** Resolves `.` and `..` segments, normalizes `\` and `/` separators, and expands `~/` before evaluation.
- **Ancestor Symlink Walking:** Walks every ancestor using `symlink_metadata` + `canonicalize`, **failing closed** on dangling/unresolvable symlinks or any symlink whose target resolves inside a protected location.
- **Bounded Descendant Inspection:** `check_dir_descendants_safe()` walks directory contents with `follow_links(false)` and fails closed if any descendant is a symlink, unreadable, protected, or exceeds `max_entries`.

---

## 3. Redaction: a Closed Vocabulary, Not Pattern Matching

Audit output (`mcp-audit`, `llm-audit`, `reap`, `memory`, `serve-stdio`) is built from a fixed catalog (`crates/sj-core/data/redact_catalog.json`) or reduced to a hash, rather than by guessing which text looks secret:

- Commands, launchers, clients and package ids: catalog only, otherwise `<command>` / `<package:hash8>`. Flag names: catalog only, otherwise `<flag>`; flag values are always `<REDACTED>`.
- URLs: `http|https|ws|wss` scheme plus a dotted DNS host only; never userinfo, path or query (otherwise `<url>`).
- Env and header key names: a fixed known-safe list; any other key is counted, never named.
- Live-process labels: the matched config label, a catalog package or client, otherwise `unknown-<8 hex of sha256(argv)>`.
- `secret_findings` fire only on a real signal (a secret-named flag or env key, or a known token prefix, case-insensitive).
- Config server labels are user-chosen and are shown only if at most 32 characters of `[a-z0-9._-]` with no alphanumeric run over 12; otherwise `server-<hash8>`. Do not use a secret as a server label.
- Config files are opened once without following leaf symlinks, then checked before reading from the opened handle. On Windows, the reader rejects leaf reparse points and checks the handle's final path against the protection and home rules. Windows directory listings are path-based.
- The TOML reader scans multiline arrays incrementally and stops parsing the file with a warning if an array remains unclosed at EOF or exceeds 256 KiB. It retains entries parsed before the incomplete statement.

---

## 4. Desktop Sandbox, Process Spawning & Loopback SLM Guard

- **Electron sandbox:** `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`; a typed, allowlisted preload bridge with payload validation.
- **No shell interpolation:** `sj` and `git` run with argument arrays (`shell: false` / `Command::new`).
- **`sj` is located by absolute path only** (bundled `resources/bin/sj` when packaged; otherwise `SPACEJANITOR_SJ_BIN` or the repo's `target/`), never `PATH` or the cwd, and must be a regular, user-owned, non-symlink executable.
- **Loopback-only SLM advisor:** connects only to `127.0.0.1` / `localhost` / `::1`, receives redacted summary metadata only, has no execution capability, and refuses to run below `2.5 GiB` free RAM. Suggestions are annotations; execution still goes through the gate.

---

## 5. Repository Hygiene Gate

Every pull request runs:
- `node scripts/check-oss-hygiene.mjs` blocks non-placeholder home paths, private IP ranges and credential prefixes.
- `gitleaks` — scans git history and working tree for leaked secrets.

---

## 6. Known limitations (opt-in orphan scanning)

Orphan-repo scanning is **off by default** because it runs `git` (status, ls-remote, config reads, worktree remove) inside repositories found on disk. Tracked in [issue #12](https://github.com/adibirzu/spacejanitor/issues/12). B35 (submodule filters), B36 (proxy/netrc credential leak) and B37 (timeouts, scan deadline, FIFO config) are fixed in the Rust core: git proofs run with a scrubbed environment and config, repositories with submodules or any `http.*`/`protocol.*` config are blocked, the whole git process tree is killed on timeout (process group on Unix, a kill-on-close job object on Windows), and the scan has a wall-clock deadline. The remaining leftovers are also fixed: a directory whose `.git` file points at a bare repository is refused as `bare_main_repository`, and a linked worktree of a bare repo is proven against its real common dir; the known benign `filter.lfs` and stock `credential.helper` forms are allowed by exact value while any other command-bearing value (and `lfs.extension.*`/`lfs.customtransfer.*`) stays blocked; refs are verified in batches up to a 200,000-commit cap that fails closed as `too_many_local_commits_to_verify`; and the scrubbed-git temp HOME is removed when the scan ends on every path. sj never runs `git worktree prune`, so removing a bare repo's linked worktree leaves its stale admin entry for the user to prune. Scanning stays opt-in.

Opt in only for repositories you trust (`--include-orphans` or the confirmed desktop toggle).

---

## 7. Vulnerability Reporting (Responsible Disclosure)

Please report security vulnerabilities **privately** via **GitHub Security Advisories** (`https://github.com/adibirzu/spacejanitor/security/advisories/new`) rather than opening a public issue with exploit details. Include:
- Affected OS and architecture (`macOS`/`Linux`/`Windows`, `x64`/`arm64`)
- Reproduction steps or minimal proof-of-concept
- Potential impact (e.g., protected-path bypass, secret exposure, or privilege/execution gate bypass)
