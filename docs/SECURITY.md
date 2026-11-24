# SpaceJanitor Security Policy & Invariants

SpaceJanitor inspects local filesystems, git repositories, running process arguments, and kernel counters, and optionally cleans operator-approved targets. Because a workstation janitor operates on sensitive local state, security invariants are enforced deterministically in `crates/sj-core`.

> **Implementation Status:**
> - **Shipped today (`M1`):** `crates/sj-core/src/protect.rs` (Protected Never-Touch Denylist, APFS `/System/Volumes/Data` prefix stripping, symlink traversal defense, `.sj-stage-*` quarantine protection), `spacejanitor.proposal.v1` SHA-256 two-step execution gate, Trash/orphan TOCTOU re-verification, and the `redact_secrets()` helper in `crates/sj-core/src/lib.rs`.
> - **Planned (`M2`–`M6`):** `memory` / `blockers` (`M2`), `mcp-audit` and `reap` PID + start-time re-verification (`M3`), collector integration of `redact_secrets()` (`M2` / `M3`), Electron sandbox & 2-step UI confirmation (`M5`), and Local SLM loopback guard (`M6`).

---

## 1. Threat Model & Core Invariants

1. **Read-Only Default:** All audit commands (`doctor`, `scan`, `trash`, `orphans` in `M1`; `memory`, `blockers` in `M2`; `mcp-audit` in `M3`) and dry-run plans perform zero file deletions, zero git mutations, and zero process signals.
2. **Two-Step Execution Gate:** Mutating actions require an explicit `--execute` flag, confirmation flag/phrase, exact `item` ID, and a matching `plan_sha256` digest bound to the dry-run plan (`spacejanitor.proposal.v1`, `M1`).
3. **TOCTOU Re-Verification:** Before removing a Trash item or pruning a git worktree (`M1`), or signalling a `PPID=1` orphan process (`M3`), `sj-core` re-verifies protection rules and git clean/pushed state (`M1`), or PID + `PPID == 1` + command + start time (`M3`).
4. **Zero Cloud Telemetry:** SpaceJanitor sends zero analytics, crash reports, or workstation metadata to external servers.

---

## 2. Protected Never-Touch Denylist (`crates/sj-core/src/protect.rs`, Shipped `M1`)

`check_path_protection()` enforces an immutable denylist that cannot be overridden by CLI flags, plugins, or SLM proposals:

- **Protected Roots:** `/`, `$HOME`, `/System`, `/usr`, `/bin`, `/sbin`, `/etc`, `/Library`, `/private/etc`, `/private/var/db`, `/Windows`, `C:\Windows` (including macOS `/System/Volumes/Data` prefix stripping so APFS data volume paths cannot bypass system root checks).
- **Credential & Agent Directories:** `.ssh`, `.gnupg`, `.aws`, `.kube`, `.claude`, `.config/gh` (checked both under `$HOME` and as any path segment, case-insensitively).
- **Secret & Key Files:** `.env`, `.env.*`, `*.env`, `*.private.*`, `id_rsa`, `id_rsa.*`, `id_ed25519`, `id_ed25519.*`, `id_ecdsa`, `id_ecdsa.*`, `id_dsa`, `id_dsa.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`. Custom suffix names without a dot (e.g., `id_rsa_work` or `.envrc`) are **not** matched by the default filename rule unless placed inside a protected directory such as `~/.ssh`.
- **VM Disk Images:** `*.vmdk`, `*.qcow2`, `*.vhdx`, `*.vdi`, `*.raw`, `*.img`.
- **Quarantine Staging Protection:** Any path segment beginning with `.sj-stage-` is protected to prevent double-mutation during staged recovery.

### Path Canonicalization & Symlink Traversal Defense
- **Lexical Normalization:** Resolves `.` and `..` segments, normalizes `\` and `/` separators, and expands `~/` before evaluation.
- **Ancestor Symlink Walking:** Walks every ancestor using `symlink_metadata` + `canonicalize`, **failing closed** on dangling/unresolvable symlinks or any symlink whose target resolves inside a protected location.
- **Bounded Descendant Inspection:** `check_dir_descendants_safe()` walks directory contents with `follow_links(false)` and fails closed if any descendant is a symlink, unreadable, protected, or exceeds `max_entries`.

---

## 3. Redacted Secret Detection (`redact_secrets()`, Helper Shipped `M1`; Collector Wiring `M2` / `M3`)

The `redact_secrets()` helper is shipped in `crates/sj-core/src/lib.rs` and awaits collector integration as `memory` (`M2`) and `mcp-audit` (`M3`) land. Process and MCP configuration collectors will pass command lines through `redact_secrets()` **before** JSON serialization, logging, or UI rendering:

- **CLI Secret Flags:** `--api-key`, `--token`, `--secret`, `--password`, `--auth-token`, `--auth` (both `--flag=value` and `--flag value` forms) are replaced with `<REDACTED>`.
- **Authorization Headers:** `Bearer <token>` and `Basic <token>` values are replaced with `<REDACTED>`.
- **URL Userinfo:** `https://user:pass@host/...` credentials are replaced with `https://<REDACTED>@host/...`.

---

## 4. Desktop Sandbox, Process Spawning & Loopback SLM Guard *(Planned `M5` / `M6`)*

- **Electron Sandbox (`M5`):** Renderer windows run with `contextIsolation: true`, `nodeIntegration: false`, and `sandbox: true`, communicating only over a typed, allowlisted `preload` IPC bridge with a 2-step UI confirmation modal.
- **Zero Shell Interpolation (`M1` `git` / `M4` `sj serve-stdio`):** All subprocess invocations (`git` in `M1`, `sj serve-stdio` in `M4`) use `execFile` / `spawn` / `Command::new` with argument arrays (`shell: false`), eliminating command injection via filenames or branch names.
- **Loopback-Only Local SLM Guard (`M6`):** The optional Local SLM Advisor only connects to `127.0.0.1` / `localhost` (or a local GGUF file), receives only redacted summary metadata, and has **zero execution capability**. Every proposed target is re-validated by `sj-core`.

---

## 5. Repository Hygiene Gate

Every pull request runs:
- `node scripts/check-oss-hygiene.mjs` — blocks non-placeholder `/Users/<name>`, `/home/<name>`, `C:\Users\<name>`, RFC1918/CGNAT IPs, and credential prefixes.
- `gitleaks` — scans git history and working tree for leaked secrets.

---

## 6. Vulnerability Reporting (Responsible Disclosure)

Please report security vulnerabilities **privately** via **GitHub Security Advisories** (`https://github.com/adibirzu/spacejanitor/security/advisories/new`) rather than opening a public issue with exploit details. Include:
- Affected OS and architecture (`macOS`/`Linux`/`Windows`, `x64`/`arm64`)
- Reproduction steps or minimal proof-of-concept
- Potential impact (e.g., protected-path bypass, secret exposure, or privilege/execution gate bypass)
