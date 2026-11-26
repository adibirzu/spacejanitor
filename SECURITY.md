# Security Policy

## Threat Model & Safety Guarantees

SpaceJanitor inspects local filesystems, git worktrees, running process arguments, and memory counters, and optionally cleans approved targets. Because a system janitor handles high-privilege diagnostics and destructive cleanup actions, SpaceJanitor enforces these invariants by design:

1. **Read-Only Default:** (orphan-repo scanning, which runs git inside repositories found on disk, is a separate opt-in, see Known limitations) All audit commands, collectors, and dry-run previews execute zero file deletions, zero git mutations, and zero process signals.
2. **Two-Step Execution Gate:** Any destructive action requires explicit confirmation flags in the CLI or a two-step typed confirmation + single-use time-bounded token in the UI.
3. **Immutable Protected-Path Denylist:** Rules in `packages/core` block removal of SSH keys, GPG keyrings, cloud credential directories, active working directories, and user-declared protected globs—even if a plugin rule explicitly targets them.
4. **CLI Argument Secret Redaction:** Process inspection collectors (`ps`, `/proc`, WMI/CIM) automatically redact bearer tokens, API key patterns, and inline secret flags before serialization or UI rendering.
5. **Local-First Execution:** SpaceJanitor sends zero analytics, telemetry, or crash reports to external servers.
6. **Zero Private Data in Repository:** CI enforces `gitleaks` and `scripts/check-oss-hygiene.mjs` on every pull request so user home directories, private IPs, and tokens never enter version control.

## Known limitations (security-relevant)

- **Orphan-repo scanning is OFF by default (experimental).** Finding and pruning orphan git worktrees runs `git` (status, ls-remote, config reads, worktree remove) inside repositories found on disk, including repositories SpaceJanitor did not create. An independent review showed a repository's own configuration can still steer that git in ways our proofs do not yet block:
  - **B35:** a clean filter in a submodule's own config can still run during the read-only status proof.
  - **B36:** repository `http.<url>.proxy` plus disabled TLS verification can redirect `ls-remote` credentials.
  - **B37:** timeouts and budgets are not a hard contract (a stalled remote or a FIFO at `.git/config` can hang a scan).

  Tracked in [issue #12](https://github.com/adibirzu/spacejanitor/issues/12). The Rust core now runs its git proofs with a scrubbed environment and config (no inherited config, proxy, credential helper or hooks), blocks repositories with submodules or any `http.*` config, kills the whole git process group on timeout, and enforces a scan-wide deadline; it stays opt-in until the remaining items in the issue (bare-repo worktrees, over-blocking, 3,000-ref cap) are done. By default no git command touches any repository (`doctor` only runs `git --version`). Until that is fixed, opt in only for repositories you trust: `spacejanitor orphans --include-orphans`, `sj orphans --include-orphans`, `sj plan --include-orphans`, or the explicit toggle in the desktop app (Disk view). Every opt-in prints or shows a warning. When scanning is off, the desktop app shows orphan worktrees as "not scanned (disabled by default)", never as "no orphans". Trash and cache cleanup, the two-step confirmation gate, the protected-path denylist, redaction, MCP audit and the SLM advisor are unaffected.

## Audit Output Vocabulary (mcp-audit, llm-audit, reap, memory, serve-stdio)

Audit output is built from a closed vocabulary, not from judging whether text looks secret. Free text from process lists and config files never reaches the output unless it is in a fixed catalog (`crates/sj-core/data/redact_catalog.json`) or reduced to a hash:

- Commands, launchers and clients: catalog only, otherwise `<command>`. Package ids after a launcher: catalog only, otherwise `<package:hash8>`. Flag names: catalog only, otherwise `<flag>`; flag values are always `<REDACTED>`.
- URLs: `http|https|ws|wss` scheme plus a dotted DNS host only; never userinfo, path or query. Anything else is `<url>`.
- Env and header key names: fixed known-safe list only; every other key is counted, never named.
- Live-process labels (`server_name`, `owning_client`): the label of a config entry the process matches, a catalog package or client, otherwise `unknown-<first 8 hex of sha256(argv)>`. Never a substring of argv.
- `secret_findings` are emitted only for a real secret signal (a secret-named flag or env key, or a known token prefix, case-insensitive), not for every redacted value.
- **Config server labels are user-chosen and are shown.** A label is displayed only if it is at most 32 characters, `[a-z0-9._-]`, with no alphanumeric run over 12; otherwise it becomes `server-<hash8>`. Do not use a secret, token or key as a server label: a short, plain value would be displayed as written.
- Config files are opened once without following symlinks, validated on the opened handle (regular file, inside the home for default discovery, never inside a protected root), and read from that handle. `--config-dir` on a protected root yields a single `protected_target` warning and no listing.

## Reporting a Vulnerability

Please report security issues privately via GitHub Security Advisories rather than opening a public issue with exploit details. Include reproduction steps, affected OS/architecture, and potential impact.
