# ADR-004: Zero-Leak Privacy & Two-Step Remediation Gate

- **Status:** Accepted and implemented (selection-bound gate, Unix-only removal)
- **Date:** 2026-11-24
- **Drivers:** MIT open-source hygiene, defense against accidental deletion or process termination, secret safety.

---

## Context

System cleanup tools inspect sensitive locations: user home directories, git repository names, command-line flags of running processes, and environment configs. A public MIT tool must guarantee both **runtime privacy** (zero telemetry, redacted outputs) and **repository privacy** (zero developer identities or secrets in code/tests), alongside **fail-closed execution safety**.

## Decision

### 1. Dry-Run Default & Two-Step Execution Gate
- **Zero mutations by default:** Running `spacejanitor remediate` or clicking cleanup in the UI only produces a deterministic `RemediationPlan` with SHA-256 plan digest and estimated reclaimable bytes/processes.
- **CLI execution gate:** Requires `--execute`, an explicit tier/scope confirmation flag (`--confirm-tier1` / `--confirm-memory`), and explicit `--item <rule_id>` selectors for high-impact Tier 2 or process kills.
- **UI execution gate:** Requires a single-use, time-bounded (`5 min`) confirmation token bound to the exact plan digest and target host ID, typed confirmation phrase for destructive actions, and an in-process mutex preventing concurrent runs on the same host.

### 2. Automatic Secret Redaction at Collector Boundaries
- All process argument inspectors pass command lines through `redactSecrets()` in `packages/core` before storing, logging, or rendering JSON/UI output.
- Redacted patterns include bearer headers, `Authorization` tokens, `--api-key=...` / `--token=...` / `--password=...` CLI flags, and known vendor prefixes.

### 3. Mandatory Repository Hygiene Gate (`check-oss-hygiene.mjs` + `gitleaks`)
- Every commit and CI pull request runs both `gitleaks` and `scripts/check-oss-hygiene.mjs` to block non-placeholder user home directories (`/Users/<name>`, `/home/<name>`, `C:\Users\<name>`), RFC1918/CGNAT IPs, and credential prefixes.
- Operator-specific blocklists are supported out-of-tree via `--extra-blocklist <path>` or `OSS_HYGIENE_BLOCKLIST` so private terms are never committed to the open-source tree.

## Consequences

- **Positive:** Safe to run unattended in scheduled audits, safe to publish under MIT, and resistant to accidental secret exposure via process lists.
- **Negative / Mitigation:** Requires two explicit clicks/flags to actually free space or kill leaked processes; this friction is intentional and documented as a core safety guarantee.

---

## Implementation Status (as of `main`)

| Decision area | State |
|---|---|
| Zero telemetry; local only | Implemented |
| Redaction before output | Implemented as a closed vocabulary (`redact.rs`, `redact_catalog.json`); applies to `mcp-audit`, `llm-audit`, `reap`, `memory`, `serve-stdio` |
| Two-step confirmation | Implemented and **bound to the user's selection**: `selection_sha256` from `sj plan --select`, `--execute --confirm --selection-sha256`, plus desktop phrase, 5-minute TTL, single use, mutex |
| Single protection owner | Rust `sj` only; the Node denylist was removed and callers fail closed |
| Hygiene gates | `scripts/check-oss-hygiene.mjs` and gitleaks in CI |
| Handle-anchored, no-follow removal | Implemented for macOS and Linux; Windows plans only |

Git-proof hardening is tracked in [#12](https://github.com/adibirzu/spacejanitor/issues/12).
