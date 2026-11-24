# Security Policy

## Threat Model & Safety Guarantees

SpaceJanitor inspects local filesystems, git worktrees, running process arguments, and memory counters, and optionally cleans approved targets. Because a system janitor handles high-privilege diagnostics and destructive cleanup actions, SpaceJanitor enforces these invariants by design:

1. **Read-Only Default:** All audit commands, collectors, and dry-run previews execute zero file deletions, zero git mutations, and zero process signals.
2. **Two-Step Execution Gate:** Any destructive action requires explicit confirmation flags in the CLI or a two-step typed confirmation + single-use time-bounded token in the UI.
3. **Immutable Protected-Path Denylist:** Rules in `packages/core` block removal of SSH keys, GPG keyrings, cloud credential directories, active working directories, and user-declared protected globs—even if a plugin rule explicitly targets them.
4. **CLI Argument Secret Redaction:** Process inspection collectors (`ps`, `/proc`, WMI/CIM) automatically redact bearer tokens, API key patterns, and inline secret flags before serialization or UI rendering.
5. **Local-First Execution:** SpaceJanitor sends zero analytics, telemetry, or crash reports to external servers.
6. **Zero Private Data in Repository:** CI enforces `gitleaks` and `scripts/check-oss-hygiene.mjs` on every pull request so user home directories, private IPs, and tokens never enter version control.

## Reporting a Vulnerability

Please report security issues privately via GitHub Security Advisories rather than opening a public issue with exploit details. Include reproduction steps, affected OS/architecture, and potential impact.
