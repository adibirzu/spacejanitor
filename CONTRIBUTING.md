# Contributing to SpaceJanitor

Thank you for contributing to SpaceJanitor! All contributions are licensed under the [MIT License](./LICENSE).

## Local Checks Before Every Pull Request

Run the built-in test suite, OSS hygiene gate, and CLI diagnostics before committing:

```bash
npm test
npm run hygiene
node packages/cli/bin/spacejanitor.mjs doctor --json
```

## Contribution Rules

1. **Test-first changes:** Add or update tests under `packages/*/test/` demonstrating new safety rules, collector parsers, or plugin validations.
2. **Never weaken safety gates:** Protected path checks, git clean/pushed verification, and two-step remediation confirmations are invariant across platforms.
3. **Keep core cross-platform:** OS-specific collectors belong behind explicit platform adapters (`darwin`, `linux`, `win32`) supporting both `x86_64` and `arm64`.
4. **No personal paths or private endpoints:** Use generic placeholders (`alice`, `developer`, `192.0.2.10`) in docs and tests. CI rejects non-placeholder `/Users/<name>`, `/home/<name>`, private IPs, and secret patterns.
5. **No shell heredocs in tooling:** Keep scripts portable across macOS, Linux, and Windows PowerShell.
