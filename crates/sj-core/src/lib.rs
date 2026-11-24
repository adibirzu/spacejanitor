//! SpaceJanitor Rust core safety invariants, secret redaction, and schema contracts.

use std::path::Path;

pub const SCHEMA_STORAGE_V1: &str = "spacejanitor.storage.v1";
pub const SCHEMA_MEMORY_V1: &str = "spacejanitor.memory.v1";
pub const SCHEMA_BLOCKERS_V1: &str = "spacejanitor.blockers.v1";
pub const SCHEMA_ORPHANS_V1: &str = "spacejanitor.orphans.v1";
pub const SCHEMA_PROPOSAL_V1: &str = "spacejanitor.proposal.v1";

pub const PROTECTED_HOME_SUBPATHS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".config/gh",
];

pub const PROTECTED_SYSTEM_ROOTS: &[&str] = &[
    "/System",
    "/Windows",
    "C:/Windows",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionVerdict {
    pub protected: bool,
    pub reason: String,
}

fn normalize_separators(raw: &str) -> String {
    let trimmed = raw.trim().replace('\\', "/");
    if trimmed.len() > 1 {
        trimmed.trim_end_matches('/').to_string()
    } else {
        trimmed
    }
}

fn expand_home(raw: &str, home_dir: &str) -> String {
    let home = normalize_separators(home_dir);
    let norm = normalize_separators(raw);
    if norm == "~" {
        return home;
    }
    if let Some(rest) = norm.strip_prefix("~/") {
        return format!("{home}/{rest}");
    }
    norm
}

/// Evaluates whether `candidate` is protected by immutable built-in safety rules or user exact paths.
pub fn is_protected_path(candidate: &str, home_dir: &str, exact_paths: &[&str]) -> ProtectionVerdict {
    let home_norm = normalize_separators(home_dir);
    let cand = expand_home(candidate, &home_norm);
    if cand.is_empty() {
        return ProtectionVerdict {
            protected: true,
            reason: "empty_path".to_string(),
        };
    }

    if cand == "/" || cand == home_norm {
        return ProtectionVerdict {
            protected: true,
            reason: "protected_root".to_string(),
        };
    }

    for sys_root in PROTECTED_SYSTEM_ROOTS {
        let root_norm = normalize_separators(sys_root);
        if cand == root_norm || cand.starts_with(&format!("{root_norm}/")) {
            return ProtectionVerdict {
                protected: true,
                reason: format!("protected_system:{sys_root}"),
            };
        }
    }

    for sub in PROTECTED_HOME_SUBPATHS {
        let full = format!("{home_norm}/{sub}");
        if cand == full || cand.starts_with(&format!("{full}/")) {
            return ProtectionVerdict {
                protected: true,
                reason: format!("protected_credential_store:~/{sub}"),
            };
        }
    }

    for exact in exact_paths {
        let exact_norm = expand_home(exact, &home_norm);
        if exact_norm == "/" || exact_norm == home_norm {
            if cand == exact_norm {
                return ProtectionVerdict {
                    protected: true,
                    reason: format!("protected_exact:{exact}"),
                };
            }
        } else if cand == exact_norm || cand.starts_with(&format!("{exact_norm}/")) {
            return ProtectionVerdict {
                protected: true,
                reason: format!("protected_exact:{exact}"),
            };
        }
    }

    if let Some(name) = Path::new(&cand).file_name().and_then(|s| s.to_str()) {
        if name.contains(".private.") {
            return ProtectionVerdict {
                protected: true,
                reason: "protected_glob:*.private.*".to_string(),
            };
        }
    }

    ProtectionVerdict {
        protected: false,
        reason: String::new(),
    }
}

/// Redacts common `--flag=secret` and `Bearer <token>` segments from CLI strings before reporting.
pub fn redact_secrets(input: &str) -> String {
    let sensitive_flags = ["--api-key=", "--token=", "--secret=", "--password=", "--auth-token="];
    let mut tokens: Vec<String> = Vec::new();
    let mut redact_next = false;

    for part in input.split_whitespace() {
        if redact_next {
            tokens.push("<REDACTED>".to_string());
            redact_next = false;
            continue;
        }
        let low = part.to_ascii_lowercase();
        if let Some(flag) = sensitive_flags.iter().find(|f| low.starts_with(*f)) {
            tokens.push(format!("{flag}<REDACTED>"));
            continue;
        }
        if matches!(low.as_str(), "--api-key" | "--token" | "--secret" | "--password" | "--auth-token" | "bearer") {
            tokens.push(part.to_string());
            redact_next = true;
            continue;
        }
        tokens.push(part.to_string());
    }

    tokens.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HOME: &str = "/home/developer";

    #[test]
    fn protects_roots_and_credentials() {
        assert!(is_protected_path("/", TEST_HOME, &[]).protected);
        assert!(is_protected_path(TEST_HOME, TEST_HOME, &[]).protected);
        assert!(is_protected_path("~/.ssh/id_ed25519", TEST_HOME, &[]).protected);
        assert!(is_protected_path("/System/Library", TEST_HOME, &[]).protected);
        assert!(is_protected_path("/home/developer/notes.private.txt", TEST_HOME, &[]).protected);
        assert!(!is_protected_path("/home/developer/.cache/npm", TEST_HOME, &[]).protected);
    }

    #[test]
    fn redacts_cli_secret_flags() {
        let out = redact_secrets("node srv.js --api-key=dummy_val_123 --token secret_456");
        assert!(!out.contains("dummy_val_123"));
        assert!(!out.contains("secret_456"));
        assert!(out.contains("--api-key=<REDACTED>"));
        assert!(out.contains("--token <REDACTED>"));
    }
}
