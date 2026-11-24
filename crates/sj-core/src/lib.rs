//! SpaceJanitor Rust core safety invariants, disk scanner, trash discovery,
//! orphan git validator, and deterministic dry-run remediation planner.

pub mod orphans;
pub mod plan;
pub mod protect;
pub mod safe_remove;
pub mod scan;
pub mod trash;

use thiserror::Error;

pub const SCHEMA_STORAGE_V1: &str = "spacejanitor.storage.v1";
pub const SCHEMA_MEMORY_V1: &str = "spacejanitor.memory.v1";
pub const SCHEMA_BLOCKERS_V1: &str = "spacejanitor.blockers.v1";
pub const SCHEMA_ORPHANS_V1: &str = "spacejanitor.orphans.v1";
pub const SCHEMA_TRASH_V1: &str = "spacejanitor.trash.v1";
pub const SCHEMA_PROPOSAL_V1: &str = "spacejanitor.proposal.v1";

pub use protect::{
    is_protected_path, ProtectionVerdict, PROTECTED_HOME_SUBPATHS, PROTECTED_SYSTEM_ROOTS,
};

#[derive(Debug, Error)]
pub enum SjError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protected path refused: {0}")]
    ProtectedPath(String),
    #[error("invalid execution gate: {0}")]
    ExecutionGate(String),
    #[error("git command error: {0}")]
    Git(String),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

fn redact_url_userinfo(token: &str) -> String {
    if let Some(scheme_idx) = token.find("://") {
        let after_scheme = &token[scheme_idx + 3..];
        let auth_end = after_scheme
            .find(['/', '?', '#'])
            .unwrap_or(after_scheme.len());
        let authority = &after_scheme[..auth_end];
        if let Some(at_idx) = authority.rfind('@') {
            let prefix = &token[..scheme_idx + 3];
            let host_and_rest = &after_scheme[at_idx + 1..];
            return format!("{prefix}<REDACTED>@{host_and_rest}");
        }
    }
    token.to_string()
}

/// Redacts common `--flag=secret`, `Bearer`/`Basic <token>`, and URL userinfo segments before reporting.
pub fn redact_secrets(input: &str) -> String {
    let sensitive_flags = [
        "--api-key=",
        "--token=",
        "--secret=",
        "--password=",
        "--auth-token=",
        "--auth=",
    ];
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
        if matches!(
            low.as_str(),
            "--api-key"
                | "--token"
                | "--secret"
                | "--password"
                | "--auth-token"
                | "--auth"
                | "bearer"
                | "basic"
        ) {
            tokens.push(part.to_string());
            redact_next = true;
            continue;
        }
        tokens.push(redact_url_userinfo(part));
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

    #[test]
    fn redacts_auth_basic_and_url_userinfo() {
        let out = redact_secrets(
            "curl --auth=tok_abc --auth tok_def -H Authorization: Basic bXlfdG9rZW4= https://alice:s3cr3t@example.com/repo.git https://example.com/@org/pkg",
        );
        assert!(!out.contains("tok_abc"));
        assert!(!out.contains("tok_def"));
        assert!(!out.contains("bXlfdG9rZW4="));
        assert!(!out.contains("s3cr3t"));
        assert!(out.contains("--auth=<REDACTED>"));
        assert!(out.contains("--auth <REDACTED>"));
        assert!(out.contains("Basic <REDACTED>"));
        assert!(out.contains("https://<REDACTED>@example.com/repo.git"));
        assert!(out.contains("https://example.com/@org/pkg"));
    }
}
