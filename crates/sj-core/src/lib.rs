//! SpaceJanitor Rust core safety invariants, disk scanner, trash discovery,
//! orphan git validator, and deterministic dry-run remediation planner.

pub mod blockers;
pub mod llm_audit;
pub mod mcp_audit;
pub mod memory;
pub mod orphans;
pub mod plan;
pub mod protect;
pub mod reap;
pub mod redact;
pub(crate) mod safe_remove;
pub mod scan;
pub mod trash;

use thiserror::Error;

pub const SCHEMA_STORAGE_V1: &str = "spacejanitor.storage.v1";
pub const SCHEMA_DISK_V1: &str = "spacejanitor.disk.v1";
pub const SCHEMA_MEMORY_V1: &str = "spacejanitor.memory.v1";
pub const SCHEMA_BLOCKERS_V1: &str = "spacejanitor.blockers.v1";
pub const SCHEMA_ORPHANS_V1: &str = "spacejanitor.orphans.v1";
pub const SCHEMA_TRASH_V1: &str = "spacejanitor.trash.v1";
pub const SCHEMA_PROPOSAL_V1: &str = "spacejanitor.proposal.v1";
pub const SCHEMA_PROTECT_V1: &str = "spacejanitor.protect.v1";
pub const SCHEMA_MCP_AUDIT_V1: &str = "spacejanitor.mcp_audit.v1";
pub const SCHEMA_REAP_V1: &str = "spacejanitor.reap.v1";

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

pub(crate) fn split_shell_like_tokens(input: &str) -> Vec<(String, Option<char>)> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut outer_quote: Option<char> = None;
    let mut escaped = false;

    for ch in input.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        match (quote, ch) {
            (Some('"'), '\\') => escaped = true,
            (Some(q), c) if c == q => {
                quote = None;
            }
            (Some(_), c) => cur.push(c),
            (None, '"') | (None, '\'') => {
                if cur.is_empty() && outer_quote.is_none() {
                    outer_quote = Some(ch);
                }
                quote = Some(ch);
            }
            (None, c) if c.is_whitespace() => {
                if !cur.is_empty() || outer_quote.is_some() {
                    tokens.push((std::mem::take(&mut cur), outer_quote.take()));
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if !cur.is_empty() || outer_quote.is_some() {
        tokens.push((cur, outer_quote));
    }
    tokens
}

pub fn is_sensitive_flag_name(flag_low: &str, has_equals: bool) -> bool {
    if matches!(
        flag_low,
        "-t" | "-p"
            | "--api-key"
            | "--apikey"
            | "--api_key"
            | "--token"
            | "--access-token"
            | "--secret"
            | "--client-secret"
            | "--password"
            | "--passwd"
            | "--pwd"
            | "--auth-token"
            | "--auth"
            | "--bearer"
            | "--private-key"
    ) {
        return true;
    }
    if !flag_low.starts_with("--") {
        return false;
    }
    if !has_equals
        && (flag_low.ends_with("-verify")
            || flag_low.ends_with("-check")
            || flag_low.ends_with("-only")
            || flag_low.ends_with("-less")
            || flag_low.ends_with("-enabled")
            || flag_low.ends_with("-disabled"))
    {
        return false;
    }
    flag_low.contains("token")
        || flag_low.contains("secret")
        || flag_low.contains("key")
        || flag_low.contains("pass")
        || flag_low.contains("auth")
        || flag_low.contains("credential")
        || flag_low.contains("dsn")
}

pub(crate) fn has_known_secret_prefix(tok: &str) -> bool {
    tok.starts_with("sk-")
        || tok.starts_with("sk_")
        || tok.starts_with("ghp_")
        || tok.starts_with("github_pat_")
        || tok.starts_with("glpat-")
        || tok.starts_with("xoxb-")
        || tok.starts_with("xoxp-")
        || tok.starts_with("AKIA")
        || tok.starts_with("AIza")
}

/// Redacts a command line for audit output using an allowlist: only clearly non-secret
/// tokens are shown, everything else (and anything after an auth-ish marker) is `<REDACTED>`.
pub fn redact_secrets(input: &str) -> String {
    redact::redact_command(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_f3_widened_allowlist_covers_probe_leaks() {
        let cases = [
            "npx mcp-remote https://h/x --header Authorization:Bearer PROBE07zz",
            "npx mcp-remote https://h/x --header Authorization:Basic PROBE08zz",
            "tool --token:PROBE80zz next",
            "mysql -pPROBE81zz",
            "npx -y mcp-remote https://mcp.exa.ai/mcp?exaApiKey=PROBE84zz",
            "curl https://h/x?access_key=PROBE85zz&ok=1",
            "curl https://h/x?sig=PROBE86zz&client_secret_v2=PROBE87zz",
            "curl https://h/x?X-Amz-Signature=PROBE88zz",
        ];
        for c in cases {
            let out = redact_secrets(c);
            assert!(!out.contains("PROBE"), "leak in {c:?} -> {out:?}");
        }
        // non-sensitive query params and flags stay readable
        let keep = redact_secrets("curl https://h/x?page=2&sort=asc --verbose");
        assert!(
            keep.contains("page=2") && keep.contains("sort=asc"),
            "{keep}"
        );
    }

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

    #[test]
    fn redacts_expanded_secret_flags_headers_env_urls_and_prefixes() {
        let akia_probe = ["AKIA", "000000000000TEST"].concat();
        let cmd = format!(
            concat!(
                "my-cli --access-token tok_access --apikey=ak_123 --api_key ak_456 ",
                "--client-secret cs_789 --password 'pw with space' --passwd=pw2 --pwd pw3 ",
                "--bearer br_1 --private-key pk_1 -t short_t -p short_p ",
                "--custom-token-val=ct_1 --my-secret=ms_1 ",
                "-H \"Authorization: Bearer hdr_tok_1\" ",
                "-H \"X-Api-Key: hdr_key_2\" ",
                "-H \"X-Auth-Token: hdr_auth_3\" ",
                "-H \"Cookie: session=hdr_cookie_4\" ",
                "-H \"Proxy-Authorization: Basic hdr_proxy_5\" ",
                "MY_APP_SECRET=inline_sec_1 DATABASE_DSN=postgres://dbuser:dbpass@db.internal:5432/app ",
                "https://api.example.com/v1?api_key=q_ak&token=q_tok&secret=q_sec&access_token=q_acc&key=q_key ",
                "sk-live-12345 ghp_abcdef123456 github_pat_12345 glpat-12345 xoxb-12345 xoxp-12345 {} AIzaSyDummyKey123"
            ),
            akia_probe
        );
        let out = redact_secrets(&cmd);
        for probe in [
            "tok_access",
            "ak_123",
            "ak_456",
            "cs_789",
            "pw with space",
            "pw2",
            "pw3",
            "br_1",
            "pk_1",
            "short_t",
            "short_p",
            "ct_1",
            "ms_1",
            "hdr_tok_1",
            "hdr_key_2",
            "hdr_auth_3",
            "hdr_cookie_4",
            "hdr_proxy_5",
            "inline_sec_1",
            "dbpass",
            "q_ak",
            "q_tok",
            "q_sec",
            "q_acc",
            "q_key",
            "sk-live-12345",
            "ghp_abcdef123456",
            "github_pat_12345",
            "glpat-12345",
            "xoxb-12345",
            "xoxp-12345",
            akia_probe.as_str(),
            "AIzaSyDummyKey123",
        ] {
            assert!(
                !out.contains(probe),
                "secret probe leaked: {probe} in {out}"
            );
        }
        assert!(out.contains("Authorization:"));
        assert!(out.contains("X-Api-Key:"));
        assert!(out.contains("X-Auth-Token:"));
        assert!(out.contains("Cookie:"));
        assert!(out.contains("Proxy-Authorization:"));
    }
}
