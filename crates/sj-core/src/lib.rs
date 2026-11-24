//! SpaceJanitor Rust core safety invariants, disk scanner, trash discovery,
//! orphan git validator, and deterministic dry-run remediation planner.

pub mod blockers;
pub mod mcp_audit;
pub mod memory;
pub mod orphans;
pub mod plan;
pub mod protect;
pub mod reap;
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

fn redact_url_query_params(token: &str) -> String {
    let Some(q_idx) = token.find('?') else {
        return token.to_string();
    };
    let (base, query_and_frag) = token.split_at(q_idx + 1);
    let (query, frag) = match query_and_frag.find('#') {
        Some(f_idx) => (&query_and_frag[..f_idx], &query_and_frag[f_idx..]),
        None => (query_and_frag, ""),
    };
    let mut parts = Vec::new();
    for pair in query.split('&') {
        if let Some((k, _v)) = pair.split_once('=') {
            let k_low = k.to_ascii_lowercase();
            if matches!(
                k_low.as_str(),
                "api_key"
                    | "apikey"
                    | "token"
                    | "secret"
                    | "access_token"
                    | "key"
                    | "password"
                    | "passwd"
                    | "auth"
                    | "auth_token"
                    | "client_secret"
            ) {
                parts.push(format!("{k}=<REDACTED>"));
                continue;
            }
        }
        parts.push(pair.to_string());
    }
    format!("{base}{}{frag}", parts.join("&"))
}

fn split_shell_like_tokens(input: &str) -> Vec<(String, Option<char>)> {
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

fn is_sensitive_header_name(header_low: &str) -> bool {
    matches!(
        header_low.trim(),
        "authorization" | "x-api-key" | "x-auth-token" | "cookie" | "proxy-authorization"
    )
}

fn redact_header_value(raw: &str) -> Option<String> {
    let (hdr, _val) = raw.split_once(':')?;
    if is_sensitive_header_name(&hdr.to_ascii_lowercase()) {
        Some(format!("{hdr}: <REDACTED>"))
    } else {
        None
    }
}

fn has_known_secret_prefix(tok: &str) -> bool {
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

/// Redacts common secret flags, headers, inline `KEY=VAL`, URL credentials/query params, and known token prefixes.
pub fn redact_secrets(input: &str) -> String {
    let mut tokens: Vec<String> = Vec::new();
    let mut redact_next = false;
    let mut redact_next_header = false;

    for (part, outer_quote) in split_shell_like_tokens(input) {
        let low = part.to_ascii_lowercase();

        if redact_next_header {
            redact_next_header = false;
            if let Some((hdr, rest)) = part.split_once(':') {
                if is_sensitive_header_name(&hdr.to_ascii_lowercase()) {
                    if rest.trim().is_empty() {
                        tokens.push(part);
                        redact_next = true;
                        continue;
                    }
                    let redacted_hdr = format!("{hdr}: <REDACTED>");
                    tokens.push(match outer_quote {
                        Some(q) => format!("{q}{redacted_hdr}{q}"),
                        None => redacted_hdr,
                    });
                    continue;
                }
            }
        }

        if redact_next {
            if matches!(low.as_str(), "bearer" | "basic") {
                tokens.push(part);
                continue;
            }
            if !part.starts_with("--") {
                tokens.push("<REDACTED>".to_string());
                redact_next = false;
                continue;
            }
            redact_next = false;
        }

        if matches!(low.as_str(), "-h" | "--header") {
            tokens.push(part);
            redact_next_header = true;
            continue;
        }

        if let Some(after_hdr) = low.strip_prefix("--header=") {
            let _ = after_hdr;
            let raw_val = &part["--header=".len()..];
            if let Some(redacted_hdr) = redact_header_value(raw_val) {
                tokens.push(format!("--header=\"{redacted_hdr}\""));
                continue;
            }
        }

        if part.starts_with('-') {
            if let Some((lhs, _rhs)) = part.split_once('=') {
                if is_sensitive_flag_name(&lhs.to_ascii_lowercase(), true) {
                    tokens.push(format!("{lhs}=<REDACTED>"));
                    continue;
                }
            } else if is_sensitive_flag_name(&low, false) {
                tokens.push(part);
                redact_next = true;
                continue;
            }
        }

        if matches!(low.as_str(), "bearer" | "basic") {
            tokens.push(part);
            redact_next = true;
            continue;
        }

        if !part.starts_with('-') && !part.contains("://") {
            if let Some((k, v)) = part.split_once('=') {
                if !k.is_empty() && !k.contains(['/', ':', '?']) {
                    let k_up = k.to_ascii_uppercase();
                    if k_up.contains("TOKEN")
                        || k_up.contains("SECRET")
                        || k_up.contains("KEY")
                        || k_up.contains("PASSWORD")
                        || k_up.contains("PASSWD")
                        || k_up.contains("AUTH")
                        || k_up.contains("CREDENTIAL")
                        || k_up.contains("DSN")
                    {
                        if v.trim() != "<REDACTED>" {
                            tokens.push(format!("{k}=<REDACTED>"));
                        } else {
                            tokens.push(part);
                        }
                        continue;
                    }
                }
            }
        }

        if has_known_secret_prefix(&part) {
            tokens.push("<REDACTED>".to_string());
            continue;
        }

        let url_clean = redact_url_query_params(&redact_url_userinfo(&part));
        tokens.push(match outer_quote {
            Some(q) if url_clean == part => format!("{q}{url_clean}{q}"),
            _ => url_clean,
        });
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
