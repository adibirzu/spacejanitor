//! Allowlist-based redaction for audit output.
//!
//! A token is echoed verbatim only when it is *clearly non-secret*: a flag name with no
//! value, a lowercase package/command word, a path under a known prefix, a short numeric or
//! boolean value, or a credential-free URL whose query values are themselves safe. Everything
//! else becomes `<REDACTED>`. Any token that follows an auth-ish marker (`Bearer`,
//! `Authorization:`, `--token`, `-p`, `-u`, `-t`, ...) is redacted. False-positive redaction
//! is acceptable; a leak is not.

use crate::{has_known_secret_prefix, is_sensitive_flag_name};

const RED: &str = "<REDACTED>";

/// Words that introduce a credential in the *next* token.
fn is_scheme_word(low: &str) -> bool {
    matches!(low, "bearer" | "basic" | "digest" | "token" | "negotiate")
}

fn is_auth_header_name(low: &str) -> bool {
    matches!(
        low.trim(),
        "authorization"
            | "proxy-authorization"
            | "x-api-key"
            | "x-auth-token"
            | "cookie"
            | "set-cookie"
    ) || low.contains("token")
        || low.contains("secret")
        || low.contains("api-key")
        || low.contains("apikey")
        || low.contains("password")
}

fn is_sensitive_env_name(k: &str) -> bool {
    let up = k.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "KEY",
        "PASS",
        "AUTH",
        "CREDENTIAL",
        "DSN",
        "SESSION",
        "COOKIE",
    ]
    .iter()
    .any(|n| up.contains(n))
}

/// Long mixed letter+digit runs or very long runs look like key material.
fn looks_high_entropy(s: &str) -> bool {
    if has_known_secret_prefix(s) {
        return true;
    }
    s.split(|c: char| !c.is_ascii_alphanumeric()).any(|seg| {
        let has_digit = seg.chars().any(|c| c.is_ascii_digit());
        let has_alpha = seg.chars().any(|c| c.is_ascii_alphabetic());
        (seg.len() >= 16 && has_digit && has_alpha) || seg.len() >= 32
    })
}

fn is_short_numeric_or_bool(s: &str) -> bool {
    (!s.is_empty() && s.len() <= 6 && s.chars().all(|c| c.is_ascii_digit()))
        || matches!(s, "true" | "false")
}

/// Lowercase package / command / simple value word: `npx`, `@scope/pkg@1.2.3`, `ubuntu:22.04`.
fn is_package_word(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars().all(|c| {
            c.is_ascii_lowercase()
                || c.is_ascii_digit()
                || matches!(c, '.' | '_' | '-' | '/' | '@' | ':' | '+' | '~')
        })
        && s.chars().any(|c| c.is_ascii_lowercase())
        && !s.contains("//")
        && !looks_high_entropy(s)
}

const KNOWN_PATH_PREFIXES: &[&str] = &[
    "/usr/",
    "/opt/",
    "/bin/",
    "/sbin/",
    "/etc/",
    "/var/",
    "/private/",
    "/tmp/",
    "/home/",
    "/Users/",
    "/Applications/",
    "/Library/",
    "/System/",
    "/nix/",
    "/snap/",
    "~/",
    "./",
    "../",
];

fn is_safe_path(s: &str) -> bool {
    let low_norm = s.replace('\\', "/");
    let known = KNOWN_PATH_PREFIXES.iter().any(|p| low_norm.starts_with(p)) || {
        let b = low_norm.as_bytes();
        b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'/'
    };
    known
        && !low_norm.contains("..\\")
        && low_norm.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '.' | '_' | '-' | '/' | '~' | '+' | '@' | ':' | '%')
        })
        && !looks_high_entropy(&low_norm)
}

fn is_safe_flag_name(f: &str) -> bool {
    let body = f.trim_start_matches('-');
    f.starts_with("--")
        && !body.is_empty()
        && body.len() <= 48
        && body.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        && !looks_high_entropy(body)
}

fn redact_url(tok: &str) -> String {
    let Some(si) = tok.find("://") else {
        return RED.to_string();
    };
    let scheme = &tok[..si];
    if !scheme
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return RED.to_string();
    }
    let after = &tok[si + 3..];
    let auth_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let authority = &after[..auth_end];
    let mut rest = &after[auth_end..];
    let mut out = format!("{scheme}://");
    let host = match authority.rfind('@') {
        Some(at) => {
            out.push_str("<REDACTED>@");
            &authority[at + 1..]
        }
        None => authority,
    };
    if host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
        && !looks_high_entropy(host)
    {
        out.push_str(host);
    } else {
        out.push_str(RED);
    }
    // path
    let path_end = rest.find(['?', '#']).unwrap_or(rest.len());
    let (path, tail) = rest.split_at(path_end);
    rest = tail;
    let segs: Vec<String> = path
        .split('/')
        .map(|seg| {
            if seg.is_empty()
                || (seg.len() <= 48
                    && seg.chars().all(|c| {
                        c.is_ascii_lowercase()
                            || c.is_ascii_digit()
                            || matches!(c, '.' | '_' | '-' | '@' | '~' | '+' | '%')
                    })
                    && !looks_high_entropy(seg)
                    && !is_sensitive_env_name(seg))
            {
                seg.to_string()
            } else {
                RED.to_string()
            }
        })
        .collect();
    out.push_str(&segs.join("/"));
    // query
    if let Some(q) = rest.strip_prefix('?') {
        let (query, frag) = match q.find('#') {
            Some(i) => (&q[..i], &q[i..]),
            None => (q, ""),
        };
        let pairs: Vec<String> = query
            .split('&')
            .map(|pair| match pair.split_once('=') {
                Some((k, v)) => {
                    let k_low = k.to_ascii_lowercase();
                    let key_ok = !k.is_empty()
                        && k.len() <= 40
                        && k.chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                        && !is_sensitive_env_name(&k_low)
                        && !k_low.contains("sig");
                    if key_ok
                        && (is_short_numeric_or_bool(v) || (is_package_word(v) && v.len() <= 24))
                    {
                        format!("{k}={v}")
                    } else if key_ok {
                        format!("{k}={RED}")
                    } else {
                        RED.to_string()
                    }
                }
                None => {
                    if pair.is_empty() || (is_package_word(pair) && pair.len() <= 24) {
                        pair.to_string()
                    } else {
                        RED.to_string()
                    }
                }
            })
            .collect();
        out.push('?');
        out.push_str(&pairs.join("&"));
        if !frag.is_empty() {
            out.push_str("#<REDACTED>");
        }
    } else if rest.starts_with('#') {
        out.push_str("#<REDACTED>");
    }
    out
}

/// Cross-token redaction state. Shared across the elements of an argv so that a credential
/// split from its marker by the JSON array (`["Authorization:", "Bearer", "X"]`) is caught.
#[derive(Debug, Default, Clone)]
pub struct RedactState {
    redact_next: bool,
    /// Plain-identifier name of the marker that armed `redact_next` (for finding labels).
    pub marker: String,
    /// Set when the most recent token was consumed as a credential value.
    pub consumed: bool,
}

impl RedactState {
    fn arm(&mut self, marker: &str) {
        self.redact_next = true;
        self.marker = if marker.len() <= 32
            && marker
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            && !looks_high_entropy(marker)
        {
            marker.to_string()
        } else {
            "cli-flag".to_string()
        };
    }
}

/// Redacts one argv element / shell word under `st`.
pub fn redact_token(tok: &str, st: &mut RedactState) -> String {
    st.consumed = false;
    if tok.is_empty() {
        return String::new();
    }
    let low = tok.to_ascii_lowercase();

    if st.redact_next {
        if is_scheme_word(&low) {
            return tok.to_string();
        }
        let is_flag = low.starts_with("--")
            && low.len() > 2
            && low[2..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic());
        if !is_flag {
            st.redact_next = false;
            st.consumed = true;
            return RED.to_string();
        }
        st.redact_next = false;
    }

    // whitespace-bearing token = quoted sub-command / header: redact each word
    if tok.chars().any(char::is_whitespace) {
        let (inner, pending) = redact_command_with_state(tok);
        if pending {
            st.arm("header");
        }
        return inner;
    }

    if tok.starts_with('-') {
        return redact_flag(tok, &low, st);
    }

    if is_scheme_word(&low) {
        st.arm(&low);
        return tok.to_string();
    }

    if tok.contains("://") {
        return redact_url(tok);
    }

    // KEY=VAL
    if let Some((k, v)) = tok.split_once('=') {
        let k_ok = !k.is_empty()
            && k.len() <= 48
            && k.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !looks_high_entropy(k);
        if !k_ok || v.is_empty() {
            return RED.to_string();
        }
        if is_sensitive_env_name(k) {
            return format!("{k}={RED}");
        }
        let mut inner = RedactState::default();
        let rv = redact_token(v, &mut inner);
        if inner.redact_next {
            st.arm(k);
        }
        return format!("{k}={rv}");
    }

    // Name:Value (headers, host:port, image:tag)
    if let Some((name, value)) = tok.split_once(':') {
        let name_low = name.to_ascii_lowercase();
        if is_auth_header_name(&name_low) {
            let val_low = value.trim().to_ascii_lowercase();
            if value.trim().is_empty() || is_scheme_word(&val_low) {
                st.arm(&name_low);
                return tok.to_string();
            }
            return format!("{name}:{RED}");
        }
    }

    if is_short_numeric_or_bool(tok) || is_package_word(tok) || is_safe_path(tok) {
        return tok.to_string();
    }
    RED.to_string()
}

fn redact_flag(tok: &str, low: &str, st: &mut RedactState) -> String {
    // split `--name=value` / `--name:value` at the first separator
    let sep = tok.find(['=', ':']);
    let (lhs, rhs, sep_ch) = match sep {
        Some(i) => (&tok[..i], Some(&tok[i + 1..]), tok.as_bytes()[i] as char),
        None => (tok, None, ' '),
    };
    let lhs_low = lhs.to_ascii_lowercase();
    let single_dash = !lhs.starts_with("--");

    // shell `-c` combinations carry no value
    if rhs.is_none() && matches!(lhs, "-lc" | "-ic" | "-lic" | "-ec" | "-xc") {
        return tok.to_string();
    }
    // glued short flag value: `-pSECRET`, `-Dapi.key=X`
    if single_dash && lhs.len() > 2 {
        let head: String = lhs.chars().take(2).collect();
        return format!("{head}{RED}");
    }

    let sensitive_flag = is_sensitive_flag_name(&lhs_low, rhs.is_some())
        || matches!(
            lhs_low.as_str(),
            "-p" | "-u" | "-t" | "--user" | "--username"
        );

    match rhs {
        Some(v) => {
            if sensitive_flag || !(is_safe_flag_name(lhs) || (single_dash && lhs.len() == 2)) {
                return format!("{lhs}{sep_ch}{RED}");
            }
            let mut inner = RedactState::default();
            let rv = redact_token(v, &mut inner);
            if inner.redact_next {
                st.arm(&lhs_low);
            }
            format!("{lhs}{sep_ch}{rv}")
        }
        None => {
            let _ = low;
            if single_dash {
                if lhs.len() == 2 && lhs.as_bytes()[1].is_ascii_alphabetic() {
                    if sensitive_flag {
                        st.arm(&lhs_low);
                    }
                    return tok.to_string();
                }
                return if lhs == "-" || lhs == "--" {
                    tok.to_string()
                } else {
                    RED.to_string()
                };
            }
            if lhs == "--" {
                return tok.to_string();
            }
            if sensitive_flag {
                st.arm(&lhs_low);
            }
            if !is_safe_flag_name(lhs) {
                return RED.to_string();
            }
            tok.to_string()
        }
    }
}

/// Splits a command line into shell-like words (quotes removed, remembering whether the
/// word had been quoted) — same dialect `redact_secrets` has always used.
fn split_words(input: &str) -> Vec<(String, Option<char>)> {
    crate::split_shell_like_tokens(input)
}

/// Returns the redacted command line and whether a credential is still pending after its end.
pub fn redact_command_with_state(input: &str) -> (String, bool) {
    let mut st = RedactState::default();
    let mut out: Vec<String> = Vec::new();
    for (word, quote) in split_words(input) {
        let red = redact_token(&word, &mut st);
        let needs_quote = red.chars().any(char::is_whitespace);
        out.push(match quote {
            Some(q) if red == word || needs_quote => format!("{q}{red}{q}"),
            _ if needs_quote => format!("\"{red}\""),
            _ => red,
        });
    }
    (out.join(" "), st.redact_next)
}

/// Allowlist redaction of a whole command line (process list, config `command`).
pub fn redact_command(input: &str) -> String {
    redact_command_with_state(input).0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> String {
        let mut st = RedactState::default();
        args.iter()
            .map(|a| redact_token(a, &mut st))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn r3_probes_never_survive_in_any_shape() {
        let cmds = [
            "bash -lc 'npx some-mcp --token PROBE_A1'",
            "sh -c \"npx mcp --token PROBE_A2\"",
            "OPTS=-pPROBE_A3 node x.js",
            "JAVA_OPTS=-Dapi.key=PROBE_A4 java -jar x.jar",
            "tool --token:PROBE_A5=",
            "tool --header=Authorization:Bearer PROBE_A6",
            "tool --header=\"Authorization: Bearer PROBE_A7\"",
            "tool -H Authorization: Bearer PROBE_A8",
            "tool Bearer PROBE_A9",
            "tool --auth Bearer PROBE_B1",
            "tool -u PROBE_B2 -p PROBE_B3 -t PROBE_B4",
            "tool X=PROBE_B5 --flag PROBE_B6",
            "powershell -Command \"npx mcp --api-key PROBE_B7\"",
            "tool https://u:PROBE_B8@host.example/p?q=PROBE_B9&page=2",
            "tool https://host.example/mcp/PROBE_C1/sse",
            "tool --url=https://host.example/x?sig=PROBE_C2",
            "bash -lc 'npx -pPROBE_C3'",
        ];
        for c in cmds {
            let out = redact_command(c);
            assert!(!out.contains("PROBE_"), "leak in {c:?} -> {out:?}");
        }
    }

    #[test]
    fn split_credentials_across_argv_elements_are_redacted() {
        for args in [
            vec!["--header", "Authorization:", "Bearer", "PROBE_S1"],
            vec!["--header", "Authorization: Bearer", "PROBE_S2"],
            vec!["--auth", "Bearer", "PROBE_S3"],
            vec!["Bearer", "PROBE_S4"],
            vec!["--header=Authorization:Bearer", "PROBE_S5"],
            vec!["-H", "Cookie:", "PROBE_S6"],
        ] {
            let out = argv(&args);
            assert!(!out.contains("PROBE_"), "leak in {args:?} -> {out:?}");
        }
    }

    #[test]
    fn clearly_non_secret_tokens_stay_readable() {
        let out = redact_command(
            "/usr/bin/node /home/developer/app/srv.js --port 8080 --verbose --log-level=debug npx -y @scope/pkg@1.2.3 page=2",
        );
        for keep in [
            "/usr/bin/node",
            "--port 8080",
            "--verbose",
            "--log-level=debug",
            "@scope/pkg@1.2.3",
        ] {
            assert!(out.contains(keep), "{keep} missing in {out}");
        }
    }

    #[test]
    fn unknown_shapes_fail_closed() {
        for odd in [
            "Zm9vYmFyYmF6cXV4",
            "ABCDEF1234567890ABCDEF",
            "k3y_Value-9",
            "x=Y_Z9",
        ] {
            let out = redact_command(odd);
            assert!(
                out.contains(RED) && !out.contains("Y_Z9") && !out.contains("Zm9v"),
                "{odd} -> {out}"
            );
        }
    }
}
