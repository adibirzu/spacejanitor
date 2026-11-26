//! Closed-vocabulary redaction for every audit output path (mcp-audit, llm-audit, reap, memory,
//! serve-stdio, `secret_findings[].key_name`, any `command` field, any derived label).
//!
//! Three rounds of judging whether a value *looks* secret (denylist, heuristic allowlist,
//! shape grammar) still leaked. This module therefore never judges shapes. Every free-text
//! field is either a member of a fixed vocabulary (`data/redact_catalog.json`) or a hash:
//!
//! - command basename / launcher: catalog only, else `<command>`
//! - package id after a launcher: catalog only, else `<package:hash8>`
//! - flag names: catalog only, else `<flag>`; values are always `<REDACTED>`
//! - URL: `http|https|ws|wss` scheme and a dotted DNS host only, else `<url>`
//! - env / header key names: catalog only; everything else is counted, never named
//! - config server labels: shown only if tiny and plain (a user-chosen label, so secrets must
//!   not be used as labels, see SECURITY.md), else `server-<hash8>`
//! - labels inferred from live processes: a config entry's label, a catalog package or
//!   client, else `unknown-<hash8 of argv>`; never a substring of argv
//!
//! Over-redaction is accepted; unrecognised text has no path to the output.

use crate::split_shell_like_tokens;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

pub const RED: &str = "<REDACTED>";
const MAX_DEPTH: usize = 4;

/// One redacted argv element / shell word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedArg {
    pub text: String,
    /// True when information was withheld from this element.
    pub redacted: bool,
    /// Fixed-vocabulary label, safe for `secret_findings[].key_name`.
    pub label: String,
    /// True only for a real secret signal (secret-named flag/env, known token prefix).
    pub secret: bool,
}

// ---------------------------------------------------------------- catalog

#[derive(Deserialize)]
struct RawCatalog {
    commands: Vec<String>,
    clients: Vec<String>,
    packages: Vec<String>,
    bool_flags: Vec<String>,
    value_flags: Vec<String>,
    win_flags: Vec<String>,
    keys: Vec<String>,
    process_words: Vec<String>,
}

struct Catalog {
    commands: BTreeSet<String>,
    clients: Vec<String>,
    /// lowercase package id -> canonical package id
    packages: BTreeMap<String, String>,
    /// canonical flag text; `--x` matched case-insensitively, `-x` exactly
    flags: BTreeSet<String>,
    bool_flags: BTreeSet<String>,
    win_flags: BTreeSet<String>,
    /// lowercase key -> canonical key
    keys: BTreeMap<String, String>,
    process_words: BTreeSet<String>,
}

fn catalog() -> &'static Catalog {
    static C: OnceLock<Catalog> = OnceLock::new();
    C.get_or_init(|| {
        let raw: RawCatalog = serde_json::from_str(include_str!("../data/redact_catalog.json"))
            .expect("redact_catalog.json is valid");
        Catalog {
            commands: raw.commands.into_iter().collect(),
            clients: raw.clients,
            packages: raw
                .packages
                .into_iter()
                .map(|p| (p.to_ascii_lowercase(), p))
                .collect(),
            flags: raw
                .bool_flags
                .iter()
                .chain(raw.value_flags.iter())
                .cloned()
                .collect(),
            bool_flags: raw.bool_flags.into_iter().collect(),
            win_flags: raw.win_flags.into_iter().collect(),
            keys: raw
                .keys
                .into_iter()
                .map(|k| (k.to_ascii_lowercase(), k))
                .collect(),
            process_words: raw.process_words.into_iter().collect(),
        }
    })
}

/// First 8 hex chars of `sha256(input)`.
pub fn hash8(input: &str) -> String {
    let d = Sha256::digest(input.as_bytes());
    d.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// `unknown-<hash8(argv)>`: the only label for a process that matches nothing known.
pub fn unknown_label(argv: &str) -> String {
    format!("unknown-{}", hash8(argv))
}

/// Case-insensitive known token prefixes (vendor key shapes seen in real leaks).
const SECRET_PREFIXES: &[&str] = &[
    "sk-",
    "sk_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxa-",
    "xoxb-",
    "xoxp-",
    "xoxs-",
    "xoxr-",
    "xapp-",
    "akia",
    "asia",
    "aiza",
    "hf_",
    "npm_",
    "rk_live_",
    "rk_test_",
    "pk_live_",
    "pk_test_",
    "whsec_",
    "ya29.",
    "eyj",
    "pypi-",
    "dop_v1_",
    "shpat_",
    "sg.",
    "lin_api_",
    "bearer ",
    "basic ",
];

pub(crate) fn has_known_secret_prefix(tok: &str) -> bool {
    let low = tok.trim().to_ascii_lowercase();
    SECRET_PREFIXES.iter().any(|p| low.starts_with(p))
}

/// Name (flag, env var, header) that names a credential.
pub(crate) fn is_secret_name(name: &str) -> bool {
    let low = name.to_ascii_lowercase();
    [
        "token",
        "secret",
        "key",
        "pass",
        "auth",
        "credential",
        "dsn",
        "cookie",
        "bearer",
        "jwt",
        "pwd",
        "sig",
        "session",
    ]
    .iter()
    .any(|n| low.contains(n))
        || low.ends_with("pat")
}

// ---------------------------------------------------------------- grammars

fn basename(word: &str) -> &str {
    word.rsplit(['/', '\\']).next().unwrap_or(word)
}

fn stem_lower(word: &str) -> String {
    let b = basename(word).to_ascii_lowercase();
    for ext in [".exe", ".cmd", ".bat"] {
        if let Some(s) = b.strip_suffix(ext) {
            return s.to_string();
        }
    }
    b
}

fn longest_alnum_run(s: &str) -> usize {
    s.split(|c: char| !c.is_ascii_alphanumeric())
        .map(str::len)
        .max()
        .unwrap_or(0)
}

fn is_python_stem(stem: &str) -> bool {
    stem.strip_prefix("python")
        .is_some_and(|r| r.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

/// Catalog command label for a stem, or `None`.
fn known_command_stem(stem: &str) -> Option<String> {
    (catalog().commands.contains(stem) || is_python_stem(stem)).then(|| stem.to_string())
}

/// Catalog label for the first word of a command line (`node`, `npx`, `codex`, ...).
pub fn known_command(command: &str) -> Option<String> {
    let first = split_shell_like_tokens(command)
        .into_iter()
        .map(|(w, _)| w)
        .find(|w| !is_env_assignment(w))?;
    known_command_stem(&stem_lower(&first))
}

/// Catalog client (`claude`, `codex`, ...) a command line belongs to.
pub fn known_client(command: &str) -> Option<String> {
    let low = command.to_ascii_lowercase();
    let first = stem_lower(low.split_whitespace().next().unwrap_or(""));
    for c in &catalog().clients {
        // short names would match inside unrelated words: require the executable itself
        let short = matches!(c.as_str(), "code" | "zed" | "agy");
        if (short && first == *c) || (!short && low.contains(c.as_str())) {
            return Some(c.clone());
        }
    }
    None
}

fn version_ok(v: &str) -> bool {
    matches!(v, "latest" | "next" | "beta" | "canary")
        || (!v.is_empty()
            && v.len() <= 16
            && v.split('.')
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())))
}

/// Canonical catalog package id (plus a strictly numeric `@version`) for a word, if known.
fn package_label(w: &str) -> Option<String> {
    let at = w.get(1..).and_then(|t| t.rfind('@')).map(|i| i + 1);
    let (name, ver) = match at {
        Some(i) => (&w[..i], Some(&w[i + 1..])),
        None => (w, None),
    };
    let canon = catalog().packages.get(&name.to_ascii_lowercase())?;
    Some(match ver {
        None => canon.clone(),
        Some(v) if version_ok(v) => format!("{canon}@{v}"),
        Some(_) => format!("{canon}@{RED}"),
    })
}

/// Catalog package referenced anywhere in a command line (bare, versioned, or as the
/// basename / `node_modules/@scope/name` directory of a path). Canonical id only, never the
/// raw text.
pub fn known_package_in(command: &str) -> Option<String> {
    for (w, _) in split_shell_like_tokens(command) {
        if w.starts_with('-') {
            continue;
        }
        let comps: Vec<&str> = w.split(['/', '\\']).collect();
        let mut cands: Vec<String> = vec![w.clone()];
        for (i, c) in comps.iter().enumerate() {
            cands.push((*c).to_string());
            if i > 0 && comps[i - 1].starts_with('@') {
                cands.push(format!("{}/{}", comps[i - 1], c));
            }
        }
        for cand in cands {
            let name = match cand.get(1..).and_then(|t| t.rfind('@')) {
                Some(i) => &cand[..i + 1],
                None => cand.as_str(),
            };
            if let Some(canon) = catalog().packages.get(&name.to_ascii_lowercase()) {
                return Some(canon.clone());
            }
        }
    }
    None
}

/// Catalog flag text for `--name` (case-insensitive) or `-x` (exact), else `None`.
fn flag_label(name: &str) -> Option<String> {
    let c = catalog();
    if name.starts_with("--") {
        let low = name.to_ascii_lowercase();
        return c.flags.contains(&low).then_some(low);
    }
    c.flags.get(name).cloned()
}

fn is_bool_flag(canon: &str) -> bool {
    catalog().bool_flags.contains(canon)
}

/// Env / header key name from the fixed list; everything else is only counted.
pub fn known_key(raw: &str) -> Option<String> {
    catalog().keys.get(&raw.to_ascii_lowercase()).cloned()
}

/// `secret_findings[].key_name` for an env key.
pub fn env_key_label(raw: &str) -> String {
    known_key(raw).unwrap_or_else(|| "<env-key>".to_string())
}

/// `secret_findings[].key_name` for a header key.
pub fn header_key_label(raw: &str) -> String {
    known_key(raw).unwrap_or_else(|| "<header-key>".to_string())
}

/// Config server label (a user-chosen key): shown only when tiny and plain, otherwise
/// `server-<hash8>`. Labels are *shown*, so a secret must never be used as a label.
pub fn server_label(raw: &str) -> String {
    let ok = !raw.is_empty()
        && raw.len() <= 32
        && raw
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
        && raw
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && longest_alnum_run(raw) <= 12
        && !has_known_secret_prefix(raw);
    if ok {
        raw.to_string()
    } else {
        format!("server-{}", hash8(raw))
    }
}

fn dns_host_ok(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.contains('.')
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !has_known_secret_prefix(l)
        })
}

/// `scheme://host[:port]` for `http|https|ws|wss` and a dotted DNS host; never userinfo, path,
/// query or fragment.
pub fn safe_url(url: &str) -> Option<String> {
    let si = url.find("://")?;
    let scheme = url[..si].to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "ws" | "wss") {
        return None;
    }
    let after = &url[si + 3..];
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let authority = &after[..end];
    let hostport = authority
        .rfind('@')
        .map_or(authority, |at| &authority[at + 1..]);
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (hostport, None),
    };
    let port_ok =
        port.is_none_or(|p| !p.is_empty() && p.len() <= 5 && p.chars().all(|c| c.is_ascii_digit()));
    if !dns_host_ok(host) || !port_ok {
        return None;
    }
    let host = host.to_ascii_lowercase();
    Some(match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    })
}

/// Output form of a config / argv URL: validated `scheme://host`, else `<url>`.
pub fn url_label(url: &str) -> String {
    safe_url(url).unwrap_or_else(|| "<url>".to_string())
}

/// Process name from `top`-style output: the first word, then only catalog words; anything
/// else becomes `<w:hash8>`.
pub fn redact_process_name(raw: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for (i, word) in raw.split_whitespace().enumerate() {
        let core = word.trim_matches(|c| matches!(c, '(' | ')' | '[' | ']'));
        let known = catalog().process_words.contains(&core.to_ascii_lowercase())
            || known_command_stem(&core.to_ascii_lowercase()).is_some();
        let first_ok = i == 0
            && !core.is_empty()
            && core.len() <= 24
            && core
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
            && !has_known_secret_prefix(core);
        out.push(if known || first_ok {
            word.to_string()
        } else {
            format!("<w:{}>", hash8(word))
        });
    }
    out.join(" ")
}

fn is_env_assignment(w: &str) -> bool {
    match w.split_once('=') {
        Some((k, _)) => {
            k.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

fn looks_like_flag(w: &str) -> bool {
    let mut it = w.chars();
    it.next() == Some('-')
        && it
            .next()
            .is_some_and(|c| c == '-' || c.is_ascii_alphabetic())
}

fn value_secret(flag: &str, value: &str) -> bool {
    is_secret_name(flag)
        || has_known_secret_prefix(value)
        || (matches!(flag, "--header" | "--headers" | "-H")
            && is_secret_name(value.split([':', '=']).next().unwrap_or("")))
}

// ---------------------------------------------------------------- engine

/// Boolean flags that may precede the package identifier of a launcher.
const SLOT_KEEPING: &[&str] = &["-y", "-q", "--yes", "--quiet", "--silent", "--no-install"];
const SHELL_C_FLAGS: &[&str] = &[
    "-c", "-lc", "-ic", "-lic", "-ec", "-xc", "-Command", "-command",
];
const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "cmd",
    "powershell",
    "pwsh",
];

struct Engine {
    cmd_seen: bool,
    is_shell: bool,
    kw: &'static [&'static str],
    kw_pending: bool,
    slot_open: bool,
    shell_inner: bool,
    expect_value: Option<String>,
}

fn arg(text: &str, redacted: bool, label: &str, secret: bool) -> RedactedArg {
    RedactedArg {
        text: text.to_string(),
        redacted,
        label: label.to_string(),
        secret,
    }
}

impl Engine {
    fn new() -> Self {
        Self {
            cmd_seen: false,
            is_shell: false,
            kw: &[],
            kw_pending: false,
            slot_open: false,
            shell_inner: false,
            expect_value: None,
        }
    }

    fn set_command(&mut self, stem: &str) {
        self.cmd_seen = true;
        self.is_shell = SHELLS.contains(&stem);
        self.kw = match stem {
            "pnpm" => &["dlx", "exec"],
            "deno" => &["run"],
            "npm" => &["exec", "x"],
            "bun" => &["x", "run"],
            "yarn" => &["dlx"],
            _ => &[],
        };
        let launcher = !self.kw.is_empty()
            || matches!(stem, "npx" | "uvx" | "bunx" | "node" | "nodejs")
            || stem.starts_with("python");
        self.kw_pending = !self.kw.is_empty();
        self.slot_open = launcher;
    }

    fn step(&mut self, w: &str, depth: usize) -> RedactedArg {
        if w.is_empty() {
            return arg("", false, "", false);
        }
        if self.shell_inner {
            self.shell_inner = false;
            if depth >= MAX_DEPTH {
                return arg(RED, true, "shell-inner", false);
            }
            let inner = redact_command_depth(w, depth + 1);
            let changed = inner != w;
            return arg(&inner, changed, "shell-inner", false);
        }
        if let Some(flag) = self.expect_value.take() {
            if !looks_like_flag(w) {
                self.slot_open = false;
                return arg(RED, true, &flag, value_secret(&flag, w));
            }
        }
        if !self.cmd_seen {
            if is_env_assignment(w) {
                let (k, v) = w.split_once('=').unwrap_or((w, ""));
                return arg(
                    RED,
                    true,
                    "env-assign",
                    is_secret_name(k) || has_known_secret_prefix(v),
                );
            }
            if w.contains("://") {
                // a URL where a command should be: host only, never a path "basename"
                self.set_command("");
                let u = url_label(w);
                let changed = u != w;
                return arg(&u, changed, "url", false);
            }
            let stem = stem_lower(w);
            self.set_command(&stem);
            return match known_command_stem(&stem) {
                Some(c) => {
                    let changed = c != w;
                    arg(&c, changed, "command", false)
                }
                None => arg("<command>", true, "command", false),
            };
        }
        // Windows `/p:value`: only `/name<sep>` is a flag; the value is always withheld.
        if let Some(rest) = w.strip_prefix('/') {
            if let Some(i) = rest.find([':', '=']) {
                let name = &rest[..i];
                if (1..=8).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphabetic()) {
                    self.slot_open = false;
                    let low = name.to_ascii_lowercase();
                    if catalog().win_flags.contains(&low) {
                        let sep = &rest[i..=i];
                        return arg(
                            &format!("/{low}{sep}{RED}"),
                            true,
                            &format!("/{low}"),
                            is_secret_name(&low) || matches!(low.as_str(), "p" | "t"),
                        );
                    }
                    return arg(
                        "<flag>",
                        true,
                        "<flag>",
                        has_known_secret_prefix(&rest[i + 1..]),
                    );
                }
            } else if self.is_shell && matches!(rest, "c" | "k") {
                self.shell_inner = true;
                return arg(w, false, "", false);
            }
        }
        if w == "-" || w == "--" {
            return arg(w, false, "", false);
        }
        if looks_like_flag(w) {
            return self.flag(w);
        }
        self.positional(w)
    }

    fn flag(&mut self, w: &str) -> RedactedArg {
        if let Some(body) = w.strip_prefix("--") {
            let cut = body.find(['=', ':']);
            let (name, inline) = match cut {
                Some(i) => (&body[..i], Some((&body[i..=i], &body[i + 1..]))),
                None => (body, None),
            };
            self.slot_open = self.slot_open && SLOT_KEEPING.contains(&w);
            let Some(full) = flag_label(&format!("--{name}")) else {
                let secret = inline.is_some_and(|(_, v)| has_known_secret_prefix(v));
                if inline.is_none() {
                    self.expect_value = Some("<flag>".to_string());
                }
                return arg("<flag>", true, "<flag>", secret);
            };
            if let Some((sep, val)) = inline {
                return arg(
                    &format!("{full}{sep}{RED}"),
                    true,
                    &full,
                    value_secret(&full, val),
                );
            }
            if !is_bool_flag(&full) {
                self.expect_value = Some(full.clone());
            }
            return arg(&full, false, "", false);
        }
        // single dash
        if SHELL_C_FLAGS.contains(&w) {
            if self.is_shell {
                self.shell_inner = true;
            } else {
                self.expect_value = Some("-c".to_string());
                self.slot_open = false;
            }
            return arg(w, false, "", false);
        }
        if let Some(full) = flag_label(w) {
            if is_bool_flag(&full) {
                self.slot_open = self.slot_open && SLOT_KEEPING.contains(&w);
            } else {
                self.slot_open = false;
                self.expect_value = Some(full.clone());
            }
            return arg(&full, false, "", false);
        }
        self.slot_open = false;
        // glued `-pSECRET`, `-Dapi.key=X`, unknown flag: only a catalog letter survives
        if w.chars().count() > 2 {
            let head: String = w.chars().take(2).collect();
            if let Some(h) = flag_label(&head) {
                return arg(&format!("{h}{RED}"), true, &h, true);
            }
            return arg(
                "<flag>",
                true,
                "<flag>",
                has_known_secret_prefix(w.trim_start_matches('-')),
            );
        }
        self.expect_value = Some("<flag>".to_string());
        arg("<flag>", true, "<flag>", false)
    }

    fn positional(&mut self, w: &str) -> RedactedArg {
        if self.kw_pending {
            self.kw_pending = false;
            if self.kw.contains(&w) {
                return arg(w, false, "", false);
            }
            self.slot_open = false;
        }
        if self.slot_open {
            self.slot_open = false;
            return match package_label(w) {
                Some(p) => arg(&p, false, "", false),
                None => arg(
                    &format!("<package:{}>", hash8(w)),
                    true,
                    "package",
                    has_known_secret_prefix(w),
                ),
            };
        }
        if w.contains("://") {
            let u = url_label(w);
            let changed = u != w;
            return arg(&u, changed, "url", false);
        }
        arg(
            RED,
            true,
            "positional",
            has_known_secret_prefix(w) || w.eq_ignore_ascii_case("bearer"),
        )
    }
}

// ---------------------------------------------------------------- public API

/// Redacts an MCP `args` array. `command` is the server's command (used only to recognise
/// launchers and shells); the result is 1:1 with `args`.
pub fn redact_argv(command: Option<&str>, args: &[String]) -> Vec<RedactedArg> {
    let mut e = Engine::new();
    match command {
        Some(c) => {
            let first = split_shell_like_tokens(c)
                .into_iter()
                .map(|(w, _)| w)
                .find(|w| !is_env_assignment(w));
            e.set_command(&first.map(|w| stem_lower(&w)).unwrap_or_default());
        }
        None => e.set_command(""),
    }
    args.iter().map(|a| e.step(a, 0)).collect()
}

fn redact_command_depth(input: &str, depth: usize) -> String {
    let mut e = Engine::new();
    let mut out: Vec<String> = Vec::new();
    for (word, _quote) in split_shell_like_tokens(input) {
        let r = e.step(&word, depth);
        out.push(if r.text.chars().any(char::is_whitespace) {
            if r.text.contains('"') {
                format!("'{}'", r.text)
            } else {
                format!("\"{}\"", r.text)
            }
        } else {
            r.text
        });
    }
    out.join(" ")
}

/// Closed-vocabulary redaction of a whole command line (process list, config `command`).
pub fn redact_command(input: &str) -> String {
    redact_command_depth(input, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(cmd: &str, args: &[&str]) -> Vec<String> {
        let a: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        redact_argv(Some(cmd), &a)
            .into_iter()
            .map(|r| r.text)
            .collect()
    }

    #[test]
    fn launcher_package_flag_names_and_redacted_values() {
        assert_eq!(
            argv(
                "npx",
                &[
                    "-y",
                    "@modelcontextprotocol/server-github@1.2.3",
                    "--port",
                    "8080",
                    "--token",
                    "X"
                ]
            ),
            [
                "-y",
                "@modelcontextprotocol/server-github@1.2.3",
                "--port",
                RED,
                "--token",
                RED
            ]
        );
        assert_eq!(
            redact_command("/usr/bin/node /srv/app/server.js --port 8080"),
            format!(
                "node <package:{}> --port {RED}",
                hash8("/srv/app/server.js")
            )
        );
        assert_eq!(
            redact_command("pnpm dlx mcp-remote https://u:p@host.example:8443/x?q=1"),
            "pnpm dlx mcp-remote https://host.example:8443"
        );
    }

    /// Every R5 B2 probe: nothing from the probe may reach any text or label.
    #[test]
    fn r5_probes_never_reach_output() {
        // assembled at runtime so the repo hygiene scan sees no token-shaped literal
        let xoxa = ["xox", "a-1234-probesecret"].concat();
        let rk = ["rk_", "live_probesecret1"].concat();
        let xoxa_flag = ["--xox", "a-1234-probesec=1"].concat();
        let probes: &[(&str, &[&str])] = &[
            ("npx", &["probesecrettokenabcd"]),
            ("npx", &["probesecret17char"]),
            ("npx", &["hf_probesecret12345"]),
            ("npx", &["gho_probesecret12345"]),
            ("npx", &["ghs_probesecret12345"]),
            ("npx", &["npm_probesecret12345"]),
            ("npx", &[rk.as_str()]),
            ("npx", &["whsec_probesecret123"]),
            ("npx", &[xoxa.as_str()]),
            ("npx", &["correct-horse-staple"]),
            ("npx", &["probesecret1.probesecret2.probesecret3"]),
            ("npx", &["mcp-pkg@1-PROBESECRET"]),
            ("npx", &["@probesecret17char/probesecret20char@1-PROBESEC"]),
            ("tool", &["--rk-live-probesec12=1", xoxa_flag.as_str()]),
            (
                "tool",
                &[
                    "--key-sk-probesec12",
                    "--token-a1b2c3d4e5=1",
                    "--probesecret123=1",
                ],
            ),
            ("tool", &["/probesec:hunter2"]),
            (
                "tool",
                &[
                    "Bearer://probesecretlowercasetoken1234",
                    "token://probesecretlowercasetoken1234",
                ],
            ),
            (
                "https://alice:PROBE_PW@hooks.example.com/services/T00/B00/PROBE_HOOK_123",
                &[],
            ),
            (
                "sh",
                &["-c", "https://alice:PROBE_PW@example.com/mcp/PROBE_URL_CMD"],
            ),
            ("/Users/alice/.secrets/PROBE_SECRET_BIN", &[]),
            ("/tmp/SK-LIVE-PROBE123", &[]),
            ("/tmp/gho_probesecret1", &[]),
            ("/tmp/Zm9v+YmFy+PROBE1", &[]),
        ];
        for (cmd, args) in probes {
            let a: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            let mut joined = redact_argv(Some(cmd), &a)
                .into_iter()
                .map(|r| format!("{} {}", r.text, r.label))
                .collect::<Vec<_>>()
                .join(" ");
            joined.push(' ');
            joined.push_str(&redact_command(&format!("{cmd} {}", args.join(" "))));
            let low = joined.to_ascii_lowercase();
            for n in [
                "probe",
                "hunter2",
                "hf_",
                "gho_",
                "ghs_",
                "npm_",
                "rk_live",
                "rk-live",
                "whsec",
                "xoxa",
                "correct-horse",
                "1-probesecret",
                "sk-live",
                "bearer://",
                "token://",
                "a1b2c3d4",
            ] {
                assert!(!low.contains(n), "{cmd} {args:?} leaked {n:?}: {joined}");
            }
        }
    }

    #[test]
    fn known_package_and_flag_survive_unknown_are_hashed() {
        assert_eq!(
            argv(
                "npx",
                &["-y", "mcp-remote", "https://mcp.example.com/sse/550e8400"]
            ),
            ["-y", "mcp-remote", "https://mcp.example.com"]
        );
        let out = argv("npx", &["not-a-known-package"]);
        assert_eq!(out, [format!("<package:{}>", hash8("not-a-known-package"))]);
        let out = argv("tool", &["--port", "8080", "--made-up-flag", "v"]);
        assert_eq!(out, ["--port", RED, "<flag>", RED]);
    }

    #[test]
    fn secret_signal_only_for_real_secret_names_or_prefixes() {
        let a: Vec<String> = ["--port", "8080", "/tmp", "--token", "x", "GHP_abc"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let r = redact_argv(Some("tool"), &a);
        assert_eq!(r.iter().filter(|x| x.secret).count(), 2, "{r:?}");
        assert!(
            r[1].redacted && !r[1].secret,
            "a benign value is redacted but is not a finding"
        );
        assert!(r[4].secret && r[4].label == "--token");
        assert!(r[5].secret, "known prefix matches case-insensitively");
    }

    #[test]
    fn flag_value_never_survives() {
        for (cmd, args) in [
            ("sqlcmd", vec!["/p:hunter2", "/key:PROBE_X"]),
            ("redis-cli", vec!["-a", "PROBE_R"]),
            ("tool", vec!["-pPROBE_G", "-uPROBE_U", "--API-KEY=PROBE_UP"]),
            ("tool", vec!["--PROBE_UNSAFE=1", "--sk-live-PROBE_SK="]),
            ("tool", vec!["-H", "Cookie: a=b; sid=PROBE_C"]),
            ("tool", vec!["X=PROBE_E", "{ \"api_key\": \"PROBE_J\" }"]),
        ] {
            let a: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            let out: Vec<String> = redact_argv(Some(cmd), &a)
                .into_iter()
                .map(|r| r.text)
                .collect();
            let joined = out.join(" ");
            assert!(
                !joined.contains("PROBE_") && !joined.contains("hunter2"),
                "{args:?} -> {joined}"
            );
        }
    }

    #[test]
    fn nested_shell_is_summarised_recursively() {
        let out = redact_command("sh -c \"sh -c 'npx mcp --token PROBE_N'\"");
        assert!(!out.contains("PROBE_"), "{out}");
        assert!(out.starts_with("sh -c"), "{out}");
    }

    #[test]
    fn url_shows_scheme_and_dotted_host_only() {
        assert_eq!(
            safe_url("https://alice:PROBE@example.com/p/PROBE?code=PROBE#f").as_deref(),
            Some("https://example.com")
        );
        assert_eq!(safe_url("https://alice%3aPROBE%40example.com/x"), None);
        assert_eq!(safe_url("Bearer://probesecretlowercasetoken1234"), None);
        assert_eq!(safe_url("https://localhost/x"), None, "no dot, no host");
        assert_eq!(url_label("ftp://example.com"), "<url>");
        assert_eq!(safe_url("not a url"), None);
    }

    #[test]
    fn labels_and_keys_are_closed() {
        assert_eq!(server_label("playwright"), "playwright");
        let long = "x".repeat(40);
        for bad in [
            "probesecretlowercasetok1",
            "550e8400-e29b-41d4-a716-446655440000",
            "SK-LIVE-PROBE12345",
            long.as_str(),
        ] {
            let l = server_label(bad);
            assert!(l.starts_with("server-") && l.len() == 15, "{bad} -> {l}");
        }
        assert_eq!(env_key_label("GITHUB_TOKEN"), "GITHUB_TOKEN");
        assert_eq!(env_key_label("probesecretlowercasetok2"), "<env-key>");
        assert_eq!(header_key_label("SK-LIVE-PROBE12345"), "<header-key>");
    }

    #[test]
    fn process_names_keep_first_word_and_catalog_words_else_hash() {
        assert_eq!(
            redact_process_name("Google Chrome Helper (Renderer)"),
            "Google Chrome Helper (Renderer)"
        );
        let out = redact_process_name("Google probesecretword");
        assert!(
            out.starts_with("Google <w:") && !out.contains("probesecret"),
            "{out}"
        );
    }

    #[test]
    fn unknown_label_is_hash_of_argv() {
        let l = unknown_label("python3 -c x https://mcp.example.com/sse/550e8400");
        assert!(
            l.starts_with("unknown-") && l.len() == 16 && !l.contains("550e"),
            "{l}"
        );
    }
}
