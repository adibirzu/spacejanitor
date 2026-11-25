//! Structural redaction for every audit output path (mcp-audit, llm-audit, reap, memory,
//! serve-stdio, `secret_findings[].key_name`, any `command` field).
//!
//! Two rounds of guessing which values look secret (a denylist, then a heuristic allowlist)
//! still leaked, so this module never decides whether a value is secret. It emits **only**:
//!
//! 1. the command's basename (strict grammar; never a path),
//! 2. the package/script identifier: the first positional after a known launcher (`npx`,
//!    `uvx`, `bunx`, `pnpm dlx`, `node`, `python`, `deno run`, ...) when it matches a strict
//!    package-name grammar,
//! 3. flag **names** (`--port`, `-y`) whose values are always `<REDACTED>`,
//! 4. URL `scheme://host` (never userinfo, path, query or fragment),
//! 5. counts (argv length, env key count, header key count), and identifier-grammar key names.
//!
//! Every other positional, value, header, env value or malformed token becomes `<REDACTED>`.
//! Over-redaction is accepted; a leak is not possible by construction because unrecognised
//! shapes have no way to reach the output.

use crate::{has_known_secret_prefix, split_shell_like_tokens};

pub const RED: &str = "<REDACTED>";
const MAX_DEPTH: usize = 4;

/// One redacted argv element / shell word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedArg {
    pub text: String,
    /// True when information was withheld from this element.
    pub redacted: bool,
    /// Fixed-vocabulary or validated-flag-name label, safe for `secret_findings[].key_name`.
    pub label: String,
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

/// Command basename: short, plain, no long unbroken run that could be key material.
fn safe_command_name(base: &str) -> Option<String> {
    let ok = !base.is_empty()
        && base.len() <= 24
        && base
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && base
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
        && longest_alnum_run(base) <= 16
        && !has_known_secret_prefix(base);
    ok.then(|| base.to_string())
}

/// `name`, `@scope/name`, optional `@version`. Lowercase only, at most two `-`/`_`
/// separators, no unbroken alphanumeric run over 20 characters, no `=`, `:` or extra `/`.
fn is_package_id(w: &str) -> bool {
    if w.is_empty() || w.len() > 64 || has_known_secret_prefix(w) {
        return false;
    }
    let (scope, rest) = match w.strip_prefix('@') {
        Some(r) => match r.split_once('/') {
            Some((sc, rest)) => (Some(sc), rest),
            None => return false,
        },
        None => (None, w),
    };
    let (name, version) = match rest.rsplit_once('@') {
        Some((n, v)) => (n, Some(v)),
        None => (rest, None),
    };
    let ident = |s: &str, max: usize| {
        !s.is_empty()
            && s.len() <= max
            && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
            && s.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
            })
    };
    if !ident(name, 40) || scope.is_some_and(|s| !ident(s, 30)) {
        return false;
    }
    if let Some(v) = version {
        let ok = matches!(v, "latest" | "next")
            || (v.len() <= 16
                && v.chars().next().is_some_and(|c| c.is_ascii_digit())
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-')));
        if !ok {
            return false;
        }
    }
    let part_ok = |p: &str| {
        p.chars().filter(|c| matches!(c, '-' | '_')).count() <= 2
            && p.split(['-', '_', '.']).all(|seg| seg.len() <= 20)
    };
    part_ok(name) && scope.is_none_or(part_ok)
}

/// Lowercase flag name body (after the dashes): `port`, `log-level`, `dangerously-skip-x`.
fn safe_flag_name(body: &str) -> bool {
    !body.is_empty()
        && body.len() <= 32
        && body.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && body
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && body.split('-').count() <= 4
        && body
            .split('-')
            .all(|seg| !seg.is_empty() && seg.len() <= 14)
        && !has_known_secret_prefix(body)
}

/// A name that is echoed (env key, header name, server name) only when it is a plain
/// identifier without an unbroken run long enough to be key material.
fn is_plain_name(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        && longest_alnum_run(s) <= 24
        && !has_known_secret_prefix(s)
}

/// Key name safe for output (`env_keys`, `header_keys`, `secret_findings[].key_name`).
pub fn safe_key_name(raw: &str) -> String {
    if is_plain_name(raw, 48) {
        raw.to_string()
    } else {
        RED.to_string()
    }
}

/// Server / client / process-label name safe for output.
pub fn safe_label(raw: &str) -> String {
    if is_plain_name(raw, 48) {
        raw.to_string()
    } else {
        RED.to_string()
    }
}

/// `scheme://host[:port]` only; userinfo, path, query and fragment are never emitted.
pub fn safe_url(url: &str) -> Option<String> {
    let si = url.find("://")?;
    let scheme = &url[..si];
    if scheme.is_empty()
        || scheme.len() > 16
        || !scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
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
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        && host.split('.').all(|l| l.len() <= 30 && !l.is_empty())
        && !has_known_secret_prefix(host);
    let port_ok =
        port.is_none_or(|p| !p.is_empty() && p.len() <= 5 && p.chars().all(|c| c.is_ascii_digit()));
    if !host_ok || !port_ok {
        return None;
    }
    Some(match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    })
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

// ---------------------------------------------------------------- engine

const BOOL_FLAGS: &[&str] = &[
    "-y",
    "-q",
    "--yes",
    "--quiet",
    "--silent",
    "--no-install",
    "--verbose",
    "--help",
    "--version",
    "--debug",
    "--stdio",
    "--no-warnings",
    "-NoProfile",
    "-NonInteractive",
];
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
    launcher: bool,
    kw: &'static [&'static str],
    kw_pending: bool,
    slot_open: bool,
    shell_inner: bool,
    expect_value: Option<String>,
}

impl Engine {
    fn new() -> Self {
        Self {
            cmd_seen: false,
            is_shell: false,
            launcher: false,
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
        self.launcher = !self.kw.is_empty()
            || matches!(stem, "npx" | "uvx" | "bunx" | "node" | "nodejs")
            || stem.starts_with("python");
        self.kw_pending = !self.kw.is_empty();
        self.slot_open = self.launcher;
    }

    fn step(&mut self, w: &str, depth: usize) -> RedactedArg {
        let keep = |t: &str| RedactedArg {
            text: t.to_string(),
            redacted: false,
            label: String::new(),
        };
        let red = |label: &str| RedactedArg {
            text: RED.to_string(),
            redacted: true,
            label: label.to_string(),
        };
        if w.is_empty() {
            return keep("");
        }
        if self.shell_inner {
            self.shell_inner = false;
            if depth >= MAX_DEPTH {
                return red("shell-inner");
            }
            let inner = redact_command_depth(w, depth + 1);
            return RedactedArg {
                redacted: inner != w,
                text: inner,
                label: "shell-inner".to_string(),
            };
        }
        if let Some(flag) = self.expect_value.take() {
            if !looks_like_flag(w) {
                self.slot_open = false;
                return red(&flag);
            }
        }
        if !self.cmd_seen {
            if is_env_assignment(w) {
                return red("env-assign");
            }
            self.set_command(&stem_lower(w));
            return match safe_command_name(basename(w)) {
                Some(b) => RedactedArg {
                    redacted: b != w,
                    text: b,
                    label: "command".to_string(),
                },
                None => red("command"),
            };
        }
        // Windows `/p:value`: only `/name<sep>` is a flag; the value is always withheld.
        if let Some(rest) = w.strip_prefix('/') {
            if let Some(i) = rest.find([':', '=']) {
                let name = &rest[..i];
                if (1..=8).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphabetic()) {
                    self.slot_open = false;
                    let sep = &rest[i..=i];
                    return RedactedArg {
                        text: format!("/{name}{sep}{RED}"),
                        redacted: true,
                        label: safe_key_name(name),
                    };
                }
            } else if self.is_shell && matches!(rest, "c" | "k") {
                self.shell_inner = true;
                return keep(w);
            }
        }
        if w == "-" || w == "--" {
            return keep(w);
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
            if !safe_flag_name(name) {
                if inline.is_none() {
                    self.expect_value = Some("cli-flag".to_string());
                }
                return RedactedArg {
                    text: RED.to_string(),
                    redacted: true,
                    label: "cli-flag".to_string(),
                };
            }
            let full = format!("--{name}");
            if let Some((sep, _)) = inline {
                return RedactedArg {
                    text: format!("{full}{sep}{RED}"),
                    redacted: true,
                    label: full,
                };
            }
            if !BOOL_FLAGS.contains(&full.as_str()) {
                self.expect_value = Some(full.clone());
            }
            return RedactedArg {
                text: full,
                redacted: false,
                label: String::new(),
            };
        }
        // single dash
        if SHELL_C_FLAGS.contains(&w) {
            if self.is_shell {
                self.shell_inner = true;
            } else {
                self.expect_value = Some(safe_key_name(w));
                self.slot_open = false;
            }
            return RedactedArg {
                text: w.to_string(),
                redacted: false,
                label: String::new(),
            };
        }
        if BOOL_FLAGS.contains(&w) {
            self.slot_open = self.slot_open && SLOT_KEEPING.contains(&w);
            return RedactedArg {
                text: w.to_string(),
                redacted: false,
                label: String::new(),
            };
        }
        self.slot_open = false;
        let rest = &w[1..];
        if rest.len() == 1 {
            self.expect_value = Some(w.to_string());
            return RedactedArg {
                text: w.to_string(),
                redacted: false,
                label: String::new(),
            };
        }
        // glued `-pSECRET`, `-Dapi.key=X`, unknown long single-dash flag: keep the letter only
        let head = &w[..2];
        RedactedArg {
            text: format!("{head}{RED}"),
            redacted: true,
            label: head.to_string(),
        }
    }

    fn positional(&mut self, w: &str) -> RedactedArg {
        if self.kw_pending {
            self.kw_pending = false;
            if self.kw.contains(&w) {
                return RedactedArg {
                    text: w.to_string(),
                    redacted: false,
                    label: String::new(),
                };
            }
            self.slot_open = false;
        }
        if self.slot_open && is_package_id(w) {
            self.slot_open = false;
            return RedactedArg {
                text: w.to_string(),
                redacted: false,
                label: String::new(),
            };
        }
        self.slot_open = false;
        if let Some(u) = safe_url(w) {
            return RedactedArg {
                redacted: u != w,
                text: u,
                label: "url".to_string(),
            };
        }
        RedactedArg {
            text: RED.to_string(),
            redacted: true,
            label: "positional".to_string(),
        }
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

/// Structural redaction of a whole command line (process list, config `command`).
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
                &["-y", "@scope/pkg@1.2.3", "--port", "8080", "--token", "X"]
            ),
            ["-y", "@scope/pkg@1.2.3", "--port", RED, "--token", RED]
        );
        assert_eq!(
            redact_command("/usr/bin/node /srv/app/server.js --port 8080"),
            format!("node {RED} --port {RED}")
        );
        assert_eq!(
            redact_command("pnpm dlx mcp-remote https://u:p@host.example:8443/x?q=1"),
            "pnpm dlx mcp-remote https://host.example:8443"
        );
    }

    #[test]
    fn secret_shapes_in_package_slot_are_rejected_by_grammar() {
        for s in [
            "probesecretlowercasetokenabcdef",
            "550e8400-e29b-41d4-a716-446655440000",
            "hf_a1b2c3d4_e5f6g7h8_i9j0k1l2",
            "correct-horse-battery-staple",
            "sk-live-abc",
            "abcdefghijklmnopqrstuvwxyz",
            "Mixed-Case",
            "a=b",
            "@scope/a/b",
        ] {
            assert!(!is_package_id(s), "{s}");
        }
        for s in [
            "mcp-remote",
            "@modelcontextprotocol/server-filesystem",
            "chrome-devtools-mcp@latest",
            "server.js",
            "@upstash/context7-mcp@1.0.2",
        ] {
            assert!(is_package_id(s), "{s}");
        }
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
    fn url_shows_scheme_and_host_only() {
        assert_eq!(
            safe_url("https://alice:PROBE@example.com/p/PROBE?code=PROBE#f").as_deref(),
            Some("https://example.com")
        );
        assert_eq!(safe_url("https://alice%3aPROBE%40example.com/x"), None);
        assert_eq!(safe_url("not a url"), None);
    }

    #[test]
    fn key_and_label_names_fail_closed() {
        assert_eq!(safe_key_name("API_TOKEN"), "API_TOKEN");
        assert_eq!(safe_key_name("sk-live-abc"), RED);
        assert_eq!(safe_key_name("probesecretlowercasetokenabcdef"), RED);
        assert_eq!(safe_label("playwright"), "playwright");
    }
}
