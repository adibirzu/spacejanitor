use crate::protect::{check_path_protection, ProtectionContext};
use crate::redact::{
    env_key_label, header_key_label, is_secret_name, known_client, known_command, known_key,
    known_package_in, redact_argv, redact_command, server_label, unknown_label, url_label,
};
use crate::safe_read::{read_config_file, EntryKind, ReadPolicy, ReadRefusal, SafeDir};
use crate::{SjError, SCHEMA_MCP_AUDIT_V1};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct McpAuditOptions {
    pub config_dirs: Vec<PathBuf>,
    /// Overrides `$HOME` for default config discovery and protected-path checks.
    pub home_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservedProcess {
    pub pid: u32,
    pub ppid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    pub start_time: String,
    pub elapsed_secs: u64,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfiguredMcpServer {
    pub server_name: String,
    /// Owning client inferred from the config path (`codex`, `gemini`, `cursor`, `vscode`, ...).
    pub client: String,
    /// False when the config marks the server `enabled = false` / `"disabled": true`.
    pub enabled: bool,
    pub source_file: String,
    pub transport: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    /// Number of argv elements (the elements themselves are structurally redacted).
    pub args_count: usize,
    /// `scheme://host` only; never userinfo, path, query or fragment.
    pub url: Option<String>,
    /// Env key names from the fixed known-safe list only; every other key is only counted.
    pub env_keys: Vec<String>,
    pub env_key_count: usize,
    pub header_keys: Vec<String>,
    pub header_key_count: usize,
    /// Lowercased raw tokens used only to *match* a live process to this config entry. They
    /// decide which label is shown and are never serialized or printed.
    #[serde(skip)]
    pub(crate) match_tokens: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretFinding {
    pub server_name: String,
    pub source_file: String,
    pub location: String,
    pub key_name: String,
    pub redacted_preview: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunningMcpProcess {
    pub pid: u32,
    pub ppid: u32,
    pub server_name: String,
    pub owning_client: String,
    pub is_orphan: bool,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DuplicateMcpGroup {
    pub server_name: String,
    pub count: usize,
    pub pids: Vec<u32>,
    pub owning_clients: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct McpAuditReport {
    pub schema: String,
    pub scanned_files: Vec<String>,
    pub configured_servers: Vec<ConfiguredMcpServer>,
    pub running_processes: Vec<RunningMcpProcess>,
    pub duplicate_groups: Vec<DuplicateMcpGroup>,
    pub orphan_processes: Vec<RunningMcpProcess>,
    pub secret_findings: Vec<SecretFinding>,
    pub warnings: Vec<String>,
}

fn is_sensitive_env_key(key: &str) -> bool {
    let up = key.to_ascii_uppercase();
    up.contains("KEY")
        || up.contains("TOKEN")
        || up.contains("SECRET")
        || up.contains("PASSWORD")
        || up.contains("PASSWD")
        || up.contains("AUTH")
        || up.contains("CREDENTIAL")
        || up.contains("PWD")
        || up.contains("BEARER")
        || up.contains("JWT")
        || up.contains("SIG")
        || up.contains("COOKIE")
        || up.contains("SESSION")
        || up.contains("DSN")
        || up.ends_with("PAT")
}

fn is_env_var_reference(val: &str) -> bool {
    let t = val.trim();
    (t.starts_with("${") && t.ends_with('}'))
        || (t.starts_with('$') && !t.contains(' ') && t.len() > 1)
        || t.eq_ignore_ascii_case("<redacted>")
        || t.contains("***REDACTED***")
}

fn looks_like_secret_value(val: &str) -> bool {
    let t = val.trim();
    !t.is_empty() && !is_env_var_reference(t) && crate::redact::has_known_secret_prefix(t)
}

fn redact_secret_preview(_val: &str) -> String {
    "[REDACTED]".to_string()
}

/// Structural redaction over the whole argv (see `redact.rs`): only the package identifier,
/// flag names and counts survive. The finding label is a validated flag name or a fixed word.
fn sanitize_args(
    command: Option<&str>,
    args: &[String],
    server_name: &str,
    source_file: &str,
    findings: &mut Vec<SecretFinding>,
) -> (Vec<String>, Vec<String>) {
    let mut tokens = Vec::new();
    let out = redact_argv(command, args)
        .into_iter()
        .zip(args)
        .map(|(r, raw)| {
            // a process matches this entry by its package slot or a plain positional, never by
            // the value of a flag
            if (r.label == "package" || (!r.redacted && !r.text.starts_with('-'))) && raw.len() >= 6
            {
                tokens.push(raw.to_ascii_lowercase());
            }
            // only a real secret signal is a finding; benign redacted values are not
            if r.secret {
                findings.push(SecretFinding {
                    server_name: server_name.to_string(),
                    source_file: source_file.to_string(),
                    location: "args".to_string(),
                    // labels are catalog flag names or fixed placeholders (redact.rs)
                    key_name: r.label,
                    redacted_preview: redact_secret_preview(&r.text),
                });
            }
            r.text
        })
        .collect();
    (out, tokens)
}

fn inspect_env_map(
    env_map: &BTreeMap<String, String>,
    server_name: &str,
    source_file: &str,
    findings: &mut Vec<SecretFinding>,
) -> (Vec<String>, usize) {
    let mut keys = Vec::new();
    for (k, v) in env_map {
        if let Some(known) = known_key(k) {
            keys.push(known);
        }
        if !v.trim().is_empty()
            && !is_env_var_reference(v)
            && (is_sensitive_env_key(k) || looks_like_secret_value(v))
        {
            findings.push(SecretFinding {
                server_name: server_name.to_string(),
                source_file: source_file.to_string(),
                location: "env".to_string(),
                key_name: env_key_label(k),
                redacted_preview: redact_secret_preview(v),
            });
        }
    }
    keys.sort();
    keys.dedup();
    (keys, env_map.len())
}

/// Header names: a finding only when the name itself names a credential.
fn inspect_header_keys<'a>(
    keys: impl Iterator<Item = &'a String>,
    server_name: &str,
    source_file: &str,
    findings: &mut Vec<SecretFinding>,
) -> (Vec<String>, usize) {
    let mut known = Vec::new();
    let mut n = 0;
    for k in keys {
        n += 1;
        if let Some(kn) = known_key(k) {
            known.push(kn);
        }
        if is_secret_name(k) {
            findings.push(SecretFinding {
                server_name: server_name.to_string(),
                source_file: source_file.to_string(),
                location: "headers".to_string(),
                key_name: header_key_label(k),
                redacted_preview: redact_secret_preview(k),
            });
        }
    }
    known.sort();
    known.dedup();
    (known, n)
}

fn parse_json_mcp_config(
    raw: &str,
    source_file: &str,
    servers: &mut Vec<ConfiguredMcpServer>,
    findings: &mut Vec<SecretFinding>,
) -> Result<(), String> {
    let val: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("invalid JSON in {source_file}: {e}"))?;

    let candidates = [
        val.get("mcpServers"),
        val.get("mcp").and_then(|m| m.get("servers")),
        val.get("mcp"),
    ];

    for map_opt in candidates {
        let Some(obj) = map_opt.and_then(|v| v.as_object()) else {
            continue;
        };
        for (name, cfg) in obj {
            let Some(cfg_obj) = cfg.as_object() else {
                continue;
            };
            // Skip non-server metadata fields if `val.get("mcp")` was matched
            let has_cmd_or_url = cfg_obj.contains_key("command") || cfg_obj.contains_key("url");
            if !has_cmd_or_url {
                continue;
            }
            let raw_command = cfg_obj.get("command").and_then(|v| v.as_str());
            let command = raw_command.map(redact_command);
            let raw_args: Vec<String> = cfg_obj
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(ToString::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let server_label = server_label(name);
            let (args, match_tokens) =
                sanitize_args(raw_command, &raw_args, &server_label, source_file, findings);
            let url = cfg_obj.get("url").and_then(|v| v.as_str()).map(url_label);
            let header_names: Vec<String> = ["headers", "http_headers"]
                .iter()
                .filter_map(|hk| cfg_obj.get(*hk).and_then(|v| v.as_object()))
                .flat_map(|h| h.keys().cloned())
                .collect();
            let (header_keys, header_key_count) =
                inspect_header_keys(header_names.iter(), &server_label, source_file, findings);

            let mut env_map = BTreeMap::new();
            if let Some(env_obj) = cfg_obj.get("env").and_then(|v| v.as_object()) {
                for (ek, ev) in env_obj {
                    if let Some(ev_str) = ev.as_str() {
                        env_map.insert(ek.clone(), ev_str.to_string());
                    }
                }
            }
            let (env_keys, env_key_count) =
                inspect_env_map(&env_map, &server_label, source_file, findings);
            let transport = if cfg_obj.contains_key("url") {
                "http".to_string()
            } else {
                "stdio".to_string()
            };

            let enabled = cfg_obj.get("enabled").and_then(|v| v.as_bool()) != Some(false)
                && cfg_obj.get("disabled").and_then(|v| v.as_bool()) != Some(true);
            servers.push(ConfiguredMcpServer {
                server_name: server_label,
                client: client_from_path(source_file),
                enabled,
                source_file: source_file.to_string(),
                transport,
                command,
                args_count: args.len(),
                args,
                url,
                env_keys,
                env_key_count,
                header_keys,
                header_key_count,
                match_tokens,
            });
        }
        break;
    }

    Ok(())
}

fn client_from_path(source_file: &str) -> String {
    let low = source_file.replace('\\', "/").to_ascii_lowercase();
    for (needle, client) in [
        ("/.codex/", "codex"),
        ("/.gemini/", "gemini"),
        ("/.cursor/", "cursor"),
        ("/code/user/", "vscode"),
        ("/opencode/", "opencode"),
        ("/.claude", "claude"),
    ] {
        if low.contains(needle) {
            return client.to_string();
        }
    }
    "other".to_string()
}

fn strip_toml_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_double => escaped = true,
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            '#' if !in_single && !in_double => return &line[..idx],
            _ => {}
        }
    }
    line
}

fn unquote_toml_str(raw: &str) -> String {
    let t = raw.trim();
    if (t.starts_with('"') && t.ends_with('"') && t.len() >= 2)
        || (t.starts_with('\'') && t.ends_with('\'') && t.len() >= 2)
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

fn parse_toml_string_array(raw: &str) -> Vec<String> {
    let t = raw.trim();
    let inner = t
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(t);
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote: Option<char> = None;
    let mut escaped = false;

    for ch in inner.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        match (in_quote, ch) {
            (Some('"'), '\\') => {
                escaped = true;
            }
            (Some(q), c) if c == q => {
                in_quote = None;
            }
            (Some(_), c) => cur.push(c),
            (None, '"') | (None, '\'') => {
                in_quote = Some(ch);
            }
            (None, ',') => {
                let item = cur.trim().to_string();
                if !item.is_empty() {
                    out.push(item);
                }
                cur.clear();
            }
            (None, c) if !c.is_whitespace() => cur.push(c),
            (None, _) => {}
        }
    }
    let last = cur.trim().to_string();
    if !last.is_empty() {
        out.push(last);
    }
    out
}

/// Splits `name.rest` / `"quoted.name".rest` from a `[mcp_servers.<...>]` header into the
/// server name and the remaining dotted tail (empty, or starting with `.`).
fn split_toml_server_header(rest: &str) -> (String, &str) {
    let rest = rest.trim();
    for q in ['"', '\''] {
        if let Some(body) = rest.strip_prefix(q) {
            if let Some(end) = body.find(q) {
                return (body[..end].to_string(), body[end + 1..].trim());
            }
        }
    }
    match rest.find('.') {
        Some(i) => (rest[..i].trim().to_string(), rest[i..].trim()),
        None => (rest.to_string(), ""),
    }
}

fn parse_toml_mcp_config(
    raw: &str,
    source_file: &str,
    servers: &mut Vec<ConfiguredMcpServer>,
    findings: &mut Vec<SecretFinding>,
) {
    #[derive(Default)]
    struct TempServer {
        command: Option<String>,
        url: Option<String>,
        enabled: Option<bool>,
        args: Vec<String>,
        env: BTreeMap<String, String>,
        header_keys: Vec<String>,
    }

    let mut map: BTreeMap<String, TempServer> = BTreeMap::new();
    let mut current_server: Option<String> = None;
    let mut in_env_section = false;
    let mut in_header_section = false;

    for raw_line in raw.lines() {
        let line = strip_toml_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim();
            if let Some(rest) = section.strip_prefix("mcp_servers.") {
                let (name, tail) = split_toml_server_header(rest);
                match tail {
                    "" => {
                        current_server = Some(name);
                        in_env_section = false;
                        in_header_section = false;
                    }
                    ".env" => {
                        current_server = Some(name);
                        in_env_section = true;
                        in_header_section = false;
                    }
                    // Header subtables: only the header *names* are read, never the values.
                    ".http_headers" | ".headers" | ".env_http_headers" => {
                        current_server = Some(name);
                        in_env_section = false;
                        in_header_section = true;
                    }
                    // `.tools.*`, ...: subtables of a server, never servers themselves.
                    _ => {
                        current_server = None;
                        in_env_section = false;
                        in_header_section = false;
                    }
                }
            } else {
                current_server = None;
                in_env_section = false;
                in_header_section = false;
            }
            continue;
        }
        let Some(ref srv_name) = current_server else {
            continue;
        };
        let Some((k_raw, v_raw)) = line.split_once('=') else {
            continue;
        };
        let key = unquote_toml_str(k_raw);
        let val = v_raw.trim();
        let entry = map.entry(srv_name.clone()).or_default();

        if in_header_section {
            entry.header_keys.push(key);
            continue;
        }
        if in_env_section {
            entry.env.insert(key, unquote_toml_str(val));
            continue;
        }
        match key.as_str() {
            "command" => entry.command = Some(unquote_toml_str(val)),
            "url" => entry.url = Some(unquote_toml_str(val)),
            "enabled" => entry.enabled = unquote_toml_str(val).parse::<bool>().ok(),
            "args" => entry.args = parse_toml_string_array(val),
            "env" if val.starts_with('{') && val.ends_with('}') => {
                let inner = &val[1..val.len() - 1];
                for pair in inner.split(',') {
                    if let Some((ek, ev)) = pair.split_once('=') {
                        entry.env.insert(unquote_toml_str(ek), unquote_toml_str(ev));
                    }
                }
            }
            _ => {}
        }
    }

    for (raw_name, ts) in map {
        let name = server_label(&raw_name);
        let (args, match_tokens) = sanitize_args(
            ts.command.as_deref(),
            &ts.args,
            &name,
            source_file,
            findings,
        );
        let (env_keys, env_key_count) = inspect_env_map(&ts.env, &name, source_file, findings);
        let (header_keys, header_key_count) =
            inspect_header_keys(ts.header_keys.iter(), &name, source_file, findings);
        let url = ts.url.as_deref().map(url_label);
        let transport = if ts.url.is_some() {
            "http".to_string()
        } else {
            "stdio".to_string()
        };
        servers.push(ConfiguredMcpServer {
            server_name: name,
            client: client_from_path(source_file),
            enabled: ts.enabled != Some(false),
            source_file: source_file.to_string(),
            transport,
            command: ts.command.as_deref().map(redact_command),
            args_count: args.len(),
            args,
            url,
            env_keys,
            env_key_count,
            header_keys,
            header_key_count,
            match_tokens,
        });
    }
}

fn default_mcp_config_files(home_dir: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![
        // `~/.claude.json` and `~/.claude/**` are never opened (protected).
        home_dir.join(".codex").join("config.toml"),
        home_dir.join(".gemini").join("settings.json"),
        home_dir
            .join(".gemini")
            .join("antigravity")
            .join("mcp_config.json"),
        home_dir.join(".mcp.json"),
        home_dir.join(".cursor").join("mcp.json"),
        home_dir
            .join(".config")
            .join("opencode")
            .join("opencode.json"),
        home_dir
            .join(".config")
            .join("Code")
            .join("User")
            .join("mcp.json"),
        home_dir
            .join("Library")
            .join("Application Support")
            .join("Code")
            .join("User")
            .join("mcp.json"),
    ];
    if let Some(appdata) = std::env::var_os("APPDATA") {
        candidates.push(
            PathBuf::from(appdata)
                .join("Code")
                .join("User")
                .join("mcp.json"),
        );
    }
    candidates.into_iter().filter(|p| p.is_file()).collect()
}

/// Enumerates `*.json` / `*.toml` under explicit `--config-dir` roots. Every root and every
/// entry is protection-checked *before* it is descended into or named, entries are classified
/// without following symlinks, and a protected root yields a single `protected_target` warning
/// and nothing else.
fn collect_config_files_in_dirs(
    dirs: &[PathBuf],
    ctx: &ProtectionContext,
    warnings: &mut Vec<String>,
) -> Vec<PathBuf> {
    const MAX_DEPTH: usize = 3;
    let mut files = Vec::new();
    for dir in dirs {
        let canon = fs::canonicalize(dir).ok();
        let protected = check_path_protection(dir, ctx).protected
            || canon
                .as_ref()
                .is_some_and(|c| check_path_protection(c, ctx).protected);
        if protected {
            warnings.push(format!("protected_target: {}", dir.display()));
            continue;
        }
        let Ok(lm) = fs::symlink_metadata(dir) else {
            continue;
        };
        if lm.file_type().is_symlink() {
            warnings.push(format!("symlinked_config_dir not read: {}", dir.display()));
            continue;
        }
        if lm.is_file() {
            files.push(dir.clone());
            continue;
        }
        if !lm.is_dir() {
            continue;
        }
        // Every directory is listed through a no-follow handle bound to its canonical path;
        // a directory swapped for a symlink mid-walk can never redirect the listing.
        let canon_home = fs::canonicalize(&ctx.home_dir).unwrap_or_else(|_| ctx.home_dir.clone());
        let policy = ReadPolicy {
            ctx,
            canon_home: &canon_home,
            require_in_home: false,
        };
        let root = match SafeDir::open(dir, &policy, None) {
            Ok(h) => h,
            Err(ReadRefusal::Protected) => {
                warnings.push(format!("protected_target: {}", dir.display()));
                continue;
            }
            Err(r) => {
                warnings.push(format!(
                    "config dir not read ({}): {}",
                    r.code(),
                    dir.display()
                ));
                continue;
            }
        };
        let mut stack: Vec<(SafeDir, PathBuf, usize)> = vec![(root, dir.clone(), 0)];
        while let Some((handle, shown, depth)) = stack.pop() {
            let Ok(entries) = handle.entries() else {
                continue;
            };
            for (name, kind) in entries {
                let p = shown.join(&name);
                // protection first: a protected entry is neither descended into nor named
                if check_path_protection(&p, ctx).protected
                    || check_path_protection(&handle.canonical_path().join(&name), ctx).protected
                {
                    continue;
                }
                match kind {
                    EntryKind::Dir => {
                        if depth + 1 < MAX_DEPTH {
                            if let Ok(child) = handle.open_child(&name) {
                                stack.push((child, p, depth + 1));
                            }
                        }
                    }
                    EntryKind::File => {
                        if let Some(ext) = p.extension().and_then(|x| x.to_str()) {
                            if ext.eq_ignore_ascii_case("json") || ext.eq_ignore_ascii_case("toml")
                            {
                                files.push(p);
                            }
                        }
                    }
                    EntryKind::Symlink | EntryKind::Other => {}
                }
            }
        }
    }
    files.sort();
    files.dedup();
    files
}

/// Server label for a live process. It is only ever (a) the label of a config entry the
/// process matches, (b) a catalog package id, or (c) `unknown-<hash8(argv)>`; never a
/// substring of argv.
fn infer_mcp_server_name(
    command: &str,
    configured_servers: &[ConfiguredMcpServer],
) -> Option<String> {
    let low = command.to_ascii_lowercase();
    for srv in configured_servers {
        let name_low = srv.server_name.to_ascii_lowercase();
        if name_low.len() >= 3 && low.contains(&name_low) {
            return Some(srv.server_name.clone());
        }
        // the raw tokens only decide the match; the label shown is the config entry's own
        if srv.match_tokens.iter().any(|t| low.contains(t.as_str())) {
            return Some(srv.server_name.clone());
        }
    }
    if let Some(pkg) = known_package_in(command) {
        return Some(pkg);
    }
    let is_mcp_proc = low.contains("mcp") || low.contains("modelcontextprotocol");
    is_mcp_proc.then(|| unknown_label(command))
}

/// Owning client for a process: a catalog client or launcher of the parent, else
/// `unknown-<hash8(parent argv)>`.
fn infer_owning_client(ppid: u32, pid_map: &BTreeMap<u32, &ObservedProcess>) -> String {
    if ppid <= 1 {
        return "orphan(ppid=1)".to_string();
    }
    let Some(parent) = pid_map.get(&ppid) else {
        return format!("pid:{ppid}");
    };
    known_client(&parent.command)
        .or_else(|| known_command(&parent.command))
        .unwrap_or_else(|| unknown_label(&parent.command))
}

fn is_supervised_daemon_leader(command: &str) -> bool {
    let first = command.split_whitespace().next().unwrap_or("");
    let bin = Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(first)
        .to_ascii_lowercase();
    matches!(
        bin.as_str(),
        "launchd" | "systemd" | "init" | "dockerd" | "containerd" | "supervisord"
    )
}

pub fn parse_bsd_etime(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (days, rest) = match trimmed.split_once('-') {
        Some((d, r)) => (d.parse::<u64>().ok()?, r),
        None => (0, trimmed),
    };
    let parts: Vec<&str> = rest.split(':').collect();
    let hms_secs = match parts.as_slice() {
        [ss] => ss.parse::<u64>().ok()?,
        [mm, ss] => {
            let m = mm.parse::<u64>().ok()?;
            let s = ss.parse::<u64>().ok()?;
            m.saturating_mul(60).saturating_add(s)
        }
        [hh, mm, ss] => {
            let h = hh.parse::<u64>().ok()?;
            let m = mm.parse::<u64>().ok()?;
            let s = ss.parse::<u64>().ok()?;
            h.saturating_mul(3600)
                .saturating_add(m.saturating_mul(60))
                .saturating_add(s)
        }
        _ => return None,
    };
    Some(days.saturating_mul(86_400).saturating_add(hms_secs))
}

pub fn list_observed_processes_with_warnings() -> (Vec<ObservedProcess>, Vec<String>) {
    #[cfg(unix)]
    {
        let mut warnings = Vec::new();
        let out = match Command::new("/bin/ps")
            .args(["-axo", "pid=,ppid=,uid=,etime=,lstart=,args="])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                warnings.push(format!("/bin/ps failed to execute: {e}"));
                return (Vec::new(), warnings);
            }
        };
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            warnings.push(format!(
                "/bin/ps exited with status {}: {stderr}",
                out.status
            ));
            return (Vec::new(), warnings);
        }
        let mut procs = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // pid, ppid, uid, etime, lstart (5 tokens: Day Mon DD HH:MM:SS YYYY), args...
            if parts.len() < 10 {
                continue;
            }
            let Ok(pid) = parts[0].parse::<u32>() else {
                continue;
            };
            let Ok(ppid) = parts[1].parse::<u32>() else {
                continue;
            };
            let uid = parts[2].parse::<u32>().ok();
            let elapsed_secs = parse_bsd_etime(parts[3]).unwrap_or(0);
            let start_time = parts[4..9].join(" ");
            let command = parts[9..].join(" ");
            procs.push(ObservedProcess {
                pid,
                ppid,
                uid,
                start_time,
                elapsed_secs,
                command,
            });
        }
        if procs.is_empty() {
            warnings.push("/bin/ps returned zero parseable processes".to_string());
        }
        (procs, warnings)
    }
    #[cfg(windows)]
    {
        let mut warnings = Vec::new();
        let ps_script = "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,CreationDate,CommandLine,Name | ConvertTo-Json -Compress";
        let out = match Command::new("powershell")
            .args(["-NoProfile", "-Command", ps_script])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                warnings.push(format!("powershell process listing failed: {e}"));
                return (Vec::new(), warnings);
            }
        };
        if !out.status.success() {
            warnings.push(format!(
                "powershell process listing exited with status {}",
                out.status
            ));
            return (Vec::new(), warnings);
        }
        let Ok(val) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
            warnings.push("powershell process listing returned invalid JSON".to_string());
            return (Vec::new(), warnings);
        };
        let items = match val {
            serde_json::Value::Array(arr) => arr,
            obj @ serde_json::Value::Object(_) => vec![obj],
            _ => Vec::new(),
        };
        let mut procs = Vec::new();
        for item in items {
            let pid = item.get("ProcessId").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let ppid = item
                .get("ParentProcessId")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let start_time = item
                .get("CreationDate")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let command = item
                .get("CommandLine")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .or_else(|| item.get("Name").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string();
            procs.push(ObservedProcess {
                pid,
                ppid,
                uid: None,
                start_time,
                elapsed_secs: 0,
                command,
            });
        }
        (procs, warnings)
    }
}

pub fn list_observed_processes() -> Vec<ObservedProcess> {
    list_observed_processes_with_warnings().0
}

pub fn audit_mcp_with_processes(
    opts: &McpAuditOptions,
    processes: &[ObservedProcess],
) -> Result<McpAuditReport, SjError> {
    let ctx = match &opts.home_dir {
        Some(h) => ProtectionContext::new(h.clone(), Vec::new()),
        None => ProtectionContext::from_env(),
    };
    let canon_home = fs::canonicalize(&ctx.home_dir).unwrap_or_else(|_| ctx.home_dir.clone());
    let default_discovery = opts.config_dirs.is_empty();
    let mut scanned_files = Vec::new();
    let mut configured_servers = Vec::new();
    let mut secret_findings = Vec::new();
    let mut warnings = Vec::new();

    let files = if default_discovery {
        default_mcp_config_files(&ctx.home_dir)
    } else {
        collect_config_files_in_dirs(&opts.config_dirs, &ctx, &mut warnings)
    };
    // Default discovery stays inside the home; an explicit --config-dir may live elsewhere but
    // is never a symlink and never a protected root. Files are opened once without following
    // symlinks and read from the validated handle (no check-then-reopen window).
    let policy = ReadPolicy {
        ctx: &ctx,
        canon_home: &canon_home,
        require_in_home: default_discovery,
    };

    for file in files {
        let file_str = file.to_string_lossy().into_owned();
        if check_path_protection(&file, &ctx).protected {
            warnings.push(format!("protected_target: {file_str}"));
            continue;
        }
        let raw = match read_config_file(&file, &policy) {
            Ok(r) => r,
            Err(refusal) => {
                warnings.push(format!(
                    "config file not read ({}): {file_str}",
                    refusal.code()
                ));
                continue;
            }
        };
        scanned_files.push(file_str.clone());
        let is_toml = file
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("toml"));
        if is_toml {
            parse_toml_mcp_config(
                &raw,
                &file_str,
                &mut configured_servers,
                &mut secret_findings,
            );
        } else if let Err(err) = parse_json_mcp_config(
            &raw,
            &file_str,
            &mut configured_servers,
            &mut secret_findings,
        ) {
            warnings.push(err);
        }
    }

    let pid_map: BTreeMap<u32, &ObservedProcess> = processes.iter().map(|p| (p.pid, p)).collect();

    let mut running_processes = Vec::new();
    for proc_item in processes {
        let Some(server_name) = infer_mcp_server_name(&proc_item.command, &configured_servers)
        else {
            continue;
        };
        let is_orphan = proc_item.ppid == 1 && !is_supervised_daemon_leader(&proc_item.command);
        let owning_client = infer_owning_client(proc_item.ppid, &pid_map);
        let clean_cmd = redact_command(&proc_item.command);
        running_processes.push(RunningMcpProcess {
            pid: proc_item.pid,
            ppid: proc_item.ppid,
            server_name,
            owning_client,
            is_orphan,
            command: clean_cmd,
        });
    }
    running_processes.sort_by(|a, b| {
        a.server_name
            .cmp(&b.server_name)
            .then_with(|| a.pid.cmp(&b.pid))
    });

    let mut by_server: BTreeMap<String, Vec<&RunningMcpProcess>> = BTreeMap::new();
    for rp in &running_processes {
        by_server
            .entry(rp.server_name.clone())
            .or_default()
            .push(rp);
    }

    let mut duplicate_groups = Vec::new();
    for (server_name, group) in by_server {
        if group.len() >= 3 {
            let pids = group.iter().map(|p| p.pid).collect();
            let clients: BTreeSet<String> = group.iter().map(|p| p.owning_client.clone()).collect();
            duplicate_groups.push(DuplicateMcpGroup {
                server_name,
                count: group.len(),
                pids,
                owning_clients: clients.into_iter().collect(),
            });
        }
    }

    let orphan_processes: Vec<RunningMcpProcess> = running_processes
        .iter()
        .filter(|p| p.is_orphan)
        .cloned()
        .collect();

    Ok(McpAuditReport {
        schema: SCHEMA_MCP_AUDIT_V1.to_string(),
        scanned_files,
        configured_servers,
        running_processes,
        duplicate_groups,
        orphan_processes,
        secret_findings,
        warnings,
    })
}

pub fn audit_mcp_fleet(opts: &McpAuditOptions) -> Result<McpAuditReport, SjError> {
    let (processes, proc_warnings) = list_observed_processes_with_warnings();
    let mut report = audit_mcp_with_processes(opts, &processes)?;
    for w in proc_warnings {
        eprintln!("warning: {w}");
        report.warnings.push(w);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn mcp_audit_scans_json_and_toml_redacts_secrets_and_flags_duplicates_and_orphans() {
        let tmp = tempdir().unwrap();
        let json_cfg = tmp.path().join("mcp.json");
        let toml_cfg = tmp.path().join("config.toml");

        let dummy_secret_a = "dummy_secret_value_for_unit_test_9876";
        let dummy_secret_b = "dummy_arg_token_for_unit_test_5432";

        fs::write(
            &json_cfg,
            format!(
                r#"{{
  "mcpServers": {{
    "github-mcp": {{
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github", "--token={dummy_secret_b}"],
      "env": {{
        "GITHUB_TOKEN": "{dummy_secret_a}",
        "SAFE_VAR": "${{GITHUB_TOKEN}}"
      }}
    }}
  }}
}}"#
            ),
        )
        .unwrap();

        fs::write(
            &toml_cfg,
            format!(
                r#"
[mcp_servers.docs-mcp]
command = "uvx"
args = ["docs-mcp-server", "--api-key", "{dummy_secret_b}"]

[mcp_servers.docs-mcp.env]
DOCS_API_KEY = "{dummy_secret_a}"
"#
            ),
        )
        .unwrap();

        let processes = vec![
            ObservedProcess {
                pid: 100,
                ppid: 1,
                uid: None,
                start_time: "Mon Nov 24 10:00:00 2026".to_string(),
                elapsed_secs: 3600,
                command: "claude".to_string(),
            },
            ObservedProcess {
                pid: 201,
                ppid: 100,
                uid: None,
                start_time: "Mon Nov 24 10:01:00 2026".to_string(),
                elapsed_secs: 3500,
                command: format!(
                    "node @modelcontextprotocol/server-github --token={dummy_secret_b}"
                ),
            },
            ObservedProcess {
                pid: 202,
                ppid: 100,
                uid: None,
                start_time: "Mon Nov 24 10:02:00 2026".to_string(),
                elapsed_secs: 3400,
                command: "node @modelcontextprotocol/server-github".to_string(),
            },
            ObservedProcess {
                pid: 203,
                ppid: 1,
                uid: None,
                start_time: "Mon Nov 24 10:03:00 2026".to_string(),
                elapsed_secs: 3300,
                command: "node @modelcontextprotocol/server-github".to_string(),
            },
        ];

        let opts = McpAuditOptions {
            config_dirs: vec![tmp.path().to_path_buf()],
            home_dir: None,
        };
        let report = audit_mcp_with_processes(&opts, &processes).unwrap();

        assert_eq!(report.schema, SCHEMA_MCP_AUDIT_V1);
        assert_eq!(report.configured_servers.len(), 2);
        assert_eq!(report.duplicate_groups.len(), 1);
        assert_eq!(report.duplicate_groups[0].server_name, "github-mcp");
        assert_eq!(report.duplicate_groups[0].count, 3);
        assert_eq!(report.orphan_processes.len(), 1);
        assert_eq!(report.orphan_processes[0].pid, 203);
        assert!(report.secret_findings.len() >= 4);

        let serialized = serde_json::to_string_pretty(&report).unwrap();
        assert!(
            !serialized.contains(dummy_secret_a),
            "raw env secret leaked into serialized JSON!"
        );
        assert!(
            !serialized.contains(dummy_secret_b),
            "raw arg secret leaked into serialized JSON!"
        );
    }

    #[test]
    fn mcp_audit_never_leaks_url_credentials_or_secret_prefixes_and_parses_bsd_etime() {
        let tmp = tempdir().unwrap();
        let json_cfg = tmp.path().join("mcp.json");
        fs::write(
            &json_cfg,
            r#"{
  "mcpServers": {
    "remote-mcp": {
      "command": "npx",
      "args": [
        "-y",
        "remote-mcp",
        "https://alice:SUPER_URL_SECRET@example.com/mcp",
        "--token",
        "XYZ_PREFIX_SECRET_999"
      ],
      "env": {
        "API_KEY": "ABC_ENV_SECRET_888"
      }
    }
  }
}"#,
        )
        .unwrap();

        let opts = McpAuditOptions {
            config_dirs: vec![tmp.path().to_path_buf()],
            home_dir: None,
        };
        let report = audit_mcp_with_processes(&opts, &[]).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            !json.contains("SUPER_URL_SECRET"),
            "leaked URL secret: {json}"
        );
        assert!(
            !json.contains("alice:"),
            "leaked URL user in key_name: {json}"
        );
        assert!(!json.contains("XYZ***"), "leaked 3-char arg prefix: {json}");
        assert!(!json.contains("ABC***"), "leaked 3-char env prefix: {json}");
        assert!(report
            .secret_findings
            .iter()
            .all(|f| f.redacted_preview == "[REDACTED]"));

        assert_eq!(parse_bsd_etime("45"), Some(45));
        assert_eq!(parse_bsd_etime("05:30"), Some(330));
        assert_eq!(parse_bsd_etime("02:05:30"), Some(7530));
        assert_eq!(parse_bsd_etime("3-02:05:30"), Some(3 * 86400 + 7530));
    }

    #[test]
    fn mcp_audit_f2_key_name_never_carries_secret_bearing_text() {
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("mcp.json"),
            r#"{
  "mcpServers": {
    "colon-flag": { "command": "tool", "args": ["--token:CFGPROBE80zz", "next-arg"] },
    "glued-short": { "command": "mysql", "args": ["-pCFGPROBE81zz"] },
    "hdr-nospace": { "command": "npx", "args": ["mcp-remote", "https://example.com/mcp", "--header", "Authorization:Bearer", "CFGPROBE82zz"] },
    "exa": { "command": "npx", "args": ["-y", "mcp-remote", "https://mcp.exa.ai/mcp?exaApiKey=CFGPROBE84zz"] },
    "url-cred": { "command": "npx", "args": ["https://alice:CFGPROBE85zz@example.com/mcp"] },
    "kv-url": { "command": "npx", "args": ["--endpoint=https://u:CFGPROBE86zz@h/x", "TOKEN_X=CFGPROBE87zz"] }
  }
}"#,
        )
        .unwrap();
        let opts = McpAuditOptions {
            config_dirs: vec![tmp.path().to_path_buf()],
            home_dir: None,
        };
        let report = audit_mcp_with_processes(&opts, &[]).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("CFGPROBE"), "secret text leaked: {json}");
        for f in &report.secret_findings {
            assert!(
                f.key_name == "<REDACTED>"
                    || (f.key_name.len() <= 48
                        && f.key_name
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))),
                "unsafe key_name {:?}",
                f.key_name
            );
        }
    }

    #[test]
    fn mcp_audit_redacted_placeholder_args_never_match_unrelated_processes() {
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("mcp.json"),
            r#"{"mcpServers":{"zzsolo":{"command":"npx","args":["zz-solo-mcp","--token","SOLO_SECRET_VALUE"]}}}"#,
        )
        .unwrap();
        let procs = vec![ObservedProcess {
            pid: 900,
            ppid: 800,
            uid: None,
            start_time: String::new(),
            elapsed_secs: 10,
            command: "other-tool --note <REDACTED> mcp".to_string(),
        }];
        let report = audit_mcp_with_processes(
            &McpAuditOptions {
                config_dirs: vec![tmp.path().to_path_buf()],
                home_dir: None,
            },
            &procs,
        )
        .unwrap();
        assert!(
            report
                .running_processes
                .iter()
                .all(|r| r.server_name != "zzsolo"),
            "{:?}",
            report.running_processes
        );
    }
}
