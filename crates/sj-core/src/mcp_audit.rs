use crate::protect::ProtectionContext;
use crate::{redact_secrets, SjError, SCHEMA_MCP_AUDIT_V1};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct McpAuditOptions {
    pub config_dirs: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservedProcess {
    pub pid: u32,
    pub ppid: u32,
    pub start_time: String,
    pub elapsed_secs: u64,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfiguredMcpServer {
    pub server_name: String,
    pub source_file: String,
    pub transport: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env_keys: Vec<String>,
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
    if t.is_empty() || is_env_var_reference(t) {
        return false;
    }
    let low = t.to_ascii_lowercase();
    low.starts_with("sk-")
        || low.starts_with("sk_")
        || low.starts_with("ghp_")
        || low.starts_with("github_pat_")
        || low.starts_with("akia")
        || low.starts_with("xoxb-")
        || low.starts_with("xoxp-")
        || low.starts_with("bearer ")
        || low.starts_with("basic ")
}

fn redact_secret_preview(val: &str) -> String {
    let t = val.trim();
    if t.len() >= 4 {
        let prefix: String = t.chars().take(3).collect();
        format!("{prefix}***REDACTED***")
    } else {
        "***REDACTED***".to_string()
    }
}

fn redact_arg_token(arg: &str) -> (String, Option<(String, String)>) {
    let redacted = redact_secrets(arg);
    if redacted != arg {
        let key = arg
            .split('=')
            .next()
            .unwrap_or("arg")
            .trim_start_matches('-')
            .to_string();
        return (redacted, Some((key, "***REDACTED***".to_string())));
    }
    if let Some((k, v)) = arg.split_once('=') {
        if is_sensitive_env_key(k) || looks_like_secret_value(v) {
            let preview = redact_secret_preview(v);
            return (format!("{k}=<REDACTED>"), Some((k.to_string(), preview)));
        }
    }
    if looks_like_secret_value(arg) {
        return (
            "<REDACTED>".to_string(),
            Some(("inline_arg".to_string(), redact_secret_preview(arg))),
        );
    }
    (arg.to_string(), None)
}

fn sanitize_args(
    args: &[String],
    server_name: &str,
    source_file: &str,
    findings: &mut Vec<SecretFinding>,
) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut redact_next_flag: Option<String> = None;

    for arg in args {
        if let Some(flag_name) = redact_next_flag.take() {
            findings.push(SecretFinding {
                server_name: server_name.to_string(),
                source_file: source_file.to_string(),
                location: "args".to_string(),
                key_name: flag_name,
                redacted_preview: redact_secret_preview(arg),
            });
            out.push("<REDACTED>".to_string());
            continue;
        }
        let low = arg.to_ascii_lowercase();
        if matches!(
            low.as_str(),
            "--api-key" | "--token" | "--secret" | "--password" | "--auth-token" | "--auth"
        ) {
            redact_next_flag = Some(arg.trim_start_matches('-').to_string());
            out.push(arg.clone());
            continue;
        }
        let (clean, maybe_finding) = redact_arg_token(arg);
        if let Some((key_name, redacted_preview)) = maybe_finding {
            findings.push(SecretFinding {
                server_name: server_name.to_string(),
                source_file: source_file.to_string(),
                location: "args".to_string(),
                key_name,
                redacted_preview,
            });
        }
        out.push(clean);
    }
    out
}

fn inspect_env_map(
    env_map: &BTreeMap<String, String>,
    server_name: &str,
    source_file: &str,
    findings: &mut Vec<SecretFinding>,
) -> Vec<String> {
    let mut keys = Vec::new();
    for (k, v) in env_map {
        keys.push(k.clone());
        if !v.trim().is_empty()
            && !is_env_var_reference(v)
            && (is_sensitive_env_key(k) || looks_like_secret_value(v))
        {
            findings.push(SecretFinding {
                server_name: server_name.to_string(),
                source_file: source_file.to_string(),
                location: "env".to_string(),
                key_name: k.clone(),
                redacted_preview: redact_secret_preview(v),
            });
        }
    }
    keys
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
            let command = cfg_obj
                .get("command")
                .and_then(|v| v.as_str())
                .map(redact_secrets);
            let raw_args: Vec<String> = cfg_obj
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(ToString::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let args = sanitize_args(&raw_args, name, source_file, findings);

            let mut env_map = BTreeMap::new();
            if let Some(env_obj) = cfg_obj.get("env").and_then(|v| v.as_object()) {
                for (ek, ev) in env_obj {
                    if let Some(ev_str) = ev.as_str() {
                        env_map.insert(ek.clone(), ev_str.to_string());
                    }
                }
            }
            let env_keys = inspect_env_map(&env_map, name, source_file, findings);
            let transport = if cfg_obj.contains_key("url") {
                "http".to_string()
            } else {
                "stdio".to_string()
            };

            servers.push(ConfiguredMcpServer {
                server_name: name.clone(),
                source_file: source_file.to_string(),
                transport,
                command,
                args,
                env_keys,
            });
        }
        break;
    }

    Ok(())
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
        args: Vec<String>,
        env: BTreeMap<String, String>,
    }

    let mut map: BTreeMap<String, TempServer> = BTreeMap::new();
    let mut current_server: Option<String> = None;
    let mut in_env_section = false;

    for raw_line in raw.lines() {
        let line = strip_toml_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim();
            if let Some(rest) = section.strip_prefix("mcp_servers.") {
                if let Some(name) = rest.strip_suffix(".env") {
                    current_server = Some(unquote_toml_str(name));
                    in_env_section = true;
                } else {
                    current_server = Some(unquote_toml_str(rest));
                    in_env_section = false;
                }
            } else {
                current_server = None;
                in_env_section = false;
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

        if in_env_section {
            entry.env.insert(key, unquote_toml_str(val));
            continue;
        }
        match key.as_str() {
            "command" => entry.command = Some(redact_secrets(&unquote_toml_str(val))),
            "url" => entry.url = Some(unquote_toml_str(val)),
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

    for (name, ts) in map {
        let args = sanitize_args(&ts.args, &name, source_file, findings);
        let env_keys = inspect_env_map(&ts.env, &name, source_file, findings);
        let transport = if ts.url.is_some() {
            "http".to_string()
        } else {
            "stdio".to_string()
        };
        servers.push(ConfiguredMcpServer {
            server_name: name,
            source_file: source_file.to_string(),
            transport,
            command: ts.command,
            args,
            env_keys,
        });
    }
}

fn default_mcp_config_files(home_dir: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![
        home_dir.join(".claude.json"),
        home_dir.join(".claude").join("settings.json"),
        home_dir.join(".codex").join("config.toml"),
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

fn collect_config_files_in_dirs(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for dir in dirs {
        if dir.is_file() {
            files.push(dir.clone());
            continue;
        }
        if !dir.is_dir() {
            continue;
        }
        for entry in jwalk::WalkDir::new(dir)
            .max_depth(3)
            .follow_links(false)
            .skip_hidden(false)
            .into_iter()
            .flatten()
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let p = entry.path();
            if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                if ext.eq_ignore_ascii_case("json") || ext.eq_ignore_ascii_case("toml") {
                    files.push(p);
                }
            }
        }
    }
    files.sort();
    files.dedup();
    files
}

fn infer_mcp_server_name(
    command: &str,
    configured_servers: &[ConfiguredMcpServer],
) -> Option<String> {
    let low = command.to_ascii_lowercase();
    for srv in configured_servers {
        let name_low = srv.server_name.to_ascii_lowercase();
        if low.contains(&name_low) {
            return Some(srv.server_name.clone());
        }
        for arg in &srv.args {
            let arg_low = arg.to_ascii_lowercase();
            if !arg_low.starts_with('-') && arg_low.len() >= 6 && low.contains(&arg_low) {
                return Some(srv.server_name.clone());
            }
        }
    }
    let is_mcp_proc = low.contains("mcp") || low.contains("modelcontextprotocol");
    if !is_mcp_proc {
        return None;
    }
    for tok in command.split_whitespace() {
        let clean = tok.trim_matches(|c| c == '"' || c == '\'');
        if clean.starts_with('-')
            || matches!(
                clean,
                "node" | "npx" | "npm" | "exec" | "uvx" | "python" | "python3" | "-y" | "--yes"
            )
        {
            continue;
        }
        if clean.to_ascii_lowercase().contains("mcp") {
            let base = Path::new(clean)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(clean);
            return Some(base.to_string());
        }
    }
    Some("mcp-server".to_string())
}

fn infer_owning_client(ppid: u32, pid_map: &BTreeMap<u32, &ObservedProcess>) -> String {
    if ppid <= 1 {
        return "orphan(ppid=1)".to_string();
    }
    let Some(parent) = pid_map.get(&ppid) else {
        return format!("pid:{ppid}");
    };
    let low = parent.command.to_ascii_lowercase();
    for client in [
        "claude", "codex", "cursor", "opencode", "code", "zed", "windsurf",
    ] {
        if low.contains(client) {
            return client.to_string();
        }
    }
    Path::new(
        parent
            .command
            .split_whitespace()
            .next()
            .unwrap_or("unknown"),
    )
    .file_name()
    .and_then(|s| s.to_str())
    .unwrap_or("unknown")
    .to_string()
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

pub fn list_observed_processes() -> Vec<ObservedProcess> {
    #[cfg(unix)]
    {
        let Ok(out) = Command::new("ps")
            .args(["-axo", "pid=,ppid=,etimes=,lstart=,args="])
            .output()
        else {
            return Vec::new();
        };
        if !out.status.success() {
            return Vec::new();
        }
        let mut procs = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // pid, ppid, etimes, lstart (5 tokens: Day Mon DD HH:MM:SS YYYY), args...
            if parts.len() < 9 {
                continue;
            }
            let Ok(pid) = parts[0].parse::<u32>() else {
                continue;
            };
            let Ok(ppid) = parts[1].parse::<u32>() else {
                continue;
            };
            let elapsed_secs = parts[2].parse::<u64>().unwrap_or(0);
            let start_time = parts[3..8].join(" ");
            let command = parts[8..].join(" ");
            procs.push(ObservedProcess {
                pid,
                ppid,
                start_time,
                elapsed_secs,
                command,
            });
        }
        procs
    }
    #[cfg(windows)]
    {
        let ps_script = "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,CreationDate,CommandLine,Name | ConvertTo-Json -Compress";
        let Ok(out) = Command::new("powershell")
            .args(["-NoProfile", "-Command", ps_script])
            .output()
        else {
            return Vec::new();
        };
        if !out.status.success() {
            return Vec::new();
        }
        let Ok(val) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
            return Vec::new();
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
                start_time,
                elapsed_secs: 0,
                command,
            });
        }
        procs
    }
}

pub fn audit_mcp_with_processes(
    opts: &McpAuditOptions,
    processes: &[ObservedProcess],
) -> Result<McpAuditReport, SjError> {
    let ctx = ProtectionContext::from_env();
    let files = if opts.config_dirs.is_empty() {
        default_mcp_config_files(&ctx.home_dir)
    } else {
        collect_config_files_in_dirs(&opts.config_dirs)
    };

    let mut scanned_files = Vec::new();
    let mut configured_servers = Vec::new();
    let mut secret_findings = Vec::new();
    let mut warnings = Vec::new();

    for file in files {
        let file_str = file.to_string_lossy().into_owned();
        let Ok(raw) = fs::read_to_string(&file) else {
            warnings.push(format!("unreadable config file: {file_str}"));
            continue;
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
        let (clean_cmd, _) = redact_arg_token(&proc_item.command);
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
    let processes = list_observed_processes();
    audit_mcp_with_processes(opts, &processes)
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
                start_time: "Mon Nov 24 10:00:00 2026".to_string(),
                elapsed_secs: 3600,
                command: "claude".to_string(),
            },
            ObservedProcess {
                pid: 201,
                ppid: 100,
                start_time: "Mon Nov 24 10:01:00 2026".to_string(),
                elapsed_secs: 3500,
                command: format!(
                    "node @modelcontextprotocol/server-github --token={dummy_secret_b}"
                ),
            },
            ObservedProcess {
                pid: 202,
                ppid: 100,
                start_time: "Mon Nov 24 10:02:00 2026".to_string(),
                elapsed_secs: 3400,
                command: "node @modelcontextprotocol/server-github".to_string(),
            },
            ObservedProcess {
                pid: 203,
                ppid: 1,
                start_time: "Mon Nov 24 10:03:00 2026".to_string(),
                elapsed_secs: 3300,
                command: "node @modelcontextprotocol/server-github".to_string(),
            },
        ];

        let opts = McpAuditOptions {
            config_dirs: vec![tmp.path().to_path_buf()],
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
}
