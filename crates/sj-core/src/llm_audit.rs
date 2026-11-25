//! Read-only audit of LLM-client plugins, skills, configured MCP servers and live idle
//! MCP agent sessions. Everything here is dry-run: nothing is moved, edited or signalled.
//!
//! Ported from the SpaceJanitor bot's `mcp_plugin_audit.py` reference behaviour.
//! Names and mtimes are inventoried; file *contents* are only read for client config
//! files that are not protected (`~/.claude/**`, `~/.claude.json`, Claude app support
//! are never opened).

use crate::mcp_audit::{audit_mcp_with_processes, McpAuditOptions};
use crate::protect::{check_path_protection, ProtectionContext};
use crate::SjError;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub const SCHEMA_LLM_AUDIT_V1: &str = "spacejanitor.llm_audit.v1";

#[derive(Debug, Clone)]
pub struct AuditPolicy {
    pub idle_session_hours: f64,
    pub unused_skill_days: u64,
    pub keep_enabled_mcps: Vec<String>,
    pub keep_enabled_plugins: Vec<String>,
    pub keep_enabled_skills: Vec<String>,
}

impl Default for AuditPolicy {
    fn default() -> Self {
        let own = |xs: &[&str]| xs.iter().map(|s| (*s).to_string()).collect();
        Self {
            idle_session_hours: 2.0,
            unused_skill_days: 30,
            keep_enabled_mcps: own(&["multillm", "node_repl"]),
            keep_enabled_plugins: own(&[
                "codex-app-tools@openai-bundled",
                "codex-security@openai-curated",
                "github@openai-curated",
                "superpowers@openai-curated",
                "ecc@ecc-codex",
                "tracing@codex-observability-plugin",
                "chrome-devtools-plugin",
                "google-antigravity-sdk",
            ]),
            keep_enabled_skills: own(&[
                "caveman",
                "orca-cli",
                "orchestration",
                "poteto-mode",
                "no-mistakes",
                "review",
                "secure-dev",
                "security-review",
                "oci-administrator",
                "diagnosing-bugs",
                "codebase-design",
                "design-an-interface",
                "grilling",
                "gh-axi",
                "chrome-devtools-axi",
            ]),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LlmAuditOptions {
    pub home_dir: PathBuf,
    pub policy: AuditPolicy,
    /// Unix seconds; `None` = system clock. Tests pin this.
    pub now_epoch_secs: Option<u64>,
}

/// One live process with the extra columns the idle-session detector needs.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LiveProc {
    pub pid: u32,
    pub ppid: u32,
    pub uid: Option<u32>,
    pub cpu_pct: f64,
    pub rss_kib: u64,
    pub elapsed_secs: u64,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginEntry {
    pub rule_id: String,
    pub client: String,
    pub plugin_id: String,
    pub enabled: bool,
    pub kept_by_policy: bool,
    pub read_only: bool,
    pub disable_candidate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StalePluginCache {
    pub plugin_id: String,
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SkillClientSummary {
    pub total: usize,
    pub symlinks: usize,
    pub real_dirs: usize,
    pub broken_symlinks: usize,
    pub stale_candidates: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StaleSkill {
    pub rule_id: String,
    pub client: String,
    pub name: String,
    pub path: String,
    pub quarantine_dest: String,
    pub age_days: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrokenSkillLink {
    pub rule_id: String,
    pub client: String,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DuplicateSkill {
    pub name: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnusedMcpServer {
    pub client: String,
    pub server_name: String,
    pub source_file: String,
    pub transport: String,
    /// Count only; env values and keys are never echoed here.
    pub env_keys_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IdleSession {
    pub pid: u32,
    pub agent: String,
    pub elapsed_secs: u64,
    pub cpu_pct: f64,
    pub mcp_proc_count: usize,
    pub mcp_rss_mib: f64,
    pub non_mcp_work_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlannedAction {
    pub rule_id: String,
    /// `disable_plugin` | `quarantine_plugin_cache` | `quarantine_skill` | `remove_broken_symlink`
    /// | `disable_mcp_server` | `terminate_idle_session`
    pub kind: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    pub protected: bool,
    pub protection_reason: String,
    /// Always false in this release: no mutating path is implemented.
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SymlinkedRoot {
    pub client: String,
    pub path: String,
    /// Link target as text only; the target is never opened or enumerated.
    pub target: String,
    pub target_protected: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LlmAuditReport {
    pub schema: String,
    pub mode: String,
    pub mutated: bool,
    pub plugins: Vec<PluginEntry>,
    pub stale_plugin_caches: Vec<StalePluginCache>,
    pub skills_by_client: BTreeMap<String, SkillClientSummary>,
    pub stale_skills: Vec<StaleSkill>,
    pub broken_skill_symlinks: Vec<BrokenSkillLink>,
    pub symlinked_roots: Vec<SymlinkedRoot>,
    pub duplicate_skill_dirs: Vec<DuplicateSkill>,
    pub unused_mcp_servers: Vec<UnusedMcpServer>,
    pub idle_sessions: Vec<IdleSession>,
    pub planned_actions: Vec<PlannedAction>,
    pub warnings: Vec<String>,
}

fn slug(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

fn unquote(raw: &str) -> String {
    let t = raw.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

fn strip_comment(line: &str) -> &str {
    let (mut sq, mut dq) = (false, false);
    for (i, c) in line.char_indices() {
        match c {
            '"' if !sq => dq = !dq,
            '\'' if !dq => sq = !sq,
            '#' if !sq && !dq => return &line[..i],
            _ => {}
        }
    }
    line
}

/// `[plugins."name@market"] enabled = true|false` from a Codex `config.toml`.
fn parse_codex_plugin_states(raw: &str) -> BTreeMap<String, bool> {
    let mut out = BTreeMap::new();
    let mut cur: Option<String> = None;
    for line in raw.lines() {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim();
            cur = section.strip_prefix("plugins.").map(unquote);
            if let Some(name) = &cur {
                out.entry(name.clone()).or_insert(false);
            }
            continue;
        }
        if let (Some(name), Some((k, v))) = (&cur, line.split_once('=')) {
            if k.trim() == "enabled" {
                out.insert(name.clone(), unquote(v) == "true");
            }
        }
    }
    out
}

/// If `root` is itself a symlink, records it (target as text, protection of the canonical
/// target) and returns true so the caller never descends into it.
fn note_symlinked_root(
    client: &str,
    root: &Path,
    ctx: &ProtectionContext,
    out: &mut Vec<SymlinkedRoot>,
) -> bool {
    let Ok(meta) = fs::symlink_metadata(root) else {
        return false;
    };
    if !meta.file_type().is_symlink() {
        return false;
    }
    let target = fs::read_link(root)
        .map(|t| t.to_string_lossy().into_owned())
        .unwrap_or_default();
    let target_protected = match fs::canonicalize(root) {
        Ok(canon) => check_path_protection(&canon, ctx).protected,
        Err(_) => true,
    };
    out.push(SymlinkedRoot {
        client: client.to_string(),
        path: root.to_string_lossy().into_owned(),
        target,
        target_protected,
    });
    true
}

/// Names of real (non-symlink) subdirectories. Never follows a symlinked root or entry.
fn dir_names(dir: &Path) -> Vec<String> {
    if fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink()) {
        return Vec::new();
    }
    let mut v: Vec<String> = fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| !n.starts_with('.'))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn newest_mtime_secs(dir: &Path) -> u64 {
    fn mt(p: &Path) -> u64 {
        fs::symlink_metadata(p)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs())
    }
    fn walk(dir: &Path, depth: usize, newest: &mut u64) {
        if depth > 2 {
            return;
        }
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten().take(40) {
            let p = e.path();
            *newest = (*newest).max(mt(&p));
            if p.is_dir() && !e.file_type().is_ok_and(|t| t.is_symlink()) {
                walk(&p, depth + 1, newest);
            }
        }
    }
    let mut newest = mt(dir);
    walk(dir, 0, &mut newest);
    newest
}

fn basename_lower(command: &str) -> String {
    let first = command.split_whitespace().next().unwrap_or("");
    Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(first)
        .to_ascii_lowercase()
}

fn is_mcp_command(command: &str) -> bool {
    let low = command.to_ascii_lowercase();
    if low.contains("--type=renderer")
        || low.contains("--type=gpu-process")
        || low.contains("--type=utility")
        || low.contains("mcp_plugin_audit")
        || low.contains("space_audit")
    {
        return false;
    }
    if matches!(
        basename_lower(command).as_str(),
        "sh" | "zsh" | "bash" | "dash" | "sj"
    ) {
        return false;
    }
    low.contains("mcp") || low.contains("modelcontextprotocol")
}

const AGENT_BASENAMES: &[&str] = &["codex", "claude", "agy", "opencode", "cursor"];

pub fn detect_idle_sessions(
    procs: &[LiveProc],
    idle_hours: f64,
    own_uid: Option<u32>,
) -> Vec<IdleSession> {
    let by_pid: BTreeMap<u32, &LiveProc> = procs.iter().map(|p| (p.pid, p)).collect();
    let mut kids: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for p in procs {
        kids.entry(p.ppid).or_default().push(p.pid);
    }
    let subtree = |root: u32| -> Vec<u32> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::from([root]);
        let mut stack: Vec<u32> = kids.get(&root).cloned().unwrap_or_default();
        while let Some(x) = stack.pop() {
            if !seen.insert(x) {
                continue;
            }
            out.push(x);
            stack.extend(kids.get(&x).cloned().unwrap_or_default());
        }
        out
    };
    let min_secs = (idle_hours * 3600.0) as u64;
    let mut out = Vec::new();
    for p in procs {
        let base = basename_lower(&p.command);
        if !AGENT_BASENAMES.contains(&base.as_str())
            || crate::reap::is_protected_wrapper(&p.command)
        {
            continue;
        }
        // Scope to our own sessions; an unknown or foreign owner is never a candidate.
        if own_uid.is_none() || p.uid != own_uid {
            continue;
        }
        let sub = subtree(p.pid);
        let mcp: Vec<u32> = sub
            .iter()
            .copied()
            .filter(|c| is_mcp_command(&by_pid[c].command))
            .collect();
        if mcp.is_empty() {
            continue;
        }
        let work = sub
            .iter()
            .filter(|c| !mcp.contains(c) && !crate::reap::is_protected_wrapper(&by_pid[*c].command))
            .count();
        if p.elapsed_secs >= min_secs && p.cpu_pct <= 1.0 && work == 0 {
            let rss: u64 = mcp.iter().map(|c| by_pid[c].rss_kib).sum();
            out.push(IdleSession {
                pid: p.pid,
                agent: base,
                elapsed_secs: p.elapsed_secs,
                cpu_pct: p.cpu_pct,
                mcp_proc_count: mcp.len(),
                mcp_rss_mib: (rss as f64 / 1024.0 * 10.0).round() / 10.0,
                non_mcp_work_count: work,
            });
        }
    }
    out.sort_by(|a, b| {
        b.mcp_rss_mib
            .partial_cmp(&a.mcp_rss_mib)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.pid.cmp(&b.pid))
    });
    out
}

fn own_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        Some(unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    {
        None
    }
}

fn action(
    ctx: &ProtectionContext,
    rule_id: &str,
    kind: &str,
    target: &Path,
    dest: Option<&Path>,
) -> PlannedAction {
    let v = check_path_protection(target, ctx);
    PlannedAction {
        rule_id: rule_id.to_string(),
        kind: kind.to_string(),
        target: target.to_string_lossy().into_owned(),
        destination: dest.map(|d| d.to_string_lossy().into_owned()),
        protected: v.protected,
        protection_reason: v.reason,
        executable: false,
    }
}

pub fn audit_llm_with_processes(
    opts: &LlmAuditOptions,
    procs: &[LiveProc],
) -> Result<LlmAuditReport, SjError> {
    let home = &opts.home_dir;
    let pol = &opts.policy;
    let ctx = ProtectionContext::new(home.clone(), Vec::new());
    let now = opts.now_epoch_secs.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    });
    let keep_plugins: BTreeSet<&str> = pol
        .keep_enabled_plugins
        .iter()
        .map(String::as_str)
        .collect();
    let keep_skills: BTreeSet<&str> = pol.keep_enabled_skills.iter().map(String::as_str).collect();
    let keep_mcps: BTreeSet<&str> = pol.keep_enabled_mcps.iter().map(String::as_str).collect();
    let mut warnings = Vec::new();
    let mut actions: Vec<PlannedAction> = Vec::new();

    // 1. plugins
    let mut plugins = Vec::new();
    let mut stale_caches = Vec::new();
    let codex_toml = home.join(".codex").join("config.toml");
    let mut states = BTreeMap::new();
    if codex_toml.is_file() && !check_path_protection(&codex_toml, &ctx).protected {
        match fs::read_to_string(&codex_toml) {
            Ok(raw) => states = parse_codex_plugin_states(&raw),
            Err(e) => warnings.push(format!("unreadable codex config: {e}")),
        }
    }
    for (id, enabled) in &states {
        let kept = keep_plugins.contains(id.as_str());
        let cand = *enabled && !kept;
        let rule_id = format!("plugin-codex-{}", slug(id));
        if cand {
            actions.push(action(&ctx, &rule_id, "disable_plugin", &codex_toml, None));
        }
        plugins.push(PluginEntry {
            rule_id,
            client: "codex".into(),
            plugin_id: id.clone(),
            enabled: *enabled,
            kept_by_policy: kept,
            read_only: false,
            disable_candidate: cand,
        });
    }
    let mut symlinked_roots: Vec<SymlinkedRoot> = Vec::new();
    let cache = home.join(".codex").join("plugins").join("cache");
    note_symlinked_root("codex", &cache, &ctx, &mut symlinked_roots);
    for mkt in dir_names(&cache) {
        for plug in dir_names(&cache.join(&mkt)) {
            let id = format!("{plug}@{mkt}");
            if states.get(&id) == Some(&false) {
                let path = cache.join(&mkt).join(&plug);
                let dest = cache
                    .parent()
                    .map(|p| p.join("cache-disabled").join(&mkt).join(&plug));
                actions.push(action(
                    &ctx,
                    &format!("plugin-cache-codex-{}", slug(&id)),
                    "quarantine_plugin_cache",
                    &path,
                    dest.as_deref(),
                ));
                stale_caches.push(StalePluginCache {
                    plugin_id: id,
                    path: path.to_string_lossy().into_owned(),
                    reason: "disabled_in_codex_config".into(),
                });
            }
        }
    }
    for (client, dir) in [
        (
            "gemini",
            home.join(".gemini").join("config").join("plugins"),
        ),
        ("gemini-extension", home.join(".gemini").join("extensions")),
    ] {
        note_symlinked_root(client, &dir, &ctx, &mut symlinked_roots);
        for name in dir_names(&dir) {
            plugins.push(PluginEntry {
                rule_id: format!("plugin-{client}-{}", slug(&name)),
                client: client.into(),
                kept_by_policy: keep_plugins.contains(name.as_str()),
                plugin_id: name,
                enabled: true,
                read_only: false,
                disable_candidate: false,
            });
        }
    }
    // Claude: directory names only, never file contents, never a candidate.
    let claude_plugins = home.join(".claude").join("plugins");
    note_symlinked_root("claude", &claude_plugins, &ctx, &mut symlinked_roots);
    for name in dir_names(&claude_plugins) {
        plugins.push(PluginEntry {
            rule_id: format!("plugin-claude-{}", slug(&name)),
            client: "claude".into(),
            plugin_id: name,
            enabled: true,
            kept_by_policy: true,
            read_only: true,
            disable_candidate: false,
        });
    }

    // 2. skills
    let roots: [(&str, PathBuf, bool); 5] = [
        ("agents", home.join(".agents").join("skills"), false),
        ("codex", home.join(".codex").join("skills"), false),
        ("gemini", home.join(".gemini").join("skills"), false),
        ("cursor", home.join(".cursor").join("skills"), false),
        ("claude", home.join(".claude").join("skills"), true),
    ];
    let mut by_client = BTreeMap::new();
    let mut stale_skills = Vec::new();
    let mut broken = Vec::new();
    let mut real_locations: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (client, root, force_ro) in &roots {
        // Never open a symlinked skills root: it may point into a protected tree.
        if note_symlinked_root(client, root, &ctx, &mut symlinked_roots) {
            continue;
        }
        let Ok(rd) = fs::read_dir(root) else { continue };
        let ro = *force_ro || check_path_protection(root, &ctx).protected;
        let mut sum = SkillClientSummary::default();
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            sum.total += 1;
            let path = e.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                sum.symlinks += 1;
                if !ro && fs::metadata(&path).is_err() {
                    sum.broken_symlinks += 1;
                    let rule_id = format!("skill-broken-{}-{}", slug(client), slug(&name));
                    actions.push(action(&ctx, &rule_id, "remove_broken_symlink", &path, None));
                    broken.push(BrokenSkillLink {
                        rule_id,
                        client: (*client).into(),
                        name,
                        path: path.to_string_lossy().into_owned(),
                    });
                }
                // a valid symlink is never stale (it may point into a protected root)
                continue;
            }
            if !meta.is_dir() {
                continue;
            }
            sum.real_dirs += 1;
            if ro {
                continue;
            }
            real_locations
                .entry(name.clone())
                .or_default()
                .push(path.to_string_lossy().into_owned());
            if keep_skills.contains(name.as_str()) {
                continue;
            }
            let newest = newest_mtime_secs(&path);
            let age_days = (now.saturating_sub(newest)) as f64 / 86_400.0;
            if age_days >= opts.policy.unused_skill_days as f64 {
                sum.stale_candidates += 1;
                let dir_name = root
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("skills");
                let dest = root
                    .parent()
                    .unwrap_or(root)
                    .join(format!("{dir_name}-disabled"))
                    .join(&name);
                let rule_id = format!("skill-{}-{}", slug(client), slug(&name));
                actions.push(action(
                    &ctx,
                    &rule_id,
                    "quarantine_skill",
                    &path,
                    Some(&dest),
                ));
                stale_skills.push(StaleSkill {
                    rule_id,
                    client: (*client).into(),
                    name,
                    path: path.to_string_lossy().into_owned(),
                    quarantine_dest: dest.to_string_lossy().into_owned(),
                    age_days: (age_days * 10.0).round() / 10.0,
                });
            }
        }
        by_client.insert((*client).to_string(), sum);
    }
    let duplicate_skill_dirs: Vec<DuplicateSkill> = real_locations
        .into_iter()
        .filter(|(_, v)| v.len() > 1)
        .map(|(name, mut paths)| {
            paths.sort();
            DuplicateSkill { name, paths }
        })
        .collect();

    // 3. configured-but-unused MCP servers (secret-safe: counts only)
    let observed: Vec<crate::mcp_audit::ObservedProcess> = procs
        .iter()
        .map(|p| crate::mcp_audit::ObservedProcess {
            pid: p.pid,
            ppid: p.ppid,
            uid: p.uid,
            start_time: String::new(),
            elapsed_secs: p.elapsed_secs,
            command: p.command.clone(),
        })
        .collect();
    let mcp = audit_mcp_with_processes(
        &McpAuditOptions {
            config_dirs: Vec::new(),
            home_dir: Some(home.clone()),
        },
        &observed,
    )?;
    warnings.extend(mcp.warnings.iter().cloned());
    let running: BTreeSet<&str> = mcp
        .running_processes
        .iter()
        .map(|r| r.server_name.as_str())
        .collect();
    let mut unused = Vec::new();
    for srv in &mcp.configured_servers {
        if !srv.enabled
            || srv.client == "claude"
            || keep_mcps.contains(srv.server_name.as_str())
            || running.contains(srv.server_name.as_str())
        {
            continue;
        }
        let rule_id = format!("mcp-{}-{}", slug(&srv.client), slug(&srv.server_name));
        actions.push(action(
            &ctx,
            &rule_id,
            "disable_mcp_server",
            Path::new(&srv.source_file),
            None,
        ));
        unused.push(UnusedMcpServer {
            client: srv.client.clone(),
            server_name: srv.server_name.clone(),
            source_file: srv.source_file.clone(),
            transport: srv.transport.clone(),
            env_keys_count: srv.env_keys.len(),
        });
    }

    // 4. live idle sessions
    let idle_sessions = detect_idle_sessions(procs, pol.idle_session_hours, own_uid());
    for s in &idle_sessions {
        actions.push(PlannedAction {
            rule_id: format!("session-{}-{}", s.agent, s.pid),
            kind: "terminate_idle_session".into(),
            target: format!("pid:{}", s.pid),
            destination: None,
            protected: false,
            protection_reason: String::new(),
            executable: false,
        });
    }

    actions.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    Ok(LlmAuditReport {
        schema: SCHEMA_LLM_AUDIT_V1.to_string(),
        mode: "dry-run".to_string(),
        mutated: false,
        plugins,
        stale_plugin_caches: stale_caches,
        skills_by_client: by_client,
        stale_skills,
        broken_skill_symlinks: broken,
        symlinked_roots,
        duplicate_skill_dirs,
        unused_mcp_servers: unused,
        idle_sessions,
        planned_actions: actions,
        warnings,
    })
}

/// Live `ps` snapshot with CPU and RSS columns (Unix). Windows returns no rows and a warning.
pub fn list_live_processes() -> (Vec<LiveProc>, Vec<String>) {
    #[cfg(unix)]
    {
        let out = match std::process::Command::new("/bin/ps")
            .args(["-axo", "pid=,ppid=,uid=,pcpu=,rss=,etime=,args="])
            .output()
        {
            Ok(o) if o.status.success() => o,
            Ok(o) => {
                return (
                    Vec::new(),
                    vec![format!("/bin/ps exited with status {}", o.status)],
                )
            }
            Err(e) => return (Vec::new(), vec![format!("/bin/ps failed to execute: {e}")]),
        };
        let mut procs = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 7 {
                continue;
            }
            let (Ok(pid), Ok(ppid)) = (parts[0].parse(), parts[1].parse()) else {
                continue;
            };
            procs.push(LiveProc {
                pid,
                ppid,
                uid: parts[2].parse().ok(),
                cpu_pct: parts[3].parse().unwrap_or(0.0),
                rss_kib: parts[4].parse().unwrap_or(0),
                elapsed_secs: crate::mcp_audit::parse_bsd_etime(parts[5]).unwrap_or(0),
                command: parts[6..].join(" "),
            });
        }
        (procs, Vec::new())
    }
    #[cfg(not(unix))]
    {
        (
            Vec::new(),
            vec!["live idle-session detection is not available on this platform".to_string()],
        )
    }
}

pub fn audit_llm_fleet(opts: &LlmAuditOptions) -> Result<LlmAuditReport, SjError> {
    let (procs, warns) = list_live_processes();
    let mut report = audit_llm_with_processes(opts, &procs)?;
    report.warnings.extend(warns);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};
    use tempfile::tempdir;

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn write(p: &Path, body: &str) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    fn age(p: &Path, days: u64) {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(now() - days * 86_400);
        let f = fs::File::options().write(true).open(p).unwrap_or_else(|_| {
            // directories: open read-only is enough for set_modified on unix
            fs::File::open(p).unwrap()
        });
        let _ = f.set_modified(t);
    }

    fn age_tree(root: &Path, days: u64) {
        for e in fs::read_dir(root).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                age_tree(&p, days);
            } else {
                age(&p, days);
            }
        }
        age(root, days);
    }

    fn me() -> Option<u32> {
        #[cfg(unix)]
        {
            Some(unsafe { libc::geteuid() })
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    fn proc(pid: u32, ppid: u32, secs: u64, cpu: f64, cmd: &str) -> LiveProc {
        LiveProc {
            pid,
            ppid,
            uid: me(),
            cpu_pct: cpu,
            rss_kib: 2048,
            elapsed_secs: secs,
            command: cmd.to_string(),
        }
    }

    fn fixture() -> tempfile::TempDir {
        let tmp = tempdir().unwrap();
        let h = tmp.path();
        write(
            &h.join(".codex/config.toml"),
            r#"
[plugins."github@openai-curated"]
enabled = true
[plugins."extra@mkt"]
enabled = true
[plugins."old@mkt"]
enabled = false

[mcp_servers.multillm]
command = "python3"
args = ["-m", "multillm.mcp_server"]

[mcp_servers.idle-srv]
command = "npx"
args = ["-y", "idle-mcp", "--token", "TOKSECRET"]
[mcp_servers.idle-srv.env]
API_KEY = "ENVSECRET"

[mcp_servers.live-srv]
command = "npx"
args = ["live-mcp"]

[mcp_servers.off-srv]
command = "npx"
args = ["off-mcp"]
enabled = false
"#,
        );
        fs::create_dir_all(h.join(".codex/plugins/cache/mkt/old")).unwrap();
        fs::create_dir_all(h.join(".codex/plugins/cache/mkt/extra")).unwrap();
        fs::create_dir_all(h.join(".gemini/config/plugins/gp")).unwrap();
        fs::create_dir_all(h.join(".gemini/extensions/ge")).unwrap();
        write(
            &h.join(".claude/plugins/installed_plugins.json"),
            r#"{"plugins":{"CLAUDE_SECRET_MARKER@x":{}}}"#,
        );
        write(
            &h.join(".claude.json"),
            r#"{"mcpServers":{"CLAUDE_SECRET_MARKER":{"command":"x"}}}"#,
        );
        write(&h.join(".claude/skills/c1/SKILL.md"), "x");
        write(&h.join(".agents/skills/old-skill/SKILL.md"), "x");
        write(&h.join(".agents/skills/caveman/SKILL.md"), "x");
        write(&h.join(".agents/skills/fresh-skill/SKILL.md"), "x");
        write(&h.join(".cursor/skills/fresh-skill/SKILL.md"), "x");
        age_tree(&h.join(".agents/skills/old-skill"), 60);
        age_tree(&h.join(".agents/skills/caveman"), 90);
        fs::create_dir_all(h.join(".codex/skills")).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/nonexistent-sj-fixture", h.join(".codex/skills/dead"))
                .unwrap();
            std::os::unix::fs::symlink(
                h.join(".agents/skills/fresh-skill"),
                h.join(".codex/skills/linked"),
            )
            .unwrap();
        }
        tmp
    }

    fn opts(h: &Path) -> LlmAuditOptions {
        LlmAuditOptions {
            home_dir: h.to_path_buf(),
            policy: AuditPolicy::default(),
            now_epoch_secs: Some(now()),
        }
    }

    fn procs() -> Vec<LiveProc> {
        vec![
            proc(10, 500, 3 * 3600, 0.0, "/usr/local/bin/codex --full-auto"),
            proc(11, 10, 3 * 3600, 0.0, "npx live-mcp"),
            proc(12, 10, 3 * 3600, 0.0, "/x/codex-code-mode-host --foo"),
            proc(20, 500, 5 * 3600, 0.1, "/usr/local/bin/claude"),
            proc(21, 20, 5 * 3600, 0.0, "npx live-mcp"),
            proc(22, 20, 100, 30.0, "cargo build"),
            proc(30, 500, 600, 0.0, "/usr/local/bin/codex"),
            proc(31, 30, 600, 0.0, "npx live-mcp"),
            proc(500, 1, 9 * 3600, 0.0, "/bin/zsh"),
        ]
    }

    #[cfg(unix)]
    #[test]
    fn llm_audit_plugins_skills_mcp_and_idle_sessions_are_dry_run_and_secret_safe() {
        let tmp = fixture();
        let r = audit_llm_with_processes(&opts(tmp.path()), &procs()).unwrap();

        assert_eq!(r.schema, SCHEMA_LLM_AUDIT_V1);
        assert_eq!(r.mode, "dry-run");
        assert!(!r.mutated);

        // plugins
        let cand: Vec<&str> = r
            .plugins
            .iter()
            .filter(|p| p.disable_candidate)
            .map(|p| p.plugin_id.as_str())
            .collect();
        assert_eq!(cand, vec!["extra@mkt"], "{:?}", r.plugins);
        assert!(r
            .plugins
            .iter()
            .any(|p| p.plugin_id == "github@openai-curated" && p.kept_by_policy));
        assert!(r
            .plugins
            .iter()
            .any(|p| p.client == "gemini" && p.plugin_id == "gp"));
        assert!(r
            .plugins
            .iter()
            .any(|p| p.client == "gemini-extension" && p.plugin_id == "ge"));
        assert_eq!(r.stale_plugin_caches.len(), 1);
        assert_eq!(r.stale_plugin_caches[0].plugin_id, "old@mkt");
        // claude plugin dir is inventory-only (no candidates, read-only)
        assert!(r
            .plugins
            .iter()
            .all(|p| p.client != "claude" || (p.read_only && !p.disable_candidate)));

        // skills
        let stale: Vec<&str> = r.stale_skills.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(stale, vec!["old-skill"], "{:?}", r.stale_skills);
        assert!(r.stale_skills[0]
            .quarantine_dest
            .ends_with("skills-disabled/old-skill"));
        assert_eq!(r.broken_skill_symlinks.len(), 1);
        assert_eq!(r.broken_skill_symlinks[0].name, "dead");
        assert_eq!(r.duplicate_skill_dirs.len(), 1);
        assert_eq!(r.duplicate_skill_dirs[0].name, "fresh-skill");
        assert_eq!(r.duplicate_skill_dirs[0].paths.len(), 2);
        assert!(r.skills_by_client.contains_key("claude"));
        assert_eq!(r.skills_by_client["claude"].stale_candidates, 0);

        // unused MCP servers: configured+enabled+not kept+no live process
        let unused: Vec<&str> = r
            .unused_mcp_servers
            .iter()
            .map(|u| u.server_name.as_str())
            .collect();
        assert_eq!(unused, vec!["idle-srv"], "{:?}", r.unused_mcp_servers);
        assert_eq!(r.unused_mcp_servers[0].env_keys_count, 1);

        // idle sessions: only pid 10 (pid 20 has real work child, pid 30 too young)
        let idle: Vec<u32> = r.idle_sessions.iter().map(|s| s.pid).collect();
        assert_eq!(idle, vec![10], "{:?}", r.idle_sessions);
        assert_eq!(r.idle_sessions[0].mcp_proc_count, 1);

        // plan: never executable, never touches ~/.claude
        assert!(!r.planned_actions.is_empty());
        for a in &r.planned_actions {
            assert!(!a.executable);
            assert!(!a.target.contains("/.claude"), "{a:?}");
        }
        let kinds: BTreeSet<&str> = r.planned_actions.iter().map(|a| a.kind.as_str()).collect();
        for k in [
            "disable_plugin",
            "quarantine_plugin_cache",
            "quarantine_skill",
            "remove_broken_symlink",
            "disable_mcp_server",
            "terminate_idle_session",
        ] {
            assert!(kinds.contains(k), "missing {k}: {kinds:?}");
        }

        let json = serde_json::to_string(&r).unwrap();
        for leak in ["TOKSECRET", "ENVSECRET", "CLAUDE_SECRET_MARKER"] {
            assert!(!json.contains(leak), "leaked {leak}");
        }
        // nothing on disk changed
        assert!(tmp.path().join(".agents/skills/old-skill").is_dir());
        assert!(fs::symlink_metadata(tmp.path().join(".codex/skills/dead")).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn llm_audit_idle_sessions_exclude_foreign_uid_and_wrapper_only_trees() {
        let tmp = fixture();
        let mut ps = procs();
        ps[0].uid = me().map(|u| u.wrapping_add(1));
        let r = audit_llm_with_processes(&opts(tmp.path()), &ps).unwrap();
        assert!(r.idle_sessions.is_empty(), "{:?}", r.idle_sessions);
    }
}
