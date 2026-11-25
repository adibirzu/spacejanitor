use crate::mcp_audit::{
    list_observed_processes, list_observed_processes_with_warnings, ObservedProcess,
};
use crate::{redact_secrets, SjError, SCHEMA_REAP_V1};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReapTarget {
    pub pid: u32,
    pub ppid: u32,
    pub start_time: String,
    pub elapsed_secs: u64,
    pub command: String,
    pub command_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReapExcluded {
    pub pid: u32,
    pub command: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReapPlan {
    pub schema: String,
    pub mode: String,
    pub mutated: bool,
    pub min_age_mins: u64,
    pub plan_sha256: String,
    pub confirm_phrase: String,
    pub targets: Vec<ReapTarget>,
    pub excluded: Vec<ReapExcluded>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ReapExecutionGate {
    pub execute: bool,
    pub confirm_phrase: String,
    pub plan_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReapOutcomeItem {
    pub pid: u32,
    pub command: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReapExecutionReport {
    pub schema: String,
    pub mode: String,
    pub mutated: bool,
    pub plan_sha256: String,
    pub terminated_count: usize,
    pub skipped_count: usize,
    pub outcomes: Vec<ReapOutcomeItem>,
}

const PROTECTED_PROCESS_NAMES: &[&str] = &[
    "init",
    "launchd",
    "systemd",
    "systemd-journald",
    "kernel_task",
    "windowserver",
    "loginwindow",
    "opendirectoryd",
    "finder",
    "dock",
    "safari",
    "sshd",
    "ssh-agent",
    "zsh",
    "bash",
    "fish",
    "sh",
    "dash",
    "tcsh",
    "tmux",
    "screen",
    "dbus-daemon",
    "pulseaudio",
    "pipewire",
    "wayland",
    "xorg",
    "explorer.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "csrss.exe",
    "svchost.exe",
    "dwm.exe",
    "sj",
];

fn extract_binary_name(command: &str) -> String {
    let first = command.split_whitespace().next().unwrap_or("");
    let clean = first.trim_matches(|c| c == '"' || c == '\'' || c == '(' || c == ')');
    Path::new(clean)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(clean)
        .trim_start_matches('-')
        .trim_end_matches(':')
        .to_ascii_lowercase()
}

fn is_system_binary_path(command: &str) -> bool {
    let low = command.to_ascii_lowercase();
    let first = low.split_whitespace().next().unwrap_or("");
    let first_clean = first.trim_matches(|c| c == '"' || c == '\'');
    first_clean.starts_with("/system/")
        || first_clean.starts_with("/usr/libexec/")
        || first_clean.starts_with("/usr/sbin/")
        || first_clean.starts_with("/usr/lib/systemd/")
        || first_clean.starts_with("/lib/systemd/")
        || (first_clean.starts_with("/applications/")
            && first_clean.contains(".app/contents/macos/"))
}

/// MCP lineage: the command line itself must name an MCP server (`mcp`,
/// `@modelcontextprotocol`, `mcp-server`, `--mcp`). A bare runtime such as
/// `node`, `python3` or `bun` is NOT enough: any orphaned dev server would match.
fn has_mcp_lineage(command: &str) -> bool {
    let low = command.to_ascii_lowercase();
    low.contains("mcp") || low.contains("modelcontextprotocol")
}

/// Wrapper hosts that supervise MCP children and must never be signalled.
fn is_protected_wrapper(command: &str) -> bool {
    let low = command.to_ascii_lowercase();
    low.contains("codex-code-mode-host")
        || low.contains("codexcli.app/contents/macos/codex app-server")
}

pub fn is_protected_process(pid: u32, command: &str) -> Option<&'static str> {
    if pid <= 1 {
        return Some("protected_pid_0_or_1");
    }
    if is_system_binary_path(command) {
        return Some("protected_system_binary_path");
    }
    if is_protected_wrapper(command) {
        return Some("protected_wrapper_process");
    }
    let bin = extract_binary_name(command);
    if PROTECTED_PROCESS_NAMES.contains(&bin.as_str()) {
        return Some("protected_system_or_shell_process");
    }
    None
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

pub fn compute_reap_plan_sha256(
    min_age_mins: u64,
    targets: &[ReapTarget],
) -> Result<String, SjError> {
    #[derive(Serialize)]
    struct StableTargetHashInput<'a> {
        pid: u32,
        ppid: u32,
        start_time: &'a str,
        command: &'a str,
        command_sha256: &'a str,
    }
    #[derive(Serialize)]
    struct HashInput<'a> {
        min_age_mins: u64,
        targets: Vec<StableTargetHashInput<'a>>,
    }
    let stable_targets = targets
        .iter()
        .map(|t| StableTargetHashInput {
            pid: t.pid,
            ppid: t.ppid,
            start_time: &t.start_time,
            command: &t.command,
            command_sha256: &t.command_sha256,
        })
        .collect();
    let bytes = serde_json::to_vec(&HashInput {
        min_age_mins,
        targets: stable_targets,
    })?;
    Ok(sha256_hex(&bytes))
}

pub fn build_reap_plan_from_processes(
    min_age_mins: u64,
    processes: &[ObservedProcess],
    self_pid: u32,
) -> Result<ReapPlan, SjError> {
    let min_age_secs = min_age_mins.saturating_mul(60);
    let mut targets = Vec::new();
    let mut excluded = Vec::new();
    #[cfg(unix)]
    let current_uid = unsafe { libc::geteuid() };

    for p in processes {
        if p.ppid != 1 {
            continue;
        }
        if p.pid == self_pid {
            excluded.push(ReapExcluded {
                pid: p.pid,
                command: redact_secrets(&p.command),
                reason: "self_process".to_string(),
            });
            continue;
        }
        // F6: a PPID=1 orphan is only a candidate when its owner is provably us.
        #[cfg(unix)]
        match p.uid {
            Some(proc_uid) if proc_uid == current_uid => {}
            Some(_) => {
                excluded.push(ReapExcluded {
                    pid: p.pid,
                    command: redact_secrets(&p.command),
                    reason: "foreign_uid".to_string(),
                });
                continue;
            }
            None => {
                excluded.push(ReapExcluded {
                    pid: p.pid,
                    command: redact_secrets(&p.command),
                    reason: "unknown_uid".to_string(),
                });
                continue;
            }
        }
        #[cfg(not(unix))]
        {
            excluded.push(ReapExcluded {
                pid: p.pid,
                command: redact_secrets(&p.command),
                reason: "uid_unverifiable".to_string(),
            });
            continue;
        }
        if let Some(reason) = is_protected_process(p.pid, &p.command) {
            excluded.push(ReapExcluded {
                pid: p.pid,
                command: redact_secrets(&p.command),
                reason: reason.to_string(),
            });
            continue;
        }
        if !has_mcp_lineage(&p.command) {
            excluded.push(ReapExcluded {
                pid: p.pid,
                command: redact_secrets(&p.command),
                reason: "non_mcp_lineage".to_string(),
            });
            continue;
        }
        if p.elapsed_secs < min_age_secs {
            excluded.push(ReapExcluded {
                pid: p.pid,
                command: redact_secrets(&p.command),
                reason: format!("below_min_age_mins:{min_age_mins}"),
            });
            continue;
        }
        targets.push(ReapTarget {
            pid: p.pid,
            ppid: p.ppid,
            start_time: p.start_time.clone(),
            elapsed_secs: p.elapsed_secs,
            command: redact_secrets(&p.command),
            command_sha256: sha256_hex(p.command.as_bytes()),
        });
    }

    targets.sort_by_key(|a| a.pid);
    excluded.sort_by_key(|a| a.pid);

    let plan_sha256 = compute_reap_plan_sha256(min_age_mins, &targets)?;
    let confirm_phrase = format!("REAP {} ORPHAN PROCESS(ES)", targets.len());

    Ok(ReapPlan {
        schema: SCHEMA_REAP_V1.to_string(),
        mode: "dry-run".to_string(),
        mutated: false,
        min_age_mins,
        plan_sha256,
        confirm_phrase,
        targets,
        excluded,
        warnings: Vec::new(),
    })
}

pub fn build_reap_plan(min_age_mins: u64) -> Result<ReapPlan, SjError> {
    let (procs, warnings) = list_observed_processes_with_warnings();
    for w in &warnings {
        eprintln!("warning: {w}");
    }
    let mut plan = build_reap_plan_from_processes(min_age_mins, &procs, std::process::id())?;
    plan.warnings = warnings;
    Ok(plan)
}

pub fn validate_reap_gate(plan: &ReapPlan, gate: &ReapExecutionGate) -> Result<(), SjError> {
    if !gate.execute {
        return Err(SjError::ExecutionGate(
            "missing --execute flag (dry-run is default)".to_string(),
        ));
    }
    if gate.confirm_phrase.trim().is_empty() || gate.plan_sha256.trim().is_empty() {
        return Err(SjError::ExecutionGate(
            "both --confirm <phrase> and --plan-sha256 <sha> are required".to_string(),
        ));
    }
    let expected_sha = compute_reap_plan_sha256(plan.min_age_mins, &plan.targets)?;
    if gate.plan_sha256 != expected_sha || gate.plan_sha256 != plan.plan_sha256 {
        return Err(SjError::ExecutionGate(
            "plan_sha256 mismatch; regenerate reap plan and retry".to_string(),
        ));
    }
    if gate.confirm_phrase != plan.confirm_phrase {
        return Err(SjError::ExecutionGate(format!(
            "confirmation phrase mismatch; expected '{}'",
            plan.confirm_phrase
        )));
    }
    Ok(())
}

pub fn verify_target_unchanged(
    target: &ReapTarget,
    live_processes: &[ObservedProcess],
) -> Result<(), String> {
    let Some(live) = live_processes.iter().find(|p| p.pid == target.pid) else {
        return Err("process_exited_before_reap".to_string());
    };
    if live.ppid != 1 {
        return Err(format!("ppid_drifted:{}", live.ppid));
    }
    #[cfg(unix)]
    if live.uid != Some(unsafe { libc::geteuid() }) {
        return Err("uid_drifted".to_string());
    }
    if sha256_hex(live.command.as_bytes()) != target.command_sha256 {
        return Err("command_drifted".to_string());
    }
    if live.start_time != target.start_time {
        return Err("start_time_drifted".to_string());
    }
    Ok(())
}

#[cfg(unix)]
fn terminate_pid_unix(pid: u32) -> Result<String, String> {
    let raw_pid = i32::try_from(pid).map_err(|_| "pid_out_of_range".to_string())?;
    let rc = unsafe { libc::kill(raw_pid, libc::SIGTERM) };
    if rc != 0 {
        return Err(format!(
            "sigterm_failed:{}",
            std::io::Error::last_os_error()
        ));
    }
    for _ in 0..10 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        let alive = unsafe { libc::kill(raw_pid, 0) };
        if alive != 0 {
            return Ok("terminated_sigterm".to_string());
        }
    }
    let kill_rc = unsafe { libc::kill(raw_pid, libc::SIGKILL) };
    if kill_rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok("terminated_sigterm".to_string());
        }
        return Err(format!("sigkill_failed:{err}"));
    }
    Ok("terminated_sigkill".to_string())
}

#[cfg(windows)]
fn terminate_pid_windows(pid: u32) -> Result<String, String> {
    let out = std::process::Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .output()
        .map_err(|e| format!("taskkill_error:{e}"))?;
    if out.status.success() {
        Ok("terminated_taskkill".to_string())
    } else {
        Err(format!(
            "taskkill_failed:{}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

pub fn execute_reap_plan(
    plan: &ReapPlan,
    gate: &ReapExecutionGate,
) -> Result<ReapExecutionReport, SjError> {
    validate_reap_gate(plan, gate)?;

    let mut outcomes = Vec::new();
    let mut terminated_count = 0usize;
    let mut skipped_count = 0usize;

    for target in &plan.targets {
        let live_processes = list_observed_processes();
        if let Err(reason) = verify_target_unchanged(target, &live_processes) {
            skipped_count += 1;
            outcomes.push(ReapOutcomeItem {
                pid: target.pid,
                command: target.command.clone(),
                status: "skipped_drift".to_string(),
                detail: reason,
            });
            continue;
        }

        #[cfg(unix)]
        let term_res = terminate_pid_unix(target.pid);
        #[cfg(windows)]
        let term_res = terminate_pid_windows(target.pid);

        match term_res {
            Ok(detail) => {
                terminated_count += 1;
                outcomes.push(ReapOutcomeItem {
                    pid: target.pid,
                    command: target.command.clone(),
                    status: "terminated".to_string(),
                    detail,
                });
            }
            Err(detail) => {
                skipped_count += 1;
                outcomes.push(ReapOutcomeItem {
                    pid: target.pid,
                    command: target.command.clone(),
                    status: "failed".to_string(),
                    detail,
                });
            }
        }
    }

    Ok(ReapExecutionReport {
        schema: SCHEMA_REAP_V1.to_string(),
        mode: "executed".to_string(),
        mutated: terminated_count > 0,
        plan_sha256: plan.plan_sha256.clone(),
        terminated_count,
        skipped_count,
        outcomes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cur_uid() -> Option<u32> {
        #[cfg(unix)]
        {
            Some(unsafe { libc::geteuid() })
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    fn orphan(pid: u32, uid: Option<u32>, command: &str) -> ObservedProcess {
        ObservedProcess {
            pid,
            ppid: 1,
            uid,
            start_time: "Mon Nov 24 01:00:00 2026".to_string(),
            elapsed_secs: 7200,
            command: command.to_string(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn reap_f6_requires_known_own_uid_and_mcp_lineage_for_ppid1_orphans() {
        let me = cur_uid();
        let other = me.map(|u| u.wrapping_add(1));
        let procs = vec![
            orphan(201, me, "node /srv/dev-server.js --port 3000"),
            orphan(202, me, "python3 train.py"),
            orphan(203, None, "node /opt/x/mcp-server.js"),
            orphan(204, other, "node /opt/x/mcp-server.js"),
            orphan(
                205,
                me,
                "npx -y @modelcontextprotocol/server-filesystem /tmp",
            ),
            orphan(206, me, "node /opt/x/mcp-server.js"),
            orphan(
                207,
                me,
                "/Applications/Codex.app/Contents/MacOS/codex app-server --mcp",
            ),
            orphan(208, me, "codex-code-mode-host --mcp"),
        ];
        let plan = build_reap_plan_from_processes(30, &procs, 999).unwrap();
        let got: Vec<u32> = plan.targets.iter().map(|t| t.pid).collect();
        assert_eq!(got, vec![205, 206], "plan: {plan:?}");
        let reason = |pid: u32| {
            plan.excluded
                .iter()
                .find(|e| e.pid == pid)
                .map(|e| e.reason.clone())
                .unwrap_or_default()
        };
        assert_eq!(reason(201), "non_mcp_lineage");
        assert_eq!(reason(202), "non_mcp_lineage");
        assert_eq!(reason(203), "unknown_uid");
        assert_eq!(reason(204), "foreign_uid");
        assert_eq!(reason(207), "protected_system_binary_path");
        assert_eq!(reason(208), "protected_wrapper_process");
    }

    #[cfg(unix)]
    #[test]
    fn reap_f6_verify_rejects_uid_drift() {
        let me = cur_uid();
        let procs = vec![orphan(301, me, "node /opt/x/mcp-server.js")];
        let plan = build_reap_plan_from_processes(30, &procs, 999).unwrap();
        let mut drifted = procs.clone();
        drifted[0].uid = me.map(|u| u.wrapping_add(1));
        assert_eq!(
            verify_target_unchanged(&plan.targets[0], &drifted),
            Err("uid_drifted".to_string())
        );
    }

    fn sample_processes() -> Vec<ObservedProcess> {
        vec![
            ObservedProcess {
                pid: 1,
                ppid: 0,
                uid: cur_uid(),
                start_time: "Mon Nov 24 00:00:00 2026".to_string(),
                elapsed_secs: 99999,
                command: "/sbin/launchd".to_string(),
            },
            ObservedProcess {
                pid: 101,
                ppid: 1,
                uid: cur_uid(),
                start_time: "Mon Nov 24 01:00:00 2026".to_string(),
                elapsed_secs: 7200,
                command: "/bin/zsh".to_string(),
            },
            ObservedProcess {
                pid: 202,
                ppid: 1,
                uid: cur_uid(),
                start_time: "Mon Nov 24 02:00:00 2026".to_string(),
                elapsed_secs: 600, // 10 mins < 30
                command: "node fresh-worker.js".to_string(),
            },
            ObservedProcess {
                pid: 303,
                ppid: 1,
                uid: cur_uid(),
                start_time: "Mon Nov 24 01:10:00 2026".to_string(),
                elapsed_secs: 3600,
                command: "node stale-mcp.js --token=secret_123".to_string(),
            },
            ObservedProcess {
                pid: 404,
                ppid: 101, // not PPID=1
                uid: cur_uid(),
                start_time: "Mon Nov 24 01:10:00 2026".to_string(),
                elapsed_secs: 3600,
                command: "node active-child.js".to_string(),
            },
        ]
    }

    #[cfg(unix)]
    #[test]
    fn reap_plan_is_deterministic_excludes_protected_and_enforces_gates() {
        let procs = sample_processes();
        let plan_a = build_reap_plan_from_processes(30, &procs, 999).unwrap();
        let plan_b = build_reap_plan_from_processes(30, &procs, 999).unwrap();

        assert_eq!(plan_a.schema, SCHEMA_REAP_V1);
        assert_eq!(plan_a.mode, "dry-run");
        assert!(!plan_a.mutated);
        assert_eq!(plan_a.plan_sha256, plan_b.plan_sha256);
        assert_eq!(plan_a.targets.len(), 1);
        assert_eq!(plan_a.targets[0].pid, 303);
        assert!(!plan_a.targets[0].command.contains("secret_123"));
        assert!(plan_a.excluded.iter().any(|e| e.pid == 101));
        assert!(plan_a.excluded.iter().any(|e| e.pid == 202));
        assert_eq!(plan_a.confirm_phrase, "REAP 1 ORPHAN PROCESS(ES)");

        // Gate rejections
        let missing_exec = validate_reap_gate(
            &plan_a,
            &ReapExecutionGate {
                execute: false,
                confirm_phrase: plan_a.confirm_phrase.clone(),
                plan_sha256: plan_a.plan_sha256.clone(),
            },
        );
        assert!(matches!(missing_exec, Err(SjError::ExecutionGate(_))));

        let bad_confirm = validate_reap_gate(
            &plan_a,
            &ReapExecutionGate {
                execute: true,
                confirm_phrase: "WRONG PHRASE".to_string(),
                plan_sha256: plan_a.plan_sha256.clone(),
            },
        );
        assert!(matches!(bad_confirm, Err(SjError::ExecutionGate(_))));

        let bad_sha = validate_reap_gate(
            &plan_a,
            &ReapExecutionGate {
                execute: true,
                confirm_phrase: plan_a.confirm_phrase.clone(),
                plan_sha256: "0000".to_string(),
            },
        );
        assert!(matches!(bad_sha, Err(SjError::ExecutionGate(_))));

        let valid = validate_reap_gate(
            &plan_a,
            &ReapExecutionGate {
                execute: true,
                confirm_phrase: plan_a.confirm_phrase.clone(),
                plan_sha256: plan_a.plan_sha256.clone(),
            },
        );
        assert!(valid.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn reap_drift_guard_detects_command_and_start_time_changes() {
        let procs = sample_processes();
        let plan = build_reap_plan_from_processes(30, &procs, 999).unwrap();
        let target = &plan.targets[0];

        assert!(verify_target_unchanged(target, &procs).is_ok());

        let mut drifted_cmd = procs.clone();
        drifted_cmd[3].command = "python3 something_else.py".to_string();
        assert_eq!(
            verify_target_unchanged(target, &drifted_cmd),
            Err("command_drifted".to_string())
        );

        let mut drifted_start = procs.clone();
        drifted_start[3].start_time = "Tue Nov 25 00:00:00 2026".to_string();
        assert_eq!(
            verify_target_unchanged(target, &drifted_start),
            Err("start_time_drifted".to_string())
        );
    }

    #[test]
    fn reap_plan_never_serializes_raw_command_or_secrets_and_hash_is_stable() {
        let mut procs = vec![ObservedProcess {
            pid: 505,
            ppid: 1,
            uid: cur_uid(),
            start_time: "Mon Nov 24 01:10:00 2026".to_string(),
            elapsed_secs: 1800,
            command: "node stale-mcp.js --token=PROBE_REAP_EQ --api-key PROBE_REAP_SP".to_string(),
        }];
        let plan_a = build_reap_plan_from_processes(30, &procs, 999).unwrap();
        let json = serde_json::to_string(&plan_a).unwrap();
        assert!(
            !json.contains("PROBE_REAP_EQ"),
            "leaked PROBE_REAP_EQ: {json}"
        );
        assert!(
            !json.contains("PROBE_REAP_SP"),
            "leaked PROBE_REAP_SP: {json}"
        );
        assert!(
            !json.contains("raw_command"),
            "raw_command field must not be serialized: {json}"
        );

        // F5: plan_sha256 must be identical when elapsed_secs increases
        procs[0].elapsed_secs = 1805;
        let plan_b = build_reap_plan_from_processes(30, &procs, 999).unwrap();
        assert_eq!(plan_a.plan_sha256, plan_b.plan_sha256);
    }

    #[cfg(unix)]
    #[test]
    fn reap_excludes_system_daemons_gui_apps_and_non_mcp_processes() {
        let procs = vec![
            ObservedProcess {
                pid: 101,
                ppid: 1,
                uid: cur_uid(),
                start_time: "Mon Nov 24 01:00:00 2026".to_string(),
                elapsed_secs: 7200,
                command: "/usr/libexec/opendirectoryd".to_string(),
            },
            ObservedProcess {
                pid: 102,
                ppid: 1,
                uid: cur_uid(),
                start_time: "Mon Nov 24 01:00:00 2026".to_string(),
                elapsed_secs: 7200,
                command: "/Applications/Safari.app/Contents/MacOS/Safari".to_string(),
            },
            ObservedProcess {
                pid: 103,
                ppid: 1,
                uid: cur_uid(),
                start_time: "Mon Nov 24 01:00:00 2026".to_string(),
                elapsed_secs: 7200,
                command: "sshd: /usr/sbin/sshd -D [listener]".to_string(),
            },
            ObservedProcess {
                pid: 104,
                ppid: 1,
                uid: cur_uid(),
                start_time: "Mon Nov 24 01:00:00 2026".to_string(),
                elapsed_secs: 7200,
                command: "/usr/lib/systemd/systemd-journald".to_string(),
            },
            ObservedProcess {
                pid: 105,
                ppid: 1,
                uid: cur_uid(),
                start_time: "Mon Nov 24 01:00:00 2026".to_string(),
                elapsed_secs: 7200,
                command: "/usr/bin/ssh-agent -l".to_string(),
            },
            ObservedProcess {
                pid: 106,
                ppid: 1,
                uid: cur_uid(),
                start_time: "Mon Nov 24 01:00:00 2026".to_string(),
                elapsed_secs: 7200,
                command: "npx -y @modelcontextprotocol/server-filesystem /tmp".to_string(),
            },
        ];
        let plan = build_reap_plan_from_processes(30, &procs, 999).unwrap();
        assert_eq!(
            plan.targets.len(),
            1,
            "expected only pid 106, got: {:?}",
            plan.targets
        );
        assert_eq!(plan.targets[0].pid, 106);
    }
}
