use crate::mcp_audit::{list_observed_processes, ObservedProcess};
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
    pub raw_command: String,
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
    "kernel_task",
    "windowserver",
    "loginwindow",
    "finder",
    "dock",
    "sshd",
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
        .to_ascii_lowercase()
}

pub fn is_protected_process(pid: u32, command: &str) -> Option<&'static str> {
    if pid <= 1 {
        return Some("protected_pid_0_or_1");
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
    struct HashInput<'a> {
        min_age_mins: u64,
        targets: &'a [ReapTarget],
    }
    let bytes = serde_json::to_vec(&HashInput {
        min_age_mins,
        targets,
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
        if let Some(reason) = is_protected_process(p.pid, &p.command) {
            excluded.push(ReapExcluded {
                pid: p.pid,
                command: redact_secrets(&p.command),
                reason: reason.to_string(),
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
            raw_command: p.command.clone(),
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
    })
}

pub fn build_reap_plan(min_age_mins: u64) -> Result<ReapPlan, SjError> {
    let procs = list_observed_processes();
    build_reap_plan_from_processes(min_age_mins, &procs, std::process::id())
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
    if live.command != target.raw_command {
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

    let live_processes = list_observed_processes();
    let mut outcomes = Vec::new();
    let mut terminated_count = 0usize;
    let mut skipped_count = 0usize;

    for target in &plan.targets {
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

    fn sample_processes() -> Vec<ObservedProcess> {
        vec![
            ObservedProcess {
                pid: 1,
                ppid: 0,
                start_time: "Mon Nov 24 00:00:00 2026".to_string(),
                elapsed_secs: 99999,
                command: "/sbin/launchd".to_string(),
            },
            ObservedProcess {
                pid: 101,
                ppid: 1,
                start_time: "Mon Nov 24 01:00:00 2026".to_string(),
                elapsed_secs: 7200,
                command: "/bin/zsh".to_string(),
            },
            ObservedProcess {
                pid: 202,
                ppid: 1,
                start_time: "Mon Nov 24 02:00:00 2026".to_string(),
                elapsed_secs: 600, // 10 mins < 30
                command: "node fresh-worker.js".to_string(),
            },
            ObservedProcess {
                pid: 303,
                ppid: 1,
                start_time: "Mon Nov 24 01:10:00 2026".to_string(),
                elapsed_secs: 3600,
                command: "node stale-mcp.js --token=secret_123".to_string(),
            },
            ObservedProcess {
                pid: 404,
                ppid: 101, // not PPID=1
                start_time: "Mon Nov 24 01:10:00 2026".to_string(),
                elapsed_secs: 3600,
                command: "node active-child.js".to_string(),
            },
        ]
    }

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
}
