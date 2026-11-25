//! R5: every JSON string (keys and values) emitted by every audit surface is walked against a
//! fixture full of secrets in every R3 + R4 shape. Nothing secret may appear anywhere.

#[path = "common/probe.rs"]
mod probe;

use probe::{assert_no_needles, probe_command_lines, write_fixture_home, NEEDLES};
use sj_core::llm_audit::{audit_llm_with_processes, AuditPolicy, LiveProc, LlmAuditOptions};
use sj_core::mcp_audit::{audit_mcp_with_processes, McpAuditOptions, ObservedProcess};
use sj_core::memory::parse_macos_ps_fallback;
use sj_core::reap::build_reap_plan_from_processes;
use std::fs;
use tempfile::tempdir;

#[test]
fn mcp_audit_walk_every_string_against_probe_fixture() {
    let tmp = tempdir().unwrap();
    let h = tmp.path().canonicalize().unwrap();
    write_fixture_home(&h);
    let procs: Vec<ObservedProcess> = probe_command_lines()
        .into_iter()
        .enumerate()
        .map(|(i, c)| ObservedProcess {
            pid: 1000 + i as u32,
            ppid: 1,
            uid: None,
            start_time: "Mon Jan  1 00:00:00 2026".into(),
            elapsed_secs: 99_999,
            command: c,
        })
        .collect();
    let report = audit_mcp_with_processes(
        &McpAuditOptions {
            config_dirs: vec![h.join(".cursor"), h.join(".codex")],
            home_dir: Some(h.clone()),
        },
        &procs,
    )
    .unwrap();
    assert!(!report.configured_servers.is_empty());
    assert!(!report.running_processes.is_empty());
    let v = serde_json::to_value(&report).unwrap();
    assert_no_needles("mcp-audit", &v);
}

#[test]
fn mcp_audit_sample_server_shows_only_basename_package_flag_names_and_counts() {
    let tmp = tempdir().unwrap();
    let h = tmp.path().canonicalize().unwrap();
    write_fixture_home(&h);
    let r = audit_mcp_with_processes(
        &McpAuditOptions {
            config_dirs: vec![h.join(".cursor")],
            home_dir: Some(h.clone()),
        },
        &[],
    )
    .unwrap();
    let s = r
        .configured_servers
        .iter()
        .find(|s| s.server_name == "pkg-sample")
        .expect("pkg-sample");
    assert_eq!(s.command.as_deref(), Some("npx"));
    assert_eq!(
        s.args,
        vec![
            "-y",
            "@scope/pkg@1.2.3",
            "--port",
            "<REDACTED>",
            "--token",
            "<REDACTED>"
        ]
    );
    assert_eq!(s.args_count, 6);
    let p = r
        .configured_servers
        .iter()
        .find(|s| s.server_name == "probe-shapes")
        .unwrap();
    assert_eq!(p.url.as_deref(), Some("https://example.com"));
    assert!(p
        .header_keys
        .iter()
        .all(|k| !k.to_lowercase().contains("probe")));
    assert_eq!(p.env_keys.len(), 3);
}

#[test]
fn llm_audit_walk_every_string_against_probe_fixture() {
    let tmp = tempdir().unwrap();
    let h = tmp.path().canonicalize().unwrap();
    write_fixture_home(&h);
    fs::create_dir_all(h.join(".cursor/skills/some-skill")).unwrap();
    let procs: Vec<LiveProc> = probe_command_lines()
        .into_iter()
        .enumerate()
        .map(|(i, c)| LiveProc {
            pid: 2000 + i as u32,
            ppid: 1,
            uid: None,
            cpu_pct: 0.0,
            rss_kib: 10,
            elapsed_secs: 99_999,
            command: c,
        })
        .collect();
    let r = audit_llm_with_processes(
        &LlmAuditOptions {
            home_dir: h.clone(),
            policy: AuditPolicy::default(),
            now_epoch_secs: None,
        },
        &procs,
    )
    .unwrap();
    let v = serde_json::to_value(&r).unwrap();
    assert_no_needles("llm-audit", &v);
}

#[test]
fn reap_plan_walk_every_string_against_probe_fixture() {
    let procs: Vec<ObservedProcess> = probe_command_lines()
        .into_iter()
        .enumerate()
        .map(|(i, c)| ObservedProcess {
            pid: 3000 + i as u32,
            ppid: 1,
            uid: None,
            start_time: "Mon Jan  1 00:00:00 2026".into(),
            elapsed_secs: 99_999,
            command: c,
        })
        .collect();
    let plan = build_reap_plan_from_processes(1, &procs, 1).unwrap();
    let v = serde_json::to_value(&plan).unwrap();
    assert_no_needles("reap", &v);
}

#[test]
fn memory_ps_fallback_commands_walk_against_probe_fixture() {
    let mut text = String::new();
    for (i, c) in probe_command_lines().iter().enumerate() {
        text.push_str(&format!("{} 1 1024 {}\n", 4000 + i, c));
    }
    let entries = parse_macos_ps_fallback(&text);
    assert!(!entries.is_empty());
    for e in entries {
        let low = e.command.to_ascii_lowercase();
        for n in NEEDLES {
            assert!(!low.contains(n), "memory leak {n:?}: {}", e.command);
        }
    }
}
