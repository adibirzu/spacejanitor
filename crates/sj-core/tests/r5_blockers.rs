//! R5 blockers (item 70, head ac2bd1f): every Gemini reproduction as a test.
//! B1: server_name / owning client derived from raw argv.
//! B2: closed vocabulary everywhere output is built from untrusted text.
//! B3: config files and `--config-dir` (symlinks, protected roots, FIFOs, TOCTOU).

#[path = "common/probe.rs"]
mod probe;

use probe::{assert_no_needles, write_fixture_home};
use sj_core::mcp_audit::{audit_mcp_with_processes, McpAuditOptions, ObservedProcess};
use std::fs;
use tempfile::tempdir;

fn proc(pid: u32, ppid: u32, command: &str) -> ObservedProcess {
    ObservedProcess {
        pid,
        ppid,
        uid: None,
        start_time: "Mon Jan  1 00:00:00 2026".into(),
        elapsed_secs: 99_999,
        command: command.to_string(),
    }
}

fn is_unknown_label(s: &str) -> bool {
    s.len() == 16
        && s.starts_with("unknown-")
        && s[8..].chars().all(|c| c.is_ascii_hexdigit())
        && s[8..].chars().all(|c| !c.is_ascii_uppercase())
}

// ------------------------------------------------------------------ B1

#[test]
fn b1_server_name_and_client_never_come_from_argv() {
    let tmp = tempdir().unwrap();
    let procs = vec![
        proc(
            100,
            1,
            "python3 -c import-time https://mcp.example.com/sse/550e8400-e29b-41d4-a716-446655440000",
        ),
        proc(101, 1, "python3 -c import-time --token PROBE_MCP_SECRET_1"),
        proc(102, 1, "node /srv/mcp/probesecretlowercasetok1"),
        proc(103, 1, "node /srv/mcp/hf_a1b2c3d4_e5f6g7h8_i9j0k1l2"),
        // owning client: parent command basename is a secret
        proc(200, 1, "/opt/PROBE_SECRET_BIN/launcher --serve"),
        proc(201, 200, "node /srv/mcp/server-x.js"),
        proc(202, 1, "/usr/local/bin/codex --full-auto"),
        proc(203, 202, "npx -y @modelcontextprotocol/server-github"),
    ];
    let r = audit_mcp_with_processes(
        &McpAuditOptions {
            config_dirs: vec![tmp.path().to_path_buf()],
            home_dir: None,
        },
        &procs,
    )
    .unwrap();
    let v = serde_json::to_value(&r).unwrap();
    assert_no_needles("b1", &v);
    for rp in r.running_processes.iter().filter(|p| p.pid < 200) {
        assert!(
            is_unknown_label(&rp.server_name),
            "pid {} server_name {:?}",
            rp.pid,
            rp.server_name
        );
    }
    let by = |pid: u32| r.running_processes.iter().find(|p| p.pid == pid).unwrap();
    // unknown parent -> hash label, never the basename
    assert!(is_unknown_label(&by(201).owning_client), "{:?}", by(201));
    // known catalog client and catalog package
    assert_eq!(by(203).owning_client, "codex");
    assert_eq!(by(203).server_name, "@modelcontextprotocol/server-github");
}

#[test]
fn b1_config_match_uses_the_config_label_and_catalog_package_is_known() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("mcp.json"),
        r#"{"mcpServers":{"my-docs":{"command":"npx","args":["-y","some-private-mcp-pkg"]}}}"#,
    )
    .unwrap();
    let procs = vec![
        proc(1, 1, "node /x/some-private-mcp-pkg/dist/index.js"),
        proc(2, 1, "node /x/mcp-server-memory/index.js"),
    ];
    let r = audit_mcp_with_processes(
        &McpAuditOptions {
            config_dirs: vec![tmp.path().to_path_buf()],
            home_dir: None,
        },
        &procs,
    )
    .unwrap();
    let by = |pid: u32| r.running_processes.iter().find(|p| p.pid == pid).unwrap();
    assert_eq!(by(1).server_name, "my-docs");
    assert_eq!(by(2).server_name, "mcp-server-memory");
}

#[test]
fn b1_same_argv_groups_into_one_duplicate_label() {
    let tmp = tempdir().unwrap();
    let procs: Vec<_> = (0..3)
        .map(|i| proc(10 + i, 1, "node /srv/mcp/some-unknown-thing.js"))
        .collect();
    let r = audit_mcp_with_processes(
        &McpAuditOptions {
            config_dirs: vec![tmp.path().to_path_buf()],
            home_dir: None,
        },
        &procs,
    )
    .unwrap();
    assert_eq!(r.duplicate_groups.len(), 1);
    assert!(is_unknown_label(&r.duplicate_groups[0].server_name));
}

// ------------------------------------------------------------------ B2

#[test]
fn b2_r5_config_probes_never_reach_mcp_audit_output() {
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
    assert!(r.configured_servers.len() >= 6);
    let v = serde_json::to_value(&r).unwrap();
    assert_no_needles("b2", &v);
    // user-chosen secret-shaped labels are replaced by a hash
    let names: Vec<&str> = r
        .configured_servers
        .iter()
        .map(|s| s.server_name.as_str())
        .collect();
    assert!(names.iter().any(|n| n.starts_with("server-")), "{names:?}");
    assert!(!names.iter().any(|n| n.contains("550e8400")), "{names:?}");
    // url scheme outside http/https/ws/wss is withheld
    assert!(r
        .configured_servers
        .iter()
        .all(|s| s.url.as_deref().is_none_or(|u| u == "<url>"
            || u.starts_with("https://")
            || u.starts_with("http://"))));
}

#[test]
fn b2_secret_findings_only_for_real_secret_signals() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("mcp.json"),
        r#"{"mcpServers":{
            "benign":{"command":"npx","args":["-y","mcp-remote","--port","8080","/tmp"],
                      "env":{"NODE_ENV":"production","LOG_LEVEL":"info"}},
            "secretive":{"command":"npx","args":["-y","mcp-remote","--token","abc"],
                      "env":{"GITHUB_TOKEN":"abc"}}
        }}"#,
    )
    .unwrap();
    let r = audit_mcp_with_processes(
        &McpAuditOptions {
            config_dirs: vec![tmp.path().to_path_buf()],
            home_dir: None,
        },
        &[],
    )
    .unwrap();
    assert!(
        r.secret_findings
            .iter()
            .all(|f| f.server_name == "secretive"),
        "benign flags/values must not be findings: {:?}",
        r.secret_findings
    );
    let keys: Vec<&str> = r
        .secret_findings
        .iter()
        .map(|f| f.key_name.as_str())
        .collect();
    assert!(
        keys.contains(&"--token") && keys.contains(&"GITHUB_TOKEN"),
        "{keys:?}"
    );
    assert_eq!(r.secret_findings.len(), 2, "{keys:?}");
}

#[test]
fn b2_env_and_header_names_are_counted_unless_in_the_fixed_list() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("mcp.json"),
        r#"{"mcpServers":{"s":{"command":"npx","args":["mcp-remote"],
            "env":{"PATH":"/bin","probesecretlowercasetok2":"x"},
            "headers":{"Authorization":"Bearer x","SK-LIVE-PROBE12345":"x"}}}}"#,
    )
    .unwrap();
    let r = audit_mcp_with_processes(
        &McpAuditOptions {
            config_dirs: vec![tmp.path().to_path_buf()],
            home_dir: None,
        },
        &[],
    )
    .unwrap();
    let s = &r.configured_servers[0];
    assert_eq!(s.env_keys, vec!["PATH"]);
    assert_eq!(s.env_key_count, 2);
    assert_eq!(s.header_keys, vec!["Authorization"]);
    assert_eq!(s.header_key_count, 2);
    assert_no_needles("b2-keys", &serde_json::to_value(&r).unwrap());
}

#[test]
fn b2_memory_top_process_names_keep_catalog_words_only() {
    let top = "\
Processes: 400 total, 3 running, 397 sleeping, 2000 threads
PID    PPID  COMMAND                          MEM      CMPRS    PORTS
10     1     Google Chrome Helper (Renderer)  512M+    256M     42+
11     1     Google probesecretword99         512M+    256M     42+
";
    let procs = sj_core::memory::parse_macos_top(top);
    assert_eq!(procs.len(), 2);
    assert_eq!(procs[0].command, "Google Chrome Helper (Renderer)");
    assert!(
        procs[1].command.starts_with("Google <w:") && !procs[1].command.contains("probesecret"),
        "{}",
        procs[1].command
    );
}

// ------------------------------------------------------------------ B3

#[cfg(unix)]
mod b3 {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{Duration, Instant};

    #[test]
    fn b3_config_dir_on_a_protected_root_emits_one_warning_and_nothing_else() {
        let tmp = tempdir().unwrap();
        let h = tmp.path().canonicalize().unwrap();
        fs::create_dir_all(h.join(".claude/projects/SecretClaudeProj")).unwrap();
        fs::write(
            h.join(".claude/projects/SecretClaudeProj/SecretSession.json"),
            r#"{"secret":"CLAUDE_INNER"}"#,
        )
        .unwrap();
        let r = audit_mcp_with_processes(
            &McpAuditOptions {
                config_dirs: vec![h.join(".claude")],
                home_dir: Some(h.clone()),
            },
            &[],
        )
        .unwrap();
        let text = serde_json::to_string(&r).unwrap();
        assert!(
            !text.contains("SecretSession") && !text.contains("SecretClaudeProj"),
            "{text}"
        );
        assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings);
        assert!(
            r.warnings[0].starts_with("protected_target"),
            "{:?}",
            r.warnings
        );
        assert!(r.scanned_files.is_empty() && r.configured_servers.is_empty());
    }

    #[test]
    fn b3_config_dir_symlink_to_protected_root_is_refused_without_listing() {
        let tmp = tempdir().unwrap();
        let h = tmp.path().canonicalize().unwrap();
        fs::create_dir_all(h.join(".claude/projects/Inner")).unwrap();
        fs::write(h.join(".claude/projects/Inner/Leak.json"), "{}").unwrap();
        symlink(h.join(".claude"), h.join("looks-innocent")).unwrap();
        let r = audit_mcp_with_processes(
            &McpAuditOptions {
                config_dirs: vec![h.join("looks-innocent")],
                home_dir: Some(h.clone()),
            },
            &[],
        )
        .unwrap();
        let text = serde_json::to_string(&r).unwrap();
        assert!(
            !text.contains("Leak.json") && !text.contains("Inner"),
            "{text}"
        );
        assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings);
    }

    #[test]
    fn b3_protected_entries_below_a_plain_root_are_pruned_unnamed() {
        let tmp = tempdir().unwrap();
        let h = tmp.path().canonicalize().unwrap();
        let root = h.join("cfg");
        fs::create_dir_all(root.join(".ssh")).unwrap();
        fs::write(
            root.join(".ssh/mcp.json"),
            r#"{"mcpServers":{"x":{"command":"npx"}}}"#,
        )
        .unwrap();
        fs::write(
            root.join("mcp.json"),
            r#"{"mcpServers":{"ok":{"command":"npx"}}}"#,
        )
        .unwrap();
        let r = audit_mcp_with_processes(
            &McpAuditOptions {
                config_dirs: vec![root.clone()],
                home_dir: Some(h.clone()),
            },
            &[],
        )
        .unwrap();
        let text = serde_json::to_string(&r).unwrap();
        assert!(!text.contains(".ssh"), "{text}");
        assert_eq!(r.configured_servers.len(), 1);
    }

    #[test]
    fn b3_symlinked_config_file_is_never_read_even_with_an_explicit_dir() {
        let tmp = tempdir().unwrap();
        let h = tmp.path().canonicalize().unwrap();
        let ext = tempdir().unwrap();
        fs::write(
            ext.path().join("real.json"),
            r#"{"mcpServers":{"ext-secret":{"command":"npx"}}}"#,
        )
        .unwrap();
        let root = h.join("cfg");
        fs::create_dir_all(&root).unwrap();
        symlink(ext.path().join("real.json"), root.join("mcp.json")).unwrap();
        let r = audit_mcp_with_processes(
            &McpAuditOptions {
                config_dirs: vec![root.clone()],
                home_dir: Some(h.clone()),
            },
            &[],
        )
        .unwrap();
        assert!(
            r.configured_servers.is_empty(),
            "{:?}",
            r.configured_servers
        );
        // a symlink entry is not even listed as a candidate file
        assert!(r.scanned_files.is_empty());
    }

    #[test]
    fn b3_default_discovery_refuses_symlink_and_fifo_without_hanging() {
        let tmp = tempdir().unwrap();
        let h = tmp.path().canonicalize().unwrap();
        let ext = tempdir().unwrap();
        fs::write(
            ext.path().join("x.json"),
            r#"{"mcpServers":{"ext-secret":{"command":"npx"}}}"#,
        )
        .unwrap();
        symlink(ext.path().join("x.json"), h.join(".mcp.json")).unwrap();
        fs::create_dir_all(h.join(".cursor")).unwrap();
        let fifo = h.join(".cursor/mcp.json");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let t = Instant::now();
        let r = audit_mcp_with_processes(
            &McpAuditOptions {
                config_dirs: Vec::new(),
                home_dir: Some(h.clone()),
            },
            &[],
        )
        .unwrap();
        assert!(t.elapsed() < Duration::from_secs(5), "blocked on a FIFO");
        assert!(
            r.configured_servers.is_empty(),
            "{:?}",
            r.configured_servers
        );
        assert!(
            r.warnings.iter().any(|w| w.contains("symlinked_file")),
            "{:?}",
            r.warnings
        );
    }

    #[test]
    fn b3_llm_audit_refuses_symlinked_codex_config_outside_home() {
        use sj_core::llm_audit::{audit_llm_with_processes, AuditPolicy, LlmAuditOptions};
        let tmp = tempdir().unwrap();
        let h = tmp.path().canonicalize().unwrap();
        let ext = tempdir().unwrap();
        fs::write(
            ext.path().join("ext.toml"),
            "[plugins.\"ExternalPlugin@ext\"]\nenabled = true\n",
        )
        .unwrap();
        fs::create_dir_all(h.join(".codex")).unwrap();
        symlink(ext.path().join("ext.toml"), h.join(".codex/config.toml")).unwrap();
        let r = audit_llm_with_processes(
            &LlmAuditOptions {
                home_dir: h.clone(),
                policy: AuditPolicy::default(),
                now_epoch_secs: None,
            },
            &[],
        )
        .unwrap();
        let text = serde_json::to_string(&r).unwrap();
        assert!(!text.contains("ExternalPlugin"), "{text}");
        assert!(
            r.warnings.iter().any(|w| w.contains("symlinked_file")),
            "{:?}",
            r.warnings
        );
    }

    #[test]
    fn b3_llm_audit_never_blocks_on_a_codex_config_fifo() {
        use sj_core::llm_audit::{audit_llm_with_processes, AuditPolicy, LlmAuditOptions};
        let tmp = tempdir().unwrap();
        let h = tmp.path().canonicalize().unwrap();
        fs::create_dir_all(h.join(".codex")).unwrap();
        let fifo = h.join(".codex/config.toml");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let t = Instant::now();
        let r = audit_llm_with_processes(
            &LlmAuditOptions {
                home_dir: h.clone(),
                policy: AuditPolicy::default(),
                now_epoch_secs: None,
            },
            &[],
        )
        .unwrap();
        assert!(t.elapsed() < Duration::from_secs(5));
        assert!(
            r.warnings.iter().any(|w| w.contains("not_regular_file")),
            "{:?}",
            r.warnings
        );
    }
}
