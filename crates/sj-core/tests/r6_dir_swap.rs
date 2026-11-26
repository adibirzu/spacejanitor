//! R6 blocker (item 70, head 75b178d): a directory swapped for a symlink to a protected root
//! while it is being listed must never leak the protected entry names.
//! Synthetic fixtures only; the swap uses an atomic exchange of two sibling paths.
#![cfg(unix)]

use sj_core::llm_audit::{audit_llm_with_processes, AuditPolicy, LlmAuditOptions};
use sj_core::mcp_audit::{audit_mcp_with_processes, McpAuditOptions};
use std::ffi::CString;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
/// Temp dir outside protected home subtrees; on Windows the default sits under `AppData`, which
/// the protect list refuses, so the audits would scan nothing.
fn tempdir() -> std::io::Result<tempfile::TempDir> {
    if cfg!(windows) {
        tempfile::Builder::new().tempdir_in(env!("CARGO_TARGET_TMPDIR"))
    } else {
        tempfile::tempdir()
    }
}

fn swap(a: &Path, b: &Path) -> bool {
    let ca = CString::new(a.to_str().unwrap()).unwrap();
    let cb = CString::new(b.to_str().unwrap()).unwrap();
    #[cfg(target_os = "macos")]
    unsafe {
        libc::renamex_np(ca.as_ptr(), cb.as_ptr(), libc::RENAME_SWAP) == 0
    }
    #[cfg(target_os = "linux")]
    unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            ca.as_ptr(),
            libc::AT_FDCWD,
            cb.as_ptr(),
            libc::RENAME_EXCHANGE,
        ) == 0
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (ca, cb);
        false
    }
}

const ITERATIONS: usize = 300;
const NEEDLE_DIR: &str = "SecretClaudeProjSynthetic";
const NEEDLE_FILE: &str = "SecretSessionSynthetic.json";

fn run_swapper(
    a: std::path::PathBuf,
    b: std::path::PathBuf,
) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    let h = std::thread::spawn(move || {
        while !s.load(Ordering::Relaxed) {
            swap(&a, &b);
        }
    });
    (stop, h)
}

#[test]
fn llm_audit_dir_swap_never_leaks_protected_names() {
    let tmp = tempdir().unwrap();
    let h = tmp.path().canonicalize().unwrap();
    let secret = h.join(".claude/projects").join(NEEDLE_DIR);
    fs::create_dir_all(&secret).unwrap();
    fs::create_dir_all(h.join(".gemini/extensions/benign")).unwrap();
    std::os::unix::fs::symlink(
        h.join(".claude/projects"),
        h.join(".gemini/extensions_swap"),
    )
    .unwrap();
    let (stop, th) = run_swapper(
        h.join(".gemini/extensions"),
        h.join(".gemini/extensions_swap"),
    );
    let mut leaks = 0;
    for _ in 0..ITERATIONS {
        let r = audit_llm_with_processes(
            &LlmAuditOptions {
                home_dir: h.clone(),
                policy: AuditPolicy::default(),
                now_epoch_secs: Some(1_800_000_000),
            },
            &[],
        )
        .unwrap();
        if serde_json::to_string(&r).unwrap().contains(NEEDLE_DIR) {
            leaks += 1;
        }
    }
    stop.store(true, Ordering::Relaxed);
    th.join().unwrap();
    assert_eq!(
        leaks, 0,
        "protected names leaked in {leaks}/{ITERATIONS} runs"
    );
}

#[test]
fn llm_audit_skills_dir_swap_never_leaks_protected_names() {
    let tmp = tempdir().unwrap();
    let h = tmp.path().canonicalize().unwrap();
    fs::create_dir_all(h.join(".claude/projects").join(NEEDLE_DIR)).unwrap();
    fs::create_dir_all(h.join(".codex/skills/benign")).unwrap();
    std::os::unix::fs::symlink(h.join(".claude/projects"), h.join(".codex/skills_swap")).unwrap();
    let (stop, th) = run_swapper(h.join(".codex/skills"), h.join(".codex/skills_swap"));
    let mut leaks = 0;
    for _ in 0..ITERATIONS {
        let r = audit_llm_with_processes(
            &LlmAuditOptions {
                home_dir: h.clone(),
                policy: AuditPolicy::default(),
                now_epoch_secs: Some(1_800_000_000),
            },
            &[],
        )
        .unwrap();
        let s = serde_json::to_string(&r).unwrap();
        // names are emitted via stale/duplicate/broken entries and by-client counts
        if s.contains(NEEDLE_DIR) {
            leaks += 1;
        }
    }
    stop.store(true, Ordering::Relaxed);
    th.join().unwrap();
    assert_eq!(
        leaks, 0,
        "protected names leaked in {leaks}/{ITERATIONS} runs"
    );
}

#[test]
fn mcp_audit_config_dir_swap_never_leaks_protected_names() {
    let tmp = tempdir().unwrap();
    let h = tmp.path().canonicalize().unwrap();
    let sec = h.join(".claude/projects").join(NEEDLE_DIR);
    fs::create_dir_all(&sec).unwrap();
    fs::write(
        sec.join(NEEDLE_FILE),
        r#"{"mcpServers":{"CLAUDE_INNER":{"command":"npx"}}}"#,
    )
    .unwrap();
    fs::create_dir_all(h.join("plain/sub")).unwrap();
    std::os::unix::fs::symlink(&sec, h.join("plain/sub_swap")).unwrap();
    let (stop, th) = run_swapper(h.join("plain/sub"), h.join("plain/sub_swap"));
    let mut leaks = 0;
    for _ in 0..ITERATIONS {
        let r = audit_mcp_with_processes(
            &McpAuditOptions {
                config_dirs: vec![h.join("plain")],
                home_dir: Some(h.clone()),
            },
            &[],
        )
        .unwrap();
        let s = serde_json::to_string(&r).unwrap();
        if s.contains(NEEDLE_FILE) || s.contains("CLAUDE_INNER") {
            leaks += 1;
        }
    }
    stop.store(true, Ordering::Relaxed);
    th.join().unwrap();
    assert_eq!(
        leaks, 0,
        "protected names leaked in {leaks}/{ITERATIONS} runs"
    );
}
