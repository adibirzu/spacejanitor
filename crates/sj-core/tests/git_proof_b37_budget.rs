//! B37: timeouts and budgets are a real contract: the whole process group dies on timeout, the
//! scan has a wall-clock deadline, and a FIFO planted at `.git/config` cannot hang the scan.
#![cfg(unix)]
#[path = "common/gitfx.rs"]
mod gitfx;
use gitfx::*;
use sj_core::{
    orphans::{inspect_orphans, inspect_orphans_with_limits, OrphanOptions, ProofLimits},
    protect::ProtectionContext,
};
use std::fs;
use std::time::{Duration, Instant};

/// Puts a stalling `ssh` shim first on PATH. It records its pid, then hangs.
fn stall_shim(root: &std::path::Path) -> (std::path::PathBuf, String) {
    let bin = root.join("shimbin");
    fs::create_dir_all(&bin).unwrap();
    let pids = root.join("pids");
    write_script(
        &bin.join("ssh"),
        &format!("echo $$ >> '{}'\nsleep 120\n", pids.display()),
    );
    let old = std::env::var("PATH").unwrap_or_default();
    (pids, format!("{}:{}", bin.display(), old))
}

fn lim(call: u64, scan: u64) -> ProofLimits {
    ProofLimits {
        call_timeout: Duration::from_secs(call),
        repo_budget: Duration::from_secs(60),
        scan_budget: Duration::from_secs(scan),
        ..ProofLimits::default()
    }
}

#[test]
fn timeout_kills_the_whole_process_group_not_just_git() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let repo = clean_pushed_repo(root, "stall");
    git(
        &repo,
        &[
            "remote",
            "set-url",
            "origin",
            "ssh://stall.invalid/repo.git",
        ],
    );
    let (pids, path) = stall_shim(root);
    let old_path = std::env::var("PATH").unwrap();
    std::env::set_var("PATH", path);
    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    let _ = inspect_orphans_with_limits(root, &ctx, &OrphanOptions { max_depth: 5 }, lim(2, 60))
        .unwrap();
    std::env::set_var("PATH", old_path);

    std::thread::sleep(Duration::from_millis(500));
    let recorded = fs::read_to_string(&pids).unwrap_or_default();
    assert!(
        !recorded.trim().is_empty(),
        "the ssh shim never ran; probe is not exercising the proof"
    );
    for pid in recorded
        .lines()
        .filter_map(|l| l.trim().parse::<i32>().ok())
    {
        let alive = pid_alive(pid);
        if alive {
            let _ = std::process::Command::new("kill")
                .args(["-9", &pid.to_string()])
                .status();
        }
        assert!(!alive, "ssh child {pid} survived the git timeout (B37)");
    }
}

#[test]
fn scan_wide_deadline_bounds_total_time_across_stalled_remotes() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for i in 0..4 {
        let repo = clean_pushed_repo(root, &format!("stall{i}"));
        git(
            &repo,
            &[
                "remote",
                "set-url",
                "origin",
                "ssh://stall.invalid/repo.git",
            ],
        );
    }
    let (pids, path) = stall_shim(root);
    let old_path = std::env::var("PATH").unwrap();
    std::env::set_var("PATH", path);
    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    let t0 = Instant::now();
    // 4 stalled remotes at 3s per call would take 12s+; the scan deadline is 4s
    let report =
        inspect_orphans_with_limits(root, &ctx, &OrphanOptions { max_depth: 5 }, lim(3, 4))
            .unwrap();
    let took = t0.elapsed();
    std::env::set_var("PATH", old_path);
    for pid in fs::read_to_string(&pids)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().parse::<i32>().ok())
    {
        let _ = std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status();
    }

    assert!(
        took < Duration::from_secs(9),
        "scan took {took:?}; no scan-wide deadline (B37)"
    );
    assert!(report.safe_to_prune.is_empty());
    assert!(
        report
            .blocked
            .iter()
            .any(|b| b.reasons.iter().any(|r| r == "scan_budget_exceeded")),
        "repos past the deadline must say so: {:?}",
        report.blocked
    );
}

#[test]
fn fifo_at_git_config_cannot_hang_the_scan() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let repo = clean_pushed_repo(&root, "fifo");
    let cfg = repo.join(".git/config");
    fs::remove_file(&cfg).unwrap();
    assert!(std::process::Command::new("mkfifo")
        .arg(&cfg)
        .status()
        .unwrap()
        .success());

    let (tx, rx) = std::sync::mpsc::channel();
    let r2 = root.clone();
    std::thread::spawn(move || {
        let ctx = ProtectionContext::new(r2.clone(), vec![]);
        let rep = inspect_orphans(&r2, &ctx, &OrphanOptions { max_depth: 5 });
        let _ = tx.send(rep.is_ok());
    });
    let finished = rx.recv_timeout(Duration::from_secs(15));
    // release any reader still blocked on the FIFO so the probe never leaks a hung process
    let _ = fs::OpenOptions::new().read(true).write(true).open(&cfg);
    assert_eq!(
        finished,
        Ok(true),
        "scan hung on a FIFO planted at .git/config (B37)"
    );
}
