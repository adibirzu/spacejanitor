//! Cross-family review (Gemini) follow-ups on the git-proof hardening, each reproduced live:
//! ~/.netrc credential leak, arbitrary git-remote-<proto> helper exec, a setsid() grandchild that
//! outlives the process-group kill and holds our pipe, and a FIFO behind core.attributesFile.
#![cfg(unix)]
#[path = "common/gitfx.rs"]
mod gitfx;
use gitfx::*;
use sj_core::{
    orphans::{inspect_orphans_with_limits, OrphanOptions, OrphansReport, ProofLimits},
    protect::ProtectionContext,
};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

fn scan(root: &Path, call: u64) -> (OrphansReport, Duration) {
    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    let limits = ProofLimits {
        call_timeout: Duration::from_secs(call),
        repo_budget: Duration::from_secs(60),
        scan_budget: Duration::from_secs(60),
    };
    let t0 = Instant::now();
    let r =
        inspect_orphans_with_limits(root, &ctx, &OrphanOptions { max_depth: 5 }, limits).unwrap();
    (r, t0.elapsed())
}

fn with_path_shim<T>(bin: &Path, f: impl FnOnce() -> T) -> T {
    let old = std::env::var("PATH").unwrap();
    std::env::set_var("PATH", format!("{}:{}", bin.display(), old));
    let r = f();
    std::env::set_var("PATH", old);
    r
}

#[test]
fn netrc_in_home_is_not_sent_to_an_attacker_http_remote() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let proxy = AttackerProxy::start();
    let repo = clean_pushed_repo(root, "netrc");
    git(
        &repo,
        &[
            "remote",
            "set-url",
            "origin",
            &format!("http://127.0.0.1:{}/a.git", proxy.port),
        ],
    );
    let home = root.join("home");
    fs::create_dir_all(&home).unwrap();
    let pw = format!("{}{}", "netrc-pass-", 6 * 111);
    fs::write(
        home.join(".netrc"),
        format!("machine 127.0.0.1\nlogin probeuser\npassword {pw}\n"),
    )
    .unwrap();
    let old_home = std::env::var("HOME").unwrap();
    std::env::set_var("HOME", &home);
    let _ = scan(root, 5);
    std::env::set_var("HOME", old_home);
    assert!(
        !proxy.saw_credentials(),
        "~/.netrc credentials reached the attacker remote"
    );
}

#[test]
fn unknown_git_remote_helper_is_never_executed() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let repo = clean_pushed_repo(root, "helper");
    git(&repo, &["remote", "set-url", "origin", "evil::pwned"]);
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let marker = root.join("PWNED");
    write_script(
        &bin.join("git-remote-evil"),
        &format!("touch '{}'\nexit 1", marker.display()),
    );
    let (report, _) = with_path_shim(&bin, || scan(root, 5));
    assert!(
        !marker.exists(),
        "git-remote-evil helper executed during the proof"
    );
    assert!(report
        .safe_to_prune
        .iter()
        .all(|c| !c.path.ends_with("/helper")));
}

#[test]
fn setsid_grandchild_holding_the_pipe_cannot_outlast_the_call_timeout() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let repo = clean_pushed_repo(root, "setsid");
    git(&repo, &["remote", "set-url", "origin", "ssh://x.invalid/r"]);
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    write_script(
        &bin.join("ssh"),
        "python3 -c 'import os,time; os.setsid(); time.sleep(9)' &\nexit 1",
    );
    let (_, took) = with_path_shim(&bin, || scan(root, 2));
    assert!(
        took < Duration::from_secs(6),
        "reader join outlived the budget: {took:?}"
    );
}

#[test]
fn fifo_behind_core_attributes_file_does_not_burn_the_call_timeout() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let repo = clean_pushed_repo(root, "attrs");
    let fifo = root.join("f");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    git(
        &repo,
        &["config", "core.attributesFile", fifo.to_str().unwrap()],
    );
    git(
        &repo,
        &["config", "core.excludesFile", fifo.to_str().unwrap()],
    );
    let (_, took) = scan(root, 3);
    let _ = fs::OpenOptions::new().read(true).write(true).open(&fifo);
    assert!(
        took < Duration::from_secs(2),
        "scan stalled on a repo-pointed FIFO: {took:?}"
    );
}

#[test]
fn repo_protocol_allow_cannot_reenable_a_remote_helper() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let repo = clean_pushed_repo(root, "protoallow");
    git(&repo, &["remote", "set-url", "origin", "evil::pwned"]);
    git(&repo, &["config", "protocol.evil.allow", "always"]);
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let marker = root.join("PWNED");
    write_script(
        &bin.join("git-remote-evil"),
        &format!("touch '{}'\nexit 1", marker.display()),
    );
    let (report, _) = with_path_shim(&bin, || scan(root, 5));
    assert!(
        !marker.exists(),
        "protocol.evil.allow=always re-enabled a remote helper"
    );
    assert!(report
        .safe_to_prune
        .iter()
        .all(|c| !c.path.ends_with("/protoallow")));
}

/// The scrubbed config must still honour the user's line-ending settings, otherwise every clean
/// checkout made with core.autocrlf=true (the Git for Windows default) looks "dirty".
#[test]
fn users_autocrlf_setting_does_not_make_clean_repos_look_dirty() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let cfg = root.join("user.gitconfig");
    fs::write(&cfg, "[core]\n\tautocrlf = true\n").unwrap();
    std::env::set_var("GIT_CONFIG_GLOBAL", &cfg);
    let repo = clean_pushed_repo(root, "crlf");
    fs::write(repo.join("lines.txt"), "a\nb\n").unwrap();
    git(&repo, &["add", "lines.txt"]);
    git(&repo, &["commit", "-m", "lines"]);
    git(&repo, &["push", "origin", "HEAD"]);
    // re-materialise the file so the worktree copy has CRLF endings per the user's setting
    fs::remove_file(repo.join("lines.txt")).unwrap();
    git(&repo, &["checkout", "--", "lines.txt"]);
    assert!(fs::read(repo.join("lines.txt"))
        .unwrap()
        .windows(2)
        .any(|w| w == b"\r\n"));
    let (report, _) = scan(root, 10);
    std::env::remove_var("GIT_CONFIG_GLOBAL");
    assert!(
        report
            .safe_to_prune
            .iter()
            .any(|c| c.path.ends_with("/crlf")),
        "clean autocrlf checkout reported unsafe: {:?}",
        report.blocked
    );
}
