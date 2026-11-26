//! Issue #12 leftovers: bare-repo worktrees, benign config over-blocking, the ref cap, and the temp
//! HOME cleanup. Real repositories, a logging git shim and hostile configs; every credential-looking
//! value is assembled at runtime.
#![cfg(unix)]
#[path = "common/gitfx.rs"]
mod gitfx;
use gitfx::*;
use sj_core::{
    orphans::{inspect_orphans, inspect_orphans_with_limits, OrphanOptions, OrphansReport, ProofLimits},
    protect::ProtectionContext,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn scan_with(root: &Path, limits: ProofLimits) -> OrphansReport {
    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    inspect_orphans_with_limits(root, &ctx, &OrphanOptions { max_depth: 5 }, limits).unwrap()
}
fn scan(root: &Path) -> OrphansReport {
    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    inspect_orphans(root, &ctx, &OrphanOptions { max_depth: 5 }).unwrap()
}
fn reasons_for<'a>(r: &'a OrphansReport, suffix: &str) -> Option<&'a Vec<String>> {
    r.blocked.iter().find(|b| b.path.ends_with(suffix)).map(|b| &b.reasons)
}
fn is_safe(r: &OrphansReport, suffix: &str) -> bool {
    r.safe_to_prune.iter().any(|c| c.path.ends_with(suffix))
}

// ---------------------------------------------------------------- item 1: bare main repository

/// `<scan>/proj/.git` is a FILE pointing at `.bare` (the popular bare-repo layout), and a linked
/// worktree lives OUTSIDE the scan root with an unpushed commit on its own branch.
fn bare_layout(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let _seed = clean_pushed_repo(root, "seed");
    let scan_root = root.join("scan");
    let proj = scan_root.join("proj");
    fs::create_dir_all(&proj).unwrap();
    git(&proj, &["clone", "--bare", root.join("remotes/seed.git").to_str().unwrap(), ".bare"]);
    fs::write(proj.join(".git"), "gitdir: ./.bare\n").unwrap();
    // hide the bare dir so the only thing that can stop `proj` is the bare-repo rule itself
    fs::write(proj.join(".bare/info/exclude"), ".bare\n.git\n").unwrap();
    let ext = root.join("elsewhere/feat");
    fs::create_dir_all(root.join("elsewhere")).unwrap();
    git(&proj.join(".bare"), &["worktree", "add", "-b", "feat", ext.to_str().unwrap(), "HEAD"]);
    fs::write(ext.join("work.txt"), "unpushed").unwrap();
    git(&ext, &["add", "work.txt"]);
    git(&ext, &["commit", "-m", "unpushed work"]);
    (scan_root, proj, ext)
}

#[test]
fn bare_main_repository_with_a_linked_worktree_is_refused_explicitly() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let (scan_root, _proj, ext) = bare_layout(tmp.path());
    let r = scan(&scan_root);
    assert!(!is_safe(&r, "/proj"), "deleting the bare main repo would destroy the linked worktree {ext:?}");
    let reasons = reasons_for(&r, "/proj").expect("proj reported blocked");
    assert!(
        reasons.iter().any(|x| x == "bare_main_repository"),
        "must be refused for the right reason, got {reasons:?}"
    );
}

/// A git shim that records the cwd of every invocation, then runs the real git.
fn logging_git_shim(root: &Path) -> (PathBuf, String) {
    let real = String::from_utf8(
        std::process::Command::new("sh").args(["-c", "command -v git"]).output().unwrap().stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    let bin = root.join("gitshim");
    fs::create_dir_all(&bin).unwrap();
    let log = root.join("git-cwds.log");
    write_script(
        &bin.join("git"),
        &format!("pwd -P >> '{}'\nexec '{}' \"$@\"\n", log.display(), real),
    );
    let old = std::env::var("PATH").unwrap_or_default();
    (log, format!("{}:{}", bin.display(), old))
}

#[test]
fn linked_worktree_of_a_bare_repo_never_runs_git_in_the_bare_repos_parent_dir() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let _seed = clean_pushed_repo(&root, "seed");
    let bare = root.join("holder/main.git");
    fs::create_dir_all(root.join("holder")).unwrap();
    git(&root, &["clone", "--bare", root.join("remotes/seed.git").to_str().unwrap(), bare.to_str().unwrap()]);
    let wts = root.join("wts");
    fs::create_dir_all(&wts).unwrap();
    git(&bare, &["worktree", "add", "-b", "feat", wts.join("feat").to_str().unwrap(), "HEAD"]);
    // a detached commit on the worktree forces the shared-reflog proof (the code path under test)
    let wt = wts.join("feat");
    git(&wt, &["checkout", "--detach"]);
    fs::write(wt.join("d.txt"), "d").unwrap();
    git(&wt, &["add", "d.txt"]);
    git(&wt, &["commit", "-m", "detached"]);
    git(&wt, &["checkout", "feat"]);

    let (log, path) = logging_git_shim(&root);
    let old = std::env::var("PATH").unwrap();
    std::env::set_var("PATH", path);
    let r = scan(&wts);
    std::env::set_var("PATH", old);

    let cwds = fs::read_to_string(&log).unwrap_or_default();
    assert!(!cwds.trim().is_empty(), "shim never ran; probe is not exercising the proof");
    let parent = root.join("holder");
    for c in cwds.lines() {
        assert_ne!(Path::new(c), parent.as_path(), "git ran in the bare repo's parent dir");
        assert!(
            !c.ends_with("/worktrees") && !c.contains("/main.git/worktrees/"),
            "git ran with a made-up work tree inside the git admin dir: {c}"
        );
    }
    assert!(!is_safe(&r, "/feat"), "detached commit is unpushed: {r:?}");
}

// ---------------------------------------------------------------- item 2: benign vs hostile config

fn pushed_repo_with_config(root: &Path, name: &str, cfg: &[(&str, &str)]) -> PathBuf {
    let repo = clean_pushed_repo(root, name);
    for (k, v) in cfg {
        git(&repo, &["config", "--add", k, v]);
    }
    repo
}

#[test]
fn benign_lfs_filter_and_credential_helper_do_not_block_a_clean_pushed_repo() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    pushed_repo_with_config(
        root,
        "benign",
        &[
            ("filter.lfs.clean", "git-lfs clean -- %f"),
            ("filter.lfs.smudge", "git-lfs smudge -- %f"),
            ("filter.lfs.process", "git-lfs filter-process"),
            ("filter.lfs.required", "true"),
            ("credential.helper", "osxkeychain"),
            ("credential.https://github.com.helper", "cache --timeout=3600"),
            ("credential.helper", "!gh auth git-credential"),
        ],
    );
    let r = scan(root);
    assert!(
        is_safe(&r, "/benign"),
        "benign git-lfs/credential config must not over-block: {:?}",
        reasons_for(&r, "/benign")
    );
}

#[test]
fn hostile_filter_and_credential_values_stay_blocked_and_never_execute() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let marker = root.join("PWNED");
    let m = marker.display().to_string();
    let touch = format!("touch {m}");
    let hostile: Vec<(String, String)> = vec![
        ("filter.lfs.clean".into(), format!("git-lfs clean -- %f; {touch}")),
        ("filter.lfs.clean".into(), format!("sh -c '{touch}'")),
        ("filter.lfs.smudge".into(), format!("git-lfs smudge -- %f && {touch}")),
        ("filter.lfs.process".into(), format!("git-lfs filter-process $({touch})")),
        ("filter.lfs.clean".into(), "/tmp/evil/git-lfs clean -- %f".into()),
        ("filter.lfs.clean".into(), "git-lfs clean -- %f ".to_string() + &format!("`{touch}`")),
        ("filter.evil.clean".into(), touch.clone()),
        ("lfs.extension.x.clean".into(), touch.clone()),
        ("lfs.customtransfer.x.path".into(), "/bin/sh".to_string()),
        ("lfs.standalonetransferagent".into(), "x".into()),
        ("credential.helper".into(), format!("!{touch}")),
        ("credential.helper".into(), format!("osxkeychain; {touch}")),
        ("credential.helper".into(), "/tmp/evil/git-credential-x".into()),
        ("credential.helper".into(), "store --file=/tmp/exfil".into()),
        ("credential.helper".into(), "totally-unknown-helper".into()),
        ("credential.https://github.com.helper".into(), format!("!{touch}")),
    ];
    for (i, (k, v)) in hostile.iter().enumerate() {
        let name = format!("h{i}");
        // a benign neighbour first, so the hostile entry is not the only one present
        pushed_repo_with_config(root, &name, &[("credential.helper", "osxkeychain"), (k, v)]);
    }
    let r = scan(root);
    for (i, (k, v)) in hostile.iter().enumerate() {
        let name = format!("/h{i}");
        assert!(!is_safe(&r, &name), "hostile `{k} = {v}` repo offered as safe");
        let reasons = reasons_for(&r, &name).unwrap_or_else(|| panic!("{name} missing: {r:?}"));
        assert!(
            reasons.iter().any(|x| x.starts_with("repo_config_can_execute")),
            "`{k} = {v}` blocked for the wrong reason: {reasons:?}"
        );
    }
    assert!(!marker.exists(), "a hostile config value executed during the proof");
}

// ---------------------------------------------------------------- item 3: ref cap

/// `n` DISTINCT commits (a chain on top of HEAD), each tagged `{prefix}{i}`, built with one
/// `git fast-import` so 5000 of them take a moment, not minutes. Distinct matters: refs that share a
/// commit would be deduplicated and never reach the cap.
fn add_tags(repo: &Path, n: usize, prefix: &str) {
    use std::io::Write;
    let head = git(repo, &["rev-parse", "HEAD"]);
    let mut s = String::new();
    for i in 0..n {
        let from = if i == 0 { head.clone() } else { format!(":{i}") };
        s.push_str(&format!(
            "commit refs/tags/{prefix}{i}\nmark :{}\ncommitter Probe <probe@example.invalid> {} +0000\ndata 2\nc\nfrom {from}\n\n",
            i + 1,
            1_700_000_000 + i
        ));
    }
    let mut child = std::process::Command::new("git")
        .current_dir(repo)
        .args(["fast-import", "--quiet"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn five_thousand_pushed_tags_are_verified_not_refused() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let repo = clean_pushed_repo(root, "tagged");
    add_tags(&repo, 5000, "rel-");
    git(&repo, &["push", "origin", "--tags"]);
    let r = scan(root);
    assert!(is_safe(&r, "/tagged"), "5000 pushed tags wrongly refused: {:?}", reasons_for(&r, "/tagged"));
}

#[test]
fn an_unpushed_tag_among_five_thousand_is_still_caught() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let repo = clean_pushed_repo(root, "lonely");
    add_tags(&repo, 5000, "rel-");
    git(&repo, &["push", "origin", "--tags"]);
    fs::write(repo.join("n.txt"), "n").unwrap();
    git(&repo, &["add", "n.txt"]);
    git(&repo, &["commit", "-m", "tag-only commit"]);
    git(&repo, &["tag", "unpushed-tag"]);
    git(&repo, &["reset", "--hard", "HEAD~1"]);
    let r = scan(root);
    assert!(!is_safe(&r, "/lonely"), "unpushed tag hidden among thousands");
}

#[test]
fn over_the_hard_cap_fails_closed_with_the_specific_reason() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let repo = clean_pushed_repo(root, "huge");
    // distinct commits so the (deduplicated) commit count really exceeds the cap
    for i in 0..12 {
        fs::write(repo.join("f.txt"), format!("{i}")).unwrap();
        git(&repo, &["add", "f.txt"]);
        git(&repo, &["commit", "-m", &format!("c{i}")]);
        git(&repo, &["tag", &format!("t{i}")]);
    }
    git(&repo, &["push", "origin", "HEAD", "--tags"]);
    let limits = ProofLimits { max_extra_commits: 5, ..ProofLimits::default() };
    let r = scan_with(root, limits);
    assert!(!is_safe(&r, "/huge"));
    let reasons = reasons_for(&r, "/huge").unwrap();
    assert!(
        reasons.iter().any(|x| x == "too_many_local_commits_to_verify"),
        "cap hit must be reported precisely, got {reasons:?}"
    );
    assert!(
        !reasons.iter().any(|x| x == "unpushed_tag_worktree_ref_or_reflog_commit"),
        "cap hit must not masquerade as an unpushed commit: {reasons:?}"
    );
}

// ---------------------------------------------------------------- item 5: temp HOME cleanup

fn homes_in(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("sj-git-home-"))
        .collect()
}

fn with_private_tmpdir<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
    let old = std::env::var_os("TMPDIR");
    std::env::set_var("TMPDIR", dir);
    let r = f();
    match old {
        Some(v) => std::env::set_var("TMPDIR", v),
        None => std::env::remove_var("TMPDIR"),
    }
    r
}

#[test]
fn temp_home_is_removed_after_a_normal_scan() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let priv_tmp = tmp.path().join("tmpdir");
    fs::create_dir_all(&priv_tmp).unwrap();
    let work = tmp.path().join("work");
    fs::create_dir_all(&work).unwrap();
    clean_pushed_repo(&work, "r");
    with_private_tmpdir(&priv_tmp, || {
        let _ = scan(&work);
    });
    assert_eq!(homes_in(&priv_tmp), Vec::<String>::new(), "temp HOME leaked after a normal scan");
}

#[test]
fn temp_home_is_removed_after_a_timeout() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let priv_tmp = tmp.path().join("tmpdir");
    fs::create_dir_all(&priv_tmp).unwrap();
    let work = tmp.path().join("work");
    fs::create_dir_all(&work).unwrap();
    let repo = clean_pushed_repo(&work, "stall");
    git(&repo, &["remote", "set-url", "origin", "ssh://stall.invalid/repo.git"]);
    let bin = tmp.path().join("shimbin");
    fs::create_dir_all(&bin).unwrap();
    write_script(&bin.join("ssh"), "sleep 120");
    let old = std::env::var("PATH").unwrap();
    std::env::set_var("PATH", format!("{}:{}", bin.display(), old));
    let limits = ProofLimits {
        call_timeout: Duration::from_secs(2),
        scan_budget: Duration::from_secs(30),
        ..ProofLimits::default()
    };
    with_private_tmpdir(&priv_tmp, || {
        let _ = scan_with(&work, limits);
    });
    std::env::set_var("PATH", old);
    assert_eq!(homes_in(&priv_tmp), Vec::<String>::new(), "temp HOME leaked after a timeout");
}

#[test]
fn temp_home_is_removed_when_the_scan_errors_out() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let priv_tmp = tmp.path().join("tmpdir");
    fs::create_dir_all(&priv_tmp).unwrap();
    let real = tmp.path().join("real");
    fs::create_dir_all(&real).unwrap();
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    with_private_tmpdir(&priv_tmp, || {
        let ctx = ProtectionContext::new(tmp.path().to_path_buf(), vec![]);
        // symlink scan root => Err before any repository work
        assert!(inspect_orphans(&link, &ctx, &OrphanOptions { max_depth: 5 }).is_err());
    });
    assert_eq!(homes_in(&priv_tmp), Vec::<String>::new(), "temp HOME leaked on the error path");
}

// ------------------------------------------------ review follow-ups (CodeRabbit on PR #26)

#[test]
fn a_checkout_that_actually_uses_lfs_stays_blocked_until_its_objects_are_verified() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let repo = pushed_repo_with_config(
        root,
        "lfsuser",
        &[
            ("filter.lfs.clean", "git-lfs clean -- %f"),
            ("filter.lfs.smudge", "git-lfs smudge -- %f"),
            ("filter.lfs.process", "git-lfs filter-process"),
        ],
    );
    // commits are pushed, but the LFS object store is local-only (push of LFS content was skipped)
    fs::write(repo.join(".gitattributes"), "*.bin filter=lfs diff=lfs merge=lfs -text\n").unwrap();
    git(&repo, &["add", ".gitattributes"]);
    git(&repo, &["commit", "-m", "track bins with lfs"]);
    git(&repo, &["push", "origin", "HEAD"]);
    let obj = repo.join(".git/lfs/objects/ab/cd");
    fs::create_dir_all(&obj).unwrap();
    fs::write(obj.join("abcd0000"), "local only content").unwrap();
    let r = scan(root);
    assert!(!is_safe(&r, "/lfsuser"), "LFS content that may exist only locally was offered as safe");
    let reasons = reasons_for(&r, "/lfsuser").unwrap();
    assert!(reasons.iter().any(|x| x == "lfs_objects_unverified"), "{reasons:?}");
}

#[test]
fn a_commit_shared_by_a_tag_and_the_reflog_counts_once_against_the_cap() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let repo = clean_pushed_repo(root, "shared");
    git(&repo, &["tag", "v1"]);
    git(&repo, &["push", "origin", "v1"]);
    let limits = ProofLimits { max_extra_commits: 1, ..ProofLimits::default() };
    let r = scan_with(root, limits);
    assert!(is_safe(&r, "/shared"), "one distinct commit must fit a cap of 1: {:?}", reasons_for(&r, "/shared"));
}
