//! B36: repository config (URL-scoped `http.<url>.proxy`) or inherited proxy env must never steer
//! the `ls-remote` proof through an attacker proxy, and no credential helper may answer there.
#![cfg(unix)]
#[path = "common/gitfx.rs"]
mod gitfx;
use gitfx::*;
use sj_core::{
    orphans::{inspect_orphans, OrphanOptions},
    protect::ProtectionContext,
};

fn run_scan(root: &std::path::Path) -> sj_core::orphans::OrphansReport {
    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    inspect_orphans(root, &ctx, &OrphanOptions { max_depth: 5 }).unwrap()
}

#[test]
fn url_scoped_proxy_in_repo_config_cannot_capture_credentials() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let proxy = AttackerProxy::start();
    let repo = clean_pushed_repo(root, "victim");
    git(
        &repo,
        &[
            "remote",
            "set-url",
            "origin",
            "http://victim.invalid/repo.git",
        ],
    );
    git(
        &repo,
        &["config", "http.http://victim.invalid/.proxy", &proxy.url()],
    );
    git(
        &repo,
        &["config", "http.http://victim.invalid/.sslVerify", "false"],
    );

    let user_cfg = root.join("user.gitconfig");
    write_user_gitconfig_with_helper(&user_cfg);
    std::env::set_var("GIT_CONFIG_GLOBAL", &user_cfg);
    let report = run_scan(root);
    std::env::remove_var("GIT_CONFIG_GLOBAL");

    assert!(
        proxy.requests().is_empty(),
        "sj contacted the attacker proxy (B36): {:?}",
        proxy.requests()
    );
    assert!(
        !proxy.saw_credentials(),
        "credentials reached the attacker proxy (B36)"
    );
    assert!(report
        .safe_to_prune
        .iter()
        .all(|c| !c.path.ends_with("/victim")));
}

#[test]
fn inherited_proxy_env_and_user_credential_helper_are_not_used_by_the_proof() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let proxy = AttackerProxy::start();
    let repo = clean_pushed_repo(root, "victim");
    git(
        &repo,
        &[
            "remote",
            "set-url",
            "origin",
            "http://victim.invalid/repo.git",
        ],
    );

    let user_cfg = root.join("user.gitconfig");
    write_user_gitconfig_with_helper(&user_cfg);
    std::env::set_var("GIT_CONFIG_GLOBAL", &user_cfg);
    for k in ["http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"] {
        std::env::set_var(k, proxy.url());
    }
    let report = run_scan(root);
    for k in [
        "http_proxy",
        "HTTP_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "GIT_CONFIG_GLOBAL",
    ] {
        std::env::remove_var(k);
    }

    assert!(
        proxy.requests().is_empty(),
        "proof inherited the proxy env (B36): {:?}",
        proxy.requests()
    );
    assert!(
        !proxy.saw_credentials(),
        "credential helper answered inside the proof (B36)"
    );
    assert!(report
        .safe_to_prune
        .iter()
        .all(|c| !c.path.ends_with("/victim")));
}
