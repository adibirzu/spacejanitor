//! B35: a filter configured in a submodule's own config (`.git/modules/*/config`) must never run
//! while the read-only proof inspects the parent repository.
#![cfg(unix)]
#[path = "common/gitfx.rs"]
mod gitfx;
use gitfx::*;
use sj_core::{
    orphans::{inspect_orphans, OrphanOptions},
    protect::ProtectionContext,
};
use std::fs;

#[test]
fn submodule_clean_filter_never_runs_during_the_parent_proof() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // a submodule origin that routes every file through filter "evil"
    let sub_origin = root.join("sub_origin");
    fs::create_dir_all(&sub_origin).unwrap();
    git(&sub_origin, &["init"]);
    fs::write(sub_origin.join(".gitattributes"), "* filter=evil\n").unwrap();
    fs::write(sub_origin.join("a.txt"), "payload\n").unwrap();
    git(&sub_origin, &["add", "."]);
    git(&sub_origin, &["commit", "-m", "sub"]);

    let repo = clean_pushed_repo(root, "parent");
    git(
        &repo,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            sub_origin.to_str().unwrap(),
            "sub",
        ],
    );
    git(&repo, &["commit", "-m", "add sub"]);
    git(&repo, &["push", "origin", "HEAD"]);

    // the attacker's filter lives ONLY in the submodule's own config
    let marker = root.join("PWNED");
    let shim = root.join("evil.sh");
    write_script(&shim, &format!("touch '{}'\ncat", marker.display()));
    let module_cfg = repo.join(".git/modules/sub/config");
    assert!(module_cfg.exists(), "submodule gitdir config must exist");
    git(
        root,
        &[
            "config",
            "--file",
            module_cfg.to_str().unwrap(),
            "filter.evil.clean",
            shim.to_str().unwrap(),
        ],
    );
    // stat-dirty a tracked submodule file so status must re-hash it through the clean filter
    let status = std::process::Command::new("touch")
        .args(["-t", "203001010000"])
        .arg(repo.join("sub/a.txt"))
        .status()
        .unwrap();
    assert!(status.success());

    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    let report = inspect_orphans(root, &ctx, &OrphanOptions { max_depth: 5 }).unwrap();

    assert!(
        !marker.exists(),
        "submodule clean filter executed during the proof (B35)"
    );
    assert!(
        report
            .safe_to_prune
            .iter()
            .all(|c| !c.path.ends_with("/parent")),
        "a repository with an initialised submodule must not be offered as safe"
    );
}
