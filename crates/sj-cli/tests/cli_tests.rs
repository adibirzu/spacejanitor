use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn sj_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sj")
}

fn run_git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Test User")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test User")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("git command should run");
    assert!(
        out.status.success(),
        "git {:?} failed in {}: {}",
        args,
        dir.display(),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_help_and_invalid_usage_exit_codes() {
    let help = Command::new(sj_bin()).arg("--help").output().unwrap();
    assert_eq!(help.status.code(), Some(0));

    let bad = Command::new(sj_bin())
        .arg("--no-such-flag")
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
}

#[test]
fn cli_doctor_scan_trash_orphans_plan_end_to_end() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let trash_dir = root.join("Trash");
    fs::create_dir_all(&trash_dir).unwrap();
    fs::write(trash_dir.join("cache.tar"), vec![0u8; 256]).unwrap();

    // doctor --json
    let doctor = Command::new(sj_bin())
        .env("HOME", root)
        .env("USERPROFILE", root)
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    assert_eq!(doctor.status.code(), Some(0));
    let doc_json: serde_json::Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(doc_json["schema"], "spacejanitor.doctor.v1");
    assert_eq!(doc_json["ready"], true);

    // scan --json
    let scan = Command::new(sj_bin())
        .env("HOME", root)
        .env("USERPROFILE", root)
        .args(["scan", root.to_str().unwrap(), "--json"])
        .env("HOME", root)
        .env("USERPROFILE", root)
        .output()
        .unwrap();
    assert_eq!(scan.status.code(), Some(0));
    let scan_json: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    assert_eq!(scan_json["schema"], "spacejanitor.storage.v1");

    // trash --path --json
    let trash = Command::new(sj_bin())
        .env("HOME", root)
        .env("USERPROFILE", root)
        .args(["trash", "--path", trash_dir.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(trash.status.code(), Some(0));
    let trash_json: serde_json::Value = serde_json::from_slice(&trash.stdout).unwrap();
    assert_eq!(trash_json["schema"], "spacejanitor.trash.v1");
    assert_eq!(trash_json["item_count"], 1);

    // orphans --json
    let orphans = Command::new(sj_bin())
        .env("HOME", root)
        .env("USERPROFILE", root)
        .args(["orphans", "--include-orphans", root.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(orphans.status.code(), Some(0));
    let orphans_json: serde_json::Value = serde_json::from_slice(&orphans.stdout).unwrap();
    assert_eq!(orphans_json["schema"], "spacejanitor.orphans.v1");

    // plan --json (dry-run by default)
    let plan = Command::new(sj_bin())
        .env("HOME", root)
        .env("USERPROFILE", root)
        .args([
            "plan",
            root.to_str().unwrap(),
            "--include-trash",
            "--trash-path",
            trash_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(plan.status.code(), Some(0));
    let plan_json: serde_json::Value = serde_json::from_slice(&plan.stdout).unwrap();
    assert_eq!(plan_json["schema"], "spacejanitor.proposal.v1");
    assert_eq!(plan_json["mode"], "dry-run");
    assert_eq!(plan_json["mutated"], false);
    assert!(trash_dir.join("cache.tar").exists());

    // plan --execute without confirmation must fail with exit code 2 and not mutate
    let exec_fail = Command::new(sj_bin())
        .env("HOME", root)
        .env("USERPROFILE", root)
        .args([
            "plan",
            root.to_str().unwrap(),
            "--include-trash",
            "--trash-path",
            trash_dir.to_str().unwrap(),
            "--execute",
        ])
        .output()
        .unwrap();
    assert_eq!(exec_fail.status.code(), Some(2));
    assert!(trash_dir.join("cache.tar").exists());

    // plan --trash-path <arbitrary> --execute --confirm must fail with exit code 2 and not mutate
    let plan_id = plan_json["items"][0]["id"].as_str().unwrap();
    let plan_sha = plan_json["plan_sha256"].as_str().unwrap();
    let exec_arbitrary = Command::new(sj_bin())
        .env("HOME", root)
        .env("USERPROFILE", root)
        .args([
            "plan",
            root.to_str().unwrap(),
            "--include-trash",
            "--trash-path",
            trash_dir.to_str().unwrap(),
            "--execute",
            "--confirm",
            "--plan-sha256",
            plan_sha,
            "--item",
            plan_id,
        ])
        .output()
        .unwrap();
    assert_eq!(exec_arbitrary.status.code(), Some(2));
    assert!(trash_dir.join("cache.tar").exists());

    // scan --depth 0 must fail with exit code 2
    let scan_zero = Command::new(sj_bin())
        .env("HOME", root)
        .env("USERPROFILE", root)
        .args(["scan", root.to_str().unwrap(), "--depth", "0"])
        .output()
        .unwrap();
    assert_eq!(scan_zero.status.code(), Some(2));

    // doctor --json includes real probe fields
    assert!(doc_json.get("git_available").is_some());
    assert!(doc_json.get("home_dir_resolved").is_some());
}

#[test]
fn cli_orphans_and_plan_accept_default_dot_relative_and_absolute_paths() {
    let tmp = tempdir().unwrap();
    let home = tmp.path();
    let remote = home.join("origin.git");
    let ws = home.join("ws");
    let checkout = ws.join("checkout");
    fs::create_dir_all(&remote).unwrap();
    fs::create_dir_all(&checkout).unwrap();

    run_git(&remote, &["init", "--bare"]);
    run_git(&checkout, &["init"]);
    run_git(&checkout, &["checkout", "-b", "main"]);
    fs::write(checkout.join("README.md"), "hello\n").unwrap();
    run_git(&checkout, &["add", "README.md"]);
    run_git(&checkout, &["commit", "-m", "initial"]);
    run_git(
        &checkout,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    run_git(&checkout, &["push", "-u", "origin", "main"]);

    let checkout_abs = checkout.to_str().unwrap();
    let orphan_invocations: Vec<(&Path, Vec<&str>)> = vec![
        (&ws, vec!["orphans", "--include-orphans", "--json"]),
        (&ws, vec!["orphans", "--include-orphans", "checkout", "--json"]),
        (&ws, vec!["orphans", "--include-orphans", checkout_abs, "--json"]),
        (&checkout, vec!["orphans", "--include-orphans", "--json"]),
    ];

    let mut expected_branch: Option<String> = None;
    let mut expected_head: Option<String> = None;

    for (cwd, args) in &orphan_invocations {
        let out = Command::new(sj_bin())
            .current_dir(cwd)
            .env("HOME", home)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "sj {:?} in {} failed: {}",
            args,
            cwd.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let safe = json["safe_to_prune"].as_array().unwrap();
        let blocked = json["blocked"].as_array().unwrap();
        assert_eq!(
            safe.len(),
            1,
            "expected 1 safe_to_prune for {:?} in {}, got: {json}",
            args,
            cwd.display()
        );
        assert!(
            blocked.is_empty(),
            "expected empty blocked for {:?} in {}, got: {json}",
            args,
            cwd.display()
        );
        let branch = safe[0]["branch"].as_str().unwrap().to_string();
        let head = safe[0]["head"].as_str().unwrap().to_string();
        assert!(!branch.is_empty());
        assert!(!head.is_empty());

        if let Some(ref b) = expected_branch {
            assert_eq!(&branch, b);
        } else {
            expected_branch = Some(branch);
        }
        if let Some(ref h) = expected_head {
            assert_eq!(&head, h);
        } else {
            expected_head = Some(head);
        }
    }

    let plan_invocations: Vec<Vec<&str>> = vec![
        vec!["plan", "--include-orphans", "--json"],
        vec!["plan", "checkout", "--include-orphans", "--json"],
        vec!["plan", checkout_abs, "--include-orphans", "--json"],
    ];

    let mut expected_snapshot: Option<(String, String, String, String)> = None;
    for args in &plan_invocations {
        let out = Command::new(sj_bin())
            .current_dir(&ws)
            .env("HOME", home)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "sj {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let items = json["items"].as_array().unwrap();
        assert_eq!(
            items.len(),
            1,
            "expected 1 plan item for {:?}, got: {json}",
            args
        );
        assert_eq!(items[0]["kind"], "orphan_worktree");
        let snap = &items[0]["snapshot"];
        let content_sha = snap["content_or_tree_sha256"].as_str().unwrap().to_string();
        let git_head = snap["git_head"].as_str().unwrap().to_string();
        let git_tree = snap["git_tree"].as_str().unwrap().to_string();
        let git_refs_sha = snap["git_refs_sha256"].as_str().unwrap().to_string();
        assert_eq!(Some(&git_head), expected_head.as_ref());

        let tuple = (content_sha, git_head, git_tree, git_refs_sha);
        if let Some(ref prev) = expected_snapshot {
            assert_eq!(&tuple, prev);
        } else {
            expected_snapshot = Some(tuple);
        }
    }
}

#[cfg(unix)]
#[test]
fn cli_orphans_and_plan_preserve_symlink_parent_path_semantics() {
    let tmp = tempdir().unwrap();
    let home = tmp.path();
    let remote = home.join("origin.git");
    let real_dir = home.join("real");
    let sub = real_dir.join("sub");
    let checkout = real_dir.join("checkout");
    fs::create_dir_all(&remote).unwrap();
    fs::create_dir_all(&sub).unwrap();
    fs::create_dir_all(&checkout).unwrap();
    std::os::unix::fs::symlink(&sub, home.join("link")).unwrap();

    run_git(&remote, &["init", "--bare"]);
    run_git(&checkout, &["init"]);
    run_git(&checkout, &["checkout", "-b", "main"]);
    fs::write(checkout.join("README.md"), "hello\n").unwrap();
    run_git(&checkout, &["add", "README.md"]);
    run_git(&checkout, &["commit", "-m", "initial"]);
    run_git(
        &checkout,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    run_git(&checkout, &["push", "-u", "origin", "main"]);

    let canonical_checkout = checkout.to_string_lossy().into_owned();
    let abs_symlink_checkout = home.join("link/../checkout").to_string_lossy().into_owned();
    let abs_symlink_parent = home.join("link/..").to_string_lossy().into_owned();

    let inputs: Vec<&str> = vec![
        &canonical_checkout,
        &abs_symlink_checkout,
        "link/../checkout",
        &abs_symlink_parent,
    ];

    let mut expected_branch: Option<String> = None;
    let mut expected_head: Option<String> = None;

    for input in &inputs {
        let out = Command::new(sj_bin())
            .current_dir(home)
            .env("HOME", home)
            .args(["orphans", "--include-orphans", input, "--json"])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "sj orphans {} --json failed: {}",
            input,
            String::from_utf8_lossy(&out.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let safe = json["safe_to_prune"].as_array().unwrap();
        let blocked = json["blocked"].as_array().unwrap();
        assert_eq!(
            safe.len(),
            1,
            "expected 1 safe_to_prune for '{input}', got: {json}"
        );
        assert!(
            blocked.is_empty(),
            "expected empty blocked for '{input}', got: {json}"
        );
        let branch = safe[0]["branch"].as_str().unwrap().to_string();
        let head = safe[0]["head"].as_str().unwrap().to_string();
        assert!(!branch.is_empty());
        assert!(!head.is_empty());

        if let Some(ref b) = expected_branch {
            assert_eq!(&branch, b);
        } else {
            expected_branch = Some(branch);
        }
        if let Some(ref h) = expected_head {
            assert_eq!(&head, h);
        } else {
            expected_head = Some(head);
        }
    }

    let mut expected_snapshot: Option<(String, String, String, String)> = None;
    for input in &inputs {
        let out = Command::new(sj_bin())
            .current_dir(home)
            .env("HOME", home)
            .args(["plan", input, "--include-orphans", "--json"])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "sj plan {} --include-orphans --json failed: {}",
            input,
            String::from_utf8_lossy(&out.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let items = json["items"].as_array().unwrap();
        assert_eq!(
            items.len(),
            1,
            "expected 1 plan item for '{input}', got: {json}"
        );
        assert_eq!(items[0]["kind"], "orphan_worktree");
        let snap = &items[0]["snapshot"];
        let content_sha = snap["content_or_tree_sha256"].as_str().unwrap().to_string();
        let git_head = snap["git_head"].as_str().unwrap().to_string();
        let git_tree = snap["git_tree"].as_str().unwrap().to_string();
        let git_refs_sha = snap["git_refs_sha256"].as_str().unwrap().to_string();
        assert_eq!(Some(&git_head), expected_head.as_ref());

        let tuple = (content_sha, git_head, git_tree, git_refs_sha);
        if let Some(ref prev) = expected_snapshot {
            assert_eq!(&tuple, prev);
        } else {
            expected_snapshot = Some(tuple);
        }
    }
}

#[cfg(unix)]
#[test]
fn cli_plan_preview_and_execute_preserve_relative_remote_with_symlink_parent() {
    let tmp = tempdir().unwrap();
    let home = tmp.path();
    let real_dir = home.join("real");
    let sub = real_dir.join("sub");
    let remote = real_dir.join("remotes").join("origin.git");
    let ws = home.join("ws");
    let checkout = ws.join("checkout");
    fs::create_dir_all(&sub).unwrap();
    fs::create_dir_all(&remote).unwrap();
    fs::create_dir_all(&checkout).unwrap();
    std::os::unix::fs::symlink(&sub, ws.join("link")).unwrap();

    run_git(&remote, &["init", "--bare"]);
    run_git(&checkout, &["init"]);
    run_git(&checkout, &["checkout", "-b", "main"]);
    fs::write(checkout.join("README.md"), "hello\n").unwrap();
    run_git(&checkout, &["add", "README.md"]);
    run_git(&checkout, &["commit", "-m", "initial"]);
    run_git(
        &checkout,
        &["remote", "add", "origin", "../link/../remotes/origin.git"],
    );
    run_git(&checkout, &["push", "-u", "origin", "main"]);

    let orphans_out = Command::new(sj_bin())
        .env("HOME", home)
        .args(["orphans", "--include-orphans", ws.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(
        orphans_out.status.code(),
        Some(0),
        "sj orphans failed: {}",
        String::from_utf8_lossy(&orphans_out.stderr)
    );
    let orphans_json: serde_json::Value = serde_json::from_slice(&orphans_out.stdout).unwrap();
    let safe = orphans_json["safe_to_prune"].as_array().unwrap();
    let blocked = orphans_json["blocked"].as_array().unwrap();
    assert_eq!(
        safe.len(),
        1,
        "expected 1 safe_to_prune, got: {orphans_json}"
    );
    assert!(
        blocked.is_empty(),
        "expected empty blocked, got: {orphans_json}"
    );
    assert!(
        safe[0]["path"].as_str().unwrap().ends_with("checkout"),
        "expected checkout in safe_to_prune, got: {orphans_json}"
    );

    let plan_out = Command::new(sj_bin())
        .env("HOME", home)
        .args(["plan", ws.to_str().unwrap(), "--include-orphans", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        plan_out.status.code(),
        Some(0),
        "sj plan failed: {}",
        String::from_utf8_lossy(&plan_out.stderr)
    );
    let plan_json: serde_json::Value = serde_json::from_slice(&plan_out.stdout).unwrap();
    let items = plan_json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "expected 1 plan item, got: {plan_json}");
    let plan_sha = plan_json["plan_sha256"].as_str().unwrap();
    let item_id = items[0]["id"].as_str().unwrap();

    let exec_out = Command::new(sj_bin())
        .env("HOME", home)
        .args([
            "plan",
            ws.to_str().unwrap(),
            "--include-orphans",
            "--execute",
            "--confirm",
            "--plan-sha256",
            plan_sha,
            "--item",
            item_id,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        exec_out.status.code(),
        Some(0),
        "sj plan --execute failed: {}",
        String::from_utf8_lossy(&exec_out.stderr)
    );
    let exec_json: serde_json::Value = serde_json::from_slice(&exec_out.stdout).unwrap();
    assert_eq!(exec_json["mutated"], true);
    assert!(
        !checkout.exists(),
        "checkout should be removed after execute"
    );
    let stage_leftovers: Vec<_> = fs::read_dir(&ws)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with(".sj-stage-"))
        .collect();
    assert!(
        stage_leftovers.is_empty(),
        "expected zero .sj-stage-* residue in ws, found: {stage_leftovers:?}"
    );

    // Confirm an unpushed checkout using the same ../link/../remotes/origin.git remote
    // is blocked and fails closed with rollback and zero residue.
    let unpushed_checkout = ws.join("unpushed_checkout");
    fs::create_dir_all(&unpushed_checkout).unwrap();
    run_git(&unpushed_checkout, &["init"]);
    run_git(&unpushed_checkout, &["checkout", "-b", "feature"]);
    fs::write(unpushed_checkout.join("README.md"), "hello\n").unwrap();
    run_git(&unpushed_checkout, &["add", "README.md"]);
    run_git(&unpushed_checkout, &["commit", "-m", "initial"]);
    run_git(
        &unpushed_checkout,
        &["remote", "add", "origin", "../link/../remotes/origin.git"],
    );
    run_git(&unpushed_checkout, &["push", "-u", "origin", "feature"]);

    let ctx = sj_core::protect::ProtectionContext::new(home.to_path_buf(), Vec::new());
    let pre_plan = sj_core::plan::build_remediation_plan(
        &ws,
        &ctx,
        &sj_core::plan::PlanOptions {
            include_trash: false,
            include_orphans: true,
            trash_path_override: None,
            orphan_max_depth: 5,
        },
    )
    .unwrap();
    assert_eq!(pre_plan.items.len(), 1);
    let pre_item_id = pre_plan.items[0].id.clone();

    fs::write(unpushed_checkout.join("unpushed.txt"), "local only\n").unwrap();
    run_git(&unpushed_checkout, &["add", "unpushed.txt"]);
    run_git(&unpushed_checkout, &["commit", "-m", "unpushed"]);

    let blocked_orphans = Command::new(sj_bin())
        .env("HOME", home)
        .args(["orphans", "--include-orphans", ws.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(blocked_orphans.status.code(), Some(0));
    let blocked_json: serde_json::Value = serde_json::from_slice(&blocked_orphans.stdout).unwrap();
    assert!(blocked_json["safe_to_prune"].as_array().unwrap().is_empty());
    let blocked_arr = blocked_json["blocked"].as_array().unwrap();
    assert_eq!(blocked_arr.len(), 1);
    assert!(blocked_arr[0]["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r == "remote_unverified_or_unpushed"));

    let blocked_plan = Command::new(sj_bin())
        .env("HOME", home)
        .args(["plan", ws.to_str().unwrap(), "--include-orphans", "--json"])
        .output()
        .unwrap();
    assert_eq!(blocked_plan.status.code(), Some(0));
    let blocked_plan_json: serde_json::Value =
        serde_json::from_slice(&blocked_plan.stdout).unwrap();
    assert!(blocked_plan_json["items"].as_array().unwrap().is_empty());

    let blocked_exec = Command::new(sj_bin())
        .env("HOME", home)
        .args([
            "plan",
            ws.to_str().unwrap(),
            "--include-orphans",
            "--execute",
            "--confirm",
            "--plan-sha256",
            &pre_plan.plan_sha256,
            "--item",
            &pre_item_id,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(blocked_exec.status.code(), Some(2));
    assert!(unpushed_checkout.exists());
    assert!(unpushed_checkout.join("unpushed.txt").exists());

    let rollback_err = sj_core::plan::execute_plan_item(
        &pre_plan,
        &sj_core::plan::ExecutionGate {
            execute: true,
            confirm: true,
            plan_sha256: pre_plan.plan_sha256.clone(),
            item_id: pre_item_id,
        },
        &ctx,
    );
    assert!(
        matches!(rollback_err, Err(sj_core::SjError::ExecutionGate(_))),
        "expected ExecutionGate error on unpushed checkout, got: {rollback_err:?}"
    );
    assert!(unpushed_checkout.exists());
    assert!(unpushed_checkout.join("unpushed.txt").exists());
    let rollback_leftovers: Vec<_> = fs::read_dir(&ws)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with(".sj-stage-"))
        .collect();
    assert!(
        rollback_leftovers.is_empty(),
        "expected zero .sj-stage-* residue after rollback, found: {rollback_leftovers:?}"
    );
}


/// A `git` shim first on PATH: records every invocation. Used to prove nothing spawns git when the
/// orphan scan is off.
#[cfg(unix)]
fn git_shim(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let bin = dir.join("shimbin");
    fs::create_dir_all(&bin).unwrap();
    let marker = dir.join("GIT_SPAWNED");
    let shim = bin.join("git");
    fs::write(&shim, format!("#!/bin/sh\necho \"$@\" >> \"{}\"\nexit 1\n", marker.display())).unwrap();
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
    (bin, marker)
}

#[cfg(unix)]
#[test]
fn orphan_scanning_is_off_by_default_and_never_spawns_git() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("home");
    let ws = root.join("ws");
    fs::create_dir_all(&home).unwrap();
    // a repo that WOULD be scanned if scanning were on
    fs::create_dir_all(ws.join("repo").join(".git")).unwrap();
    let (shim_bin, marker) = git_shim(root);
    let path = format!("{}:{}", shim_bin.display(), std::env::var("PATH").unwrap_or_default());

    let orphans = Command::new(sj_bin())
        .env("HOME", &home)
        .env("PATH", &path)
        .args(["orphans", ws.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(orphans.status.code(), Some(0), "{}", String::from_utf8_lossy(&orphans.stderr));
    let j: serde_json::Value = serde_json::from_slice(&orphans.stdout).unwrap();
    assert_eq!(j["schema"], "spacejanitor.orphans.v1");
    assert_eq!(j["scanned"], false, "must say not scanned, not 'no orphans': {j}");
    assert_eq!(j["not_scanned_reason"], "orphan_scan_disabled_by_default");

    for args in [
        vec!["plan", ws.to_str().unwrap(), "--json"],
        vec!["plan", ws.to_str().unwrap(), "--include-trash", "--json"],
    ] {
        let plan = Command::new(sj_bin())
            .env("HOME", &home)
            .env("PATH", &path)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(plan.status.code(), Some(0), "{:?}: {}", args, String::from_utf8_lossy(&plan.stderr));
        let pj: serde_json::Value = serde_json::from_slice(&plan.stdout).unwrap();
        assert!(
            pj["items"].as_array().unwrap().iter().all(|i| i["kind"] != "orphan_worktree"),
            "default plan must not contain orphan items: {pj}"
        );
    }
    assert!(!marker.exists(), "git was spawned although the orphan scan is off: {}", fs::read_to_string(&marker).unwrap_or_default());

    // opt-in: now git IS used and the user gets the warning
    let on = Command::new(sj_bin())
        .env("HOME", &home)
        .env("PATH", &path)
        .args(["orphans", ws.to_str().unwrap(), "--include-orphans", "--json"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&on.stderr).contains("experimental"), "opt-in must warn");
    assert!(marker.exists(), "opt-in scan should reach git");
}

fn run_protect(home: &str, args: &[&str]) -> std::process::Output {
    Command::new(sj_bin())
        .arg("protect")
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .output()
        .unwrap()
}

#[test]
fn cli_protect_reports_per_path_verdicts_from_the_rust_gate() {
    let out = run_protect(
        "/Users/alice",
        &[
            "--json",
            "--",
            "/Users/alice/.ssh/id_x",
            "/Users/alice/.cache/vite",
            "/Users/alice/proj/.env",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema"], "spacejanitor.protect.v1");
    let results = v["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0]["path"], "/Users/alice/.ssh/id_x");
    assert_eq!(results[0]["protected"], true);
    assert_eq!(results[1]["protected"], false);
    assert_eq!(results[2]["protected"], true);
    assert!(results[2]["reason"].as_str().unwrap().contains("env"));
}

#[test]
fn cli_protect_descendants_blocks_a_tree_holding_a_protected_entry() {
    let tmp = tempdir().unwrap();
    // the synthetic home contains the work dirs: on Windows the temp dir lives under C:\Users, which
    // is another account's home to the gate unless it is inside the home being judged
    let home = tmp.path().to_path_buf();
    let project = tmp.path().join("project");
    fs::create_dir_all(project.join("app")).unwrap();
    fs::write(project.join("app").join(".env.production"), "S=1").unwrap();
    let clean = tmp.path().join("clean");
    fs::create_dir_all(clean.join("src")).unwrap();
    fs::write(clean.join("src").join("main.rs"), "x").unwrap();

    let out = run_protect(
        home.to_str().unwrap(),
        &[
            "--json",
            "--descendants",
            "--",
            project.to_str().unwrap(),
            clean.to_str().unwrap(),
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let results = v["results"].as_array().unwrap();
    assert_eq!(results[0]["protected"], true);
    assert!(results[0]["reason"]
        .as_str()
        .unwrap()
        .starts_with("protected_descendant"));
    assert_eq!(results[1]["protected"], false);
}

#[test]
fn cli_protect_with_no_paths_is_a_usage_error() {
    let out = run_protect("/Users/alice", &["--json"]);
    assert_ne!(out.status.code(), Some(0));
}

#[cfg(not(windows))] // the Windows trash is the system Recycle Bin, not a directory under HOME
#[test]
fn cli_plan_excludes_keepass_vaults_and_key_material_in_trash() {
    // cross-family review blocker 1: *.kdbx was planned (and deletable) once the JS denylist was gone.
    // (Credential-NAMED files inside ~/.Trash, e.g. ~/.Trash/.netrc, were never covered by the JS
    // denylist either: its home rules are anchored at ~/.netrc itself. The home-anchored cases are pinned
    // by the shared protect vectors.)
    let tmp = tempdir().unwrap();
    let home = fs::canonicalize(tmp.path()).unwrap().join("home");
    let trash = if cfg!(target_os = "macos") {
        home.join(".Trash")
    } else {
        home.join(".local").join("share").join("Trash").join("files")
    };
    fs::create_dir_all(&trash).unwrap();
    for f in ["passwords.kdbx", "server.pem", "id_rsa_backup", "junk.bin"] {
        fs::write(trash.join(f), "x").unwrap();
    }
    let out = Command::new(sj_bin())
        .args(["plan", home.to_str().unwrap(), "--json"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("XDG_DATA_HOME")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let planned: Vec<String> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["path"].as_str().unwrap().rsplit('/').next().unwrap().to_string())
        .collect();
    assert_eq!(planned, vec!["junk.bin".to_string()], "only the harmless item may be planned: {v}");
    assert_eq!(v["protected_exclusions"].as_array().unwrap().len(), 3);
}

#[test]
fn cli_protect_honours_custom_exact_dynamic_and_glob_rules() {
    let out = run_protect(
        "/Users/alice",
        &[
            "--json",
            "--exact", "/data/keep",
            "--dynamic", "/work/active",
            "--glob", "*.secret-ish",
            "--",
            "/data/keep/sub",
            "/work/active/src",
            "/Users/alice/a.secret-ish",
            "/data/other",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let flags: Vec<bool> = v["results"].as_array().unwrap().iter().map(|r| r["protected"].as_bool().unwrap()).collect();
    assert_eq!(flags, vec![true, true, true, false]);
}

#[cfg(unix)]
#[test]
fn cli_selection_token_for_one_item_cannot_execute_another_selection() {
    let tmp = tempdir().unwrap();
    let home = fs::canonicalize(tmp.path()).unwrap().join("home");
    let trash = if cfg!(target_os = "macos") {
        home.join(".Trash")
    } else {
        home.join(".local").join("share").join("Trash").join("files")
    };
    fs::create_dir_all(&trash).unwrap();
    for (n, b) in [("a.bin", "aaaa"), ("b.bin", "bbbbbb")] {
        fs::write(trash.join(n), b).unwrap();
    }
    let a = trash.join("a.bin");
    let b = trash.join("b.bin");
    let sj = |args: &[&str]| {
        Command::new(sj_bin())
            .args(args)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env_remove("XDG_DATA_HOME")
            .output()
            .unwrap()
    };
    let h = home.to_str().unwrap();
    let plan_a = sj(&["plan", h, "--json", "--select", a.to_str().unwrap()]);
    assert_eq!(plan_a.status.code(), Some(0), "{}", String::from_utf8_lossy(&plan_a.stderr));
    let pa: serde_json::Value = serde_json::from_slice(&plan_a.stdout).unwrap();
    let token_a = pa["selection"]["selection_sha256"].as_str().unwrap().to_string();
    let plan_ab = sj(&["plan", h, "--json", "--select", a.to_str().unwrap(), "--select", b.to_str().unwrap()]);
    let pab: serde_json::Value = serde_json::from_slice(&plan_ab.stdout).unwrap();
    assert_ne!(pab["selection"]["selection_sha256"].as_str().unwrap(), token_a);
    assert_eq!(pa["plan_sha256"], pab["plan_sha256"], "the whole-plan digest is the same; only the selection digest differs");

    // the one-item token must not authorise A+B or B
    for sel in [vec![a.to_str().unwrap(), b.to_str().unwrap()], vec![b.to_str().unwrap()]] {
        let mut args = vec!["plan", h, "--execute", "--confirm", "--selection-sha256", token_a.as_str()];
        for s in &sel {
            args.push("--select");
            args.push(s);
        }
        let out = sj(&args);
        assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
        assert!(a.exists() && b.exists());
    }

    // the right selection executes only that item (reordered/duplicated flags are fine)
    let out = sj(&["plan", h, "--execute", "--confirm", "--selection-sha256", &token_a, "--select", a.to_str().unwrap(), "--select", a.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let done: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(done["executed_items"].as_array().unwrap().len(), 1);
    assert!(!a.exists());
    assert!(b.exists());
}

#[cfg(unix)]
#[test]
fn cli_protect_runs_every_shared_fs_vector_including_relative_custom_rules() {
    use std::os::unix::fs::symlink;
    let v: serde_json::Value = serde_json::from_str(include_str!("../../sj-core/tests/fixtures/protect_vectors.json")).unwrap();
    for case in v["fs_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let root = fs::canonicalize(tempdir().unwrap().keep()).unwrap();
        let abs = |rel: &str| -> std::path::PathBuf {
            if Path::new(rel).is_absolute() { Path::new(rel).to_path_buf() } else { root.join(rel) }
        };
        for step in case["setup"].as_array().unwrap() {
            if let Some(d) = step["dir"].as_str() {
                fs::create_dir_all(abs(d)).unwrap();
            } else if let Some(l) = step["link"].as_str() {
                fs::create_dir_all(abs(l).parent().unwrap()).unwrap();
                symlink(abs(step["target"].as_str().unwrap()), abs(l)).unwrap();
            }
        }
        let cwd = case.get("cwd").and_then(|c| c.as_str()).map(|c| abs(c)).unwrap_or_else(|| root.clone());
        fs::create_dir_all(&cwd).unwrap();
        let home = abs(case["home"].as_str().unwrap());
        let list = |k: &str| -> Vec<String> {
            case.get("options")
                .and_then(|o| o.get(k))
                .and_then(|x| x.as_array())
                .map(|a| a.iter().map(|y| y.as_str().unwrap().to_string()).collect())
                .unwrap_or_default()
        };
        let check = |p: &str| -> bool {
            let mut cmd = Command::new(sj_bin());
            cmd.current_dir(&cwd).env("HOME", &home).env("USERPROFILE", &home).args(["protect", "--json"]);
            for e in list("exact") { cmd.arg(format!("--exact={e}")); }
            for e in list("dynamic") { cmd.arg(format!("--dynamic={e}")); }
            for e in list("glob") { cmd.arg(format!("--glob={e}")); }
            cmd.arg("--").arg(abs(p));
            let out = cmd.output().unwrap();
            assert_eq!(out.status.code(), Some(0), "{name}: {}", String::from_utf8_lossy(&out.stderr));
            let j: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            j["results"][0]["protected"].as_bool().unwrap()
        };
        for p in case["protected"].as_array().unwrap() {
            assert!(check(p.as_str().unwrap()), "{name}: expected protected: {p}");
        }
        for p in case["unprotected"].as_array().unwrap() {
            assert!(!check(p.as_str().unwrap()), "{name}: expected unprotected: {p}");
        }
    }
}

#[cfg(unix)]
#[test]
fn cli_plan_excludes_trash_items_covered_by_symlink_dotdot_and_relative_custom_rules() {
    // cross-family review R3 blocker 1: both shapes were planned (and deletable) at 8f61e92
    use std::os::unix::fs::symlink;
    let tmp = tempdir().unwrap();
    let home = fs::canonicalize(tmp.path()).unwrap().join("home");
    let trash = if cfg!(target_os = "macos") {
        home.join(".Trash")
    } else {
        home.join(".local").join("share").join("Trash").join("files")
    };
    fs::create_dir_all(trash.join("other_dir")).unwrap();
    for keep in ["keep_via_sym_dotdot", "keep_via_rel_exact", "free.bin"] {
        if keep.ends_with(".bin") {
            fs::write(trash.join(keep), "x").unwrap();
        } else {
            fs::create_dir_all(trash.join(keep)).unwrap();
            fs::write(trash.join(keep).join("precious.txt"), "p").unwrap();
        }
    }
    symlink(trash.join("other_dir"), home.join("to_trash_other")).unwrap();
    let rel_trash = trash.strip_prefix(&home).unwrap().to_string_lossy().into_owned();
    let out = Command::new(sj_bin())
        .current_dir(&home)
        .args(["plan", home.to_str().unwrap(), "--json"])
        .arg("--exact=~/to_trash_other/../keep_via_sym_dotdot")
        .arg(format!("--exact=./{rel_trash}/keep_via_rel_exact"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("XDG_DATA_HOME")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let planned: Vec<String> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["path"].as_str().unwrap().rsplit('/').next().unwrap().to_string())
        .collect();
    assert!(!planned.contains(&"keep_via_sym_dotdot".to_string()), "{planned:?}");
    assert!(!planned.contains(&"keep_via_rel_exact".to_string()), "{planned:?}");
    assert!(planned.contains(&"free.bin".to_string()), "{planned:?}");
}

#[cfg(unix)]
#[test]
fn cli_plan_include_orphans_alone_replaces_trash_but_with_include_trash_keeps_it() {
    // cross-family review R3 blocker 2: callers must pass --include-trash next to --include-orphans
    let tmp = tempdir().unwrap();
    let home = fs::canonicalize(tmp.path()).unwrap().join("home");
    let trash = if cfg!(target_os = "macos") {
        home.join(".Trash")
    } else {
        home.join(".local").join("share").join("Trash").join("files")
    };
    fs::create_dir_all(&trash).unwrap();
    fs::write(trash.join("old_log.txt"), "x").unwrap();
    let planned = |extra: &[&str]| -> usize {
        let mut args = vec!["plan", home.to_str().unwrap(), "--json"];
        args.extend_from_slice(extra);
        let out = Command::new(sj_bin())
            .args(&args)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env_remove("XDG_DATA_HOME")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["items"].as_array().unwrap().len()
    };
    assert_eq!(planned(&[]), 1, "default: trash only");
    assert_eq!(planned(&["--include-trash"]), 1);
    assert_eq!(planned(&["--include-orphans"]), 0, "documented sj semantics: orphans INSTEAD of trash");
    assert_eq!(planned(&["--include-trash", "--include-orphans"]), 1, "trash plus orphans keeps the trash item");
#[test]
fn cli_memory_blockers_mcp_audit_and_reap_end_to_end() {
    let tmp = tempdir().unwrap();
    let cfg_dir = tmp.path().join("mcp-configs");
    fs::create_dir_all(&cfg_dir).unwrap();
    fs::write(
        cfg_dir.join("mcp.json"),
        r#"{"mcpServers":{"sample-mcp":{"command":"npx","args":["-y","sample-mcp"]}}}"#,
    )
    .unwrap();

    // memory --top 5 --json
    let mem = Command::new(sj_bin())
        .args(["memory", "--top", "5", "--json"])
        .output()
        .unwrap();
    assert_eq!(mem.status.code(), Some(0));
    let mem_json: serde_json::Value = serde_json::from_slice(&mem.stdout).unwrap();
    assert_eq!(mem_json["schema"], "spacejanitor.memory.v1");

    // blockers --json
    let blk = Command::new(sj_bin())
        .args(["blockers", "--json"])
        .output()
        .unwrap();
    assert_eq!(blk.status.code(), Some(0));
    let blk_json: serde_json::Value = serde_json::from_slice(&blk.stdout).unwrap();
    assert_eq!(blk_json["schema"], "spacejanitor.blockers.v1");

    // mcp-audit --config-dir <dir> --json
    let mcp = Command::new(sj_bin())
        .args([
            "mcp-audit",
            "--config-dir",
            cfg_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(mcp.status.code(), Some(0));
    let mcp_json: serde_json::Value = serde_json::from_slice(&mcp.stdout).unwrap();
    assert_eq!(mcp_json["schema"], "spacejanitor.mcp_audit.v1");
    assert_eq!(mcp_json["configured_servers"].as_array().unwrap().len(), 1);

    // reap --dry-run --json
    let reap_dry = Command::new(sj_bin())
        .args(["reap", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert_eq!(reap_dry.status.code(), Some(0));
    let reap_json: serde_json::Value = serde_json::from_slice(&reap_dry.stdout).unwrap();
    assert_eq!(reap_json["schema"], "spacejanitor.reap.v1");
    assert_eq!(reap_json["mode"], "dry-run");
    assert_eq!(reap_json["mutated"], false);

    // reap --execute without confirm/plan-sha256 must fail closed with exit code 2
    let reap_bad = Command::new(sj_bin())
        .args(["reap", "--execute", "--json"])
        .output()
        .unwrap();
    assert_eq!(reap_bad.status.code(), Some(2));
}

#[test]
fn cli_serve_stdio_json_rpc_round_trip_and_error_handling() {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new(sj_bin())
        .arg("serve-stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"doctor","params":{{}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":2,"method":"memory","params":{{"top":3}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":3,"method":"blockers","params":{{}}}}"#
        )
        .unwrap();
        writeln!(stdin, r#"{{not-valid-json"#).unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":"req-unknown","method":"no_such_method","params":{{}}}}"#
        )
        .unwrap();
    }

    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        5,
        "expected 5 JSON-RPC responses, got: {stdout}"
    );

    let r1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(r1["id"], 1);
    assert_eq!(r1["result"]["schema"], "spacejanitor.doctor.v1");

    let r2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(r2["id"], 2);
    assert_eq!(r2["result"]["schema"], "spacejanitor.memory.v1");

    let r3: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(r3["id"], 3);
    assert_eq!(r3["result"]["schema"], "spacejanitor.blockers.v1");

    let r4: serde_json::Value = serde_json::from_str(lines[3]).unwrap();
    assert_eq!(r4["id"], serde_json::Value::Null);
    assert_eq!(r4["error"]["code"], -32700);

    let r5: serde_json::Value = serde_json::from_str(lines[4]).unwrap();
    assert_eq!(r5["id"], "req-unknown");
    assert_eq!(r5["error"]["code"], -32601);
}

#[test]
fn cli_serve_stdio_omits_notification_responses_and_handles_invalid_utf8() {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new(sj_bin())
        .arg("serve-stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        // JSON-RPC 2.0 notification (no id) must produce no response
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","method":"doctor","params":{{}}}}"#
        )
        .unwrap();
        // Invalid UTF-8 line must return -32700 instead of crashing
        stdin.write_all(b"\xff\xfe\xfd\n").unwrap();
        // Subsequent valid request must still succeed
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":9,"method":"doctor","params":{{}}}}"#
        )
        .unwrap();
    }

    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "expected 2 responses, got: {stdout}");

    let r1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(r1["id"], serde_json::Value::Null);
    assert_eq!(r1["error"]["code"], -32700);

    let r2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(r2["id"], 9);
    assert_eq!(r2["result"]["schema"], "spacejanitor.doctor.v1");
}

#[cfg(unix)]
#[test]
fn cli_llm_audit_is_read_only_secret_safe_and_has_no_execute_path() {
    let tmp = tempdir().unwrap();
    let h = tmp.path();
    fs::create_dir_all(h.join(".codex/skills")).unwrap();
    fs::create_dir_all(h.join(".agents/skills/stale-skill")).unwrap();
    fs::write(h.join(".agents/skills/stale-skill/SKILL.md"), "x").unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(90 * 86_400);
    for p in [
        h.join(".agents/skills/stale-skill/SKILL.md"),
        h.join(".agents/skills/stale-skill"),
    ] {
        let _ = fs::File::open(&p).unwrap().set_modified(old);
    }
    std::os::unix::fs::symlink("/nonexistent-sj-cli-fixture", h.join(".codex/skills/dead"))
        .unwrap();
    fs::write(
        h.join(".codex/config.toml"),
        "[plugins.\"extra@mkt\"]\nenabled = true\n[mcp_servers.sjfixtureunused]\ncommand = \"npx\"\nargs = [\"sjfixture-unused-mcp-x\", \"--token\", \"CLI_TOK_SECRET\"]\n",
    )
    .unwrap();
    fs::write(
        h.join(".claude.json"),
        "{\"mcpServers\":{\"CLI_CLAUDE_MARKER\":{\"command\":\"x\"}}}",
    )
    .unwrap();

    let out = Command::new(sj_bin())
        .args(["llm-audit", "--home"])
        .arg(h)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["schema"], "spacejanitor.llm_audit.v1");
    assert_eq!(v["mode"], "dry-run");
    assert_eq!(v["mutated"], false);
    assert_eq!(v["stale_skills"][0]["name"], "stale-skill");
    assert_eq!(v["broken_skill_symlinks"][0]["name"], "dead");
    assert_eq!(
        v["unused_mcp_servers"][0]["server_name"], "sjfixtureunused",
        "{text}"
    );
    assert!(v["plugins"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["plugin_id"] == "extra@mkt" && p["disable_candidate"] == true));
    assert!(!text.contains("CLI_TOK_SECRET") && !text.contains("CLI_CLAUDE_MARKER"));
    // nothing moved
    assert!(h.join(".agents/skills/stale-skill").is_dir());
    assert!(fs::symlink_metadata(h.join(".codex/skills/dead")).is_ok());

    // no execute path exists
    let ex = Command::new(sj_bin())
        .args(["llm-audit", "--execute"])
        .output()
        .unwrap();
    assert_ne!(ex.status.code(), Some(0));
}

// ---- R3 blocker regressions (item 70): every probe must stay out of CLI output ----

fn run_sj(args: &[&str], home: Option<&Path>) -> String {
    let mut cmd = Command::new(sj_bin());
    cmd.args(args);
    if let Some(h) = home {
        cmd.env("HOME", h);
    }
    let out = cmd.output().unwrap();
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn r3_b1_redaction_is_allowlist_based_and_leaks_no_probe() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("mcp.json"),
        r#"{"mcpServers":{"probe":{
 "command":"bash -lc 'npx some-mcp --token PROBE_SHELL_CMD'",
 "args":["OPTS=-pPROBE_OPTS_P","JAVA_OPTS=-Dapi.key=PROBE_JAVA_OPTS",
 "-c","sh -c 'npx mcp --token PROBE_SHELL_INNER'",
 "--token:PROBE_COLON_B64=","--header=Authorization:Bearer","PROBE_HDR_EQ_SPLIT"]}}}"#,
    )
    .unwrap();
    let out = run_sj(
        &[
            "mcp-audit",
            "--config-dir",
            tmp.path().to_str().unwrap(),
            "--json",
        ],
        None,
    );
    assert!(out.contains("\"probe\""), "{out}");
    assert!(!out.contains("PROBE_"), "leak: {out}");
}

#[test]
fn r3_b2_split_bearer_and_authorization_args_leak_nothing() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("mcp.json"),
        r#"{"mcpServers":{"split":{"command":"npx","args":[
 "--header","Authorization:","Bearer","PROBE_HDR_SPLIT3",
 "--auth","Bearer","PROBE_AUTH_BEARER3","Bearer","PROBE_BEARER_PAIR"]}}}"#,
    )
    .unwrap();
    let out = run_sj(
        &[
            "mcp-audit",
            "--config-dir",
            tmp.path().to_str().unwrap(),
            "--json",
        ],
        None,
    );
    assert!(out.contains("\"split\""), "{out}");
    assert!(!out.contains("PROBE_"), "leak: {out}");
}

#[cfg(unix)]
#[test]
fn r3_b3_symlinked_home_cannot_bypass_protection() {
    use std::os::unix::fs::symlink;
    let tmp = tempdir().unwrap();
    let real = tmp.path().join("real");
    fs::create_dir_all(real.join(".cursor")).unwrap();
    fs::create_dir_all(real.join("Library/Application Support/Claude/Local Storage")).unwrap();
    fs::write(
        real.join(".claude.json"),
        r#"{"mcpServers":{"srv-inside-claude-json":{"command":"npx","args":["srv-x"]}}}"#,
    )
    .unwrap();
    symlink(real.join(".claude.json"), real.join(".mcp.json")).unwrap();
    symlink(
        real.join("Library/Application Support/Claude"),
        real.join(".cursor/skills"),
    )
    .unwrap();
    // non-canonical home: reach `real` through a symlink
    let link_home = tmp.path().join("homelink");
    symlink(&real, &link_home).unwrap();
    let out = run_sj(&["mcp-audit", "--json"], Some(&link_home));
    assert!(!out.contains("srv-inside-claude-json"), "{out}");
    let out = run_sj(
        &["llm-audit", "--home", link_home.to_str().unwrap(), "--json"],
        None,
    );
    assert!(!out.contains("Local Storage"), "{out}");
}

#[cfg(unix)]
#[test]
fn r3_b4_llm_audit_never_descends_through_symlinked_roots() {
    use std::os::unix::fs::symlink;
    let tmp = tempdir().unwrap();
    let h = tmp.path().canonicalize().unwrap();
    fs::create_dir_all(h.join(".ssh/SecretSubDir")).unwrap();
    fs::create_dir_all(h.join(".gemini")).unwrap();
    fs::create_dir_all(h.join(".cursor")).unwrap();
    symlink(h.join(".ssh"), h.join(".gemini/extensions")).unwrap();
    symlink(h.join(".ssh"), h.join(".cursor/skills")).unwrap();
    let out = run_sj(
        &["llm-audit", "--home", h.to_str().unwrap(), "--json"],
        None,
    );
    assert!(!out.contains("SecretSubDir"), "{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(v["skills_by_client"].get("cursor").is_none(), "{out}");
    let roots = v["symlinked_roots"].as_array().unwrap();
    assert!(
        roots
            .iter()
            .any(|r| r["client"] == "cursor" && r["target_protected"] == true),
        "{out}"
    );
}

#[test]
fn r3_b5_codex_toml_subtables_are_not_phantom_servers() {
    let tmp = tempdir().unwrap();
    let h = tmp.path();
    fs::create_dir_all(h.join(".codex")).unwrap();
    fs::write(
        h.join(".codex/config.toml"),
        "[mcp_servers.multillm]\nurl = \"https://example.com/mcp\"\n[mcp_servers.multillm.http_headers]\nAuthorization = \"Bearer SECRET_HDR\"\n",
    )
    .unwrap();
    let out = run_sj(
        &["llm-audit", "--home", h.to_str().unwrap(), "--json"],
        None,
    );
    assert!(!out.contains("multillm.http_headers"), "{out}");
    assert!(!out.contains("SECRET_HDR"), "{out}");
}
