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
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    assert_eq!(doctor.status.code(), Some(0));
    let doc_json: serde_json::Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(doc_json["schema"], "spacejanitor.doctor.v1");
    assert_eq!(doc_json["ready"], true);

    // scan --json
    let scan = Command::new(sj_bin())
        .args(["scan", root.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(scan.status.code(), Some(0));
    let scan_json: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    assert_eq!(scan_json["schema"], "spacejanitor.storage.v1");

    // trash --path --json
    let trash = Command::new(sj_bin())
        .args(["trash", "--path", trash_dir.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(trash.status.code(), Some(0));
    let trash_json: serde_json::Value = serde_json::from_slice(&trash.stdout).unwrap();
    assert_eq!(trash_json["schema"], "spacejanitor.trash.v1");
    assert_eq!(trash_json["item_count"], 1);

    // orphans --json
    let orphans = Command::new(sj_bin())
        .args(["orphans", "--include-orphans", root.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(orphans.status.code(), Some(0));
    let orphans_json: serde_json::Value = serde_json::from_slice(&orphans.stdout).unwrap();
    assert_eq!(orphans_json["schema"], "spacejanitor.orphans.v1");

    // plan --json (dry-run by default)
    let plan = Command::new(sj_bin())
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
    let home = tmp.path().join("home");
    let project = tmp.path().join("project");
    fs::create_dir_all(&home).unwrap();
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
