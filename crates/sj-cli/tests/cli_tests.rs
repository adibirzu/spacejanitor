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
        .args(["orphans", root.to_str().unwrap(), "--json"])
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
        (&ws, vec!["orphans", "--json"]),
        (&ws, vec!["orphans", "checkout", "--json"]),
        (&ws, vec!["orphans", checkout_abs, "--json"]),
        (&checkout, vec!["orphans", "--json"]),
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
            .args(["orphans", input, "--json"])
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
