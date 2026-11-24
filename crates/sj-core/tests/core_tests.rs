use sj_core::{
    orphans::{inspect_orphans, OrphanOptions},
    plan::{build_remediation_plan, execute_plan_item, ExecutionGate, PlanOptions},
    protect::{check_path_protection, ProtectionContext},
    scan::{scan_directory, ScanOptions, ScanStatus, ScanThresholds},
    trash::discover_trash_at,
    SCHEMA_ORPHANS_V1, SCHEMA_PROPOSAL_V1, SCHEMA_STORAGE_V1, SCHEMA_TRASH_V1,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

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
fn protected_denylist_covers_secrets_vm_images_and_system_roots() {
    let home = Path::new("/home/developer");
    let ctx = ProtectionContext::new(home.to_path_buf(), vec![]);

    // Secret directories
    for rel in [".ssh", ".gnupg", ".aws", ".kube", ".claude", ".config/gh"] {
        let p = home.join(rel).join("config");
        assert!(
            check_path_protection(&p, &ctx).protected,
            "expected {} to be protected",
            p.display()
        );
    }

    // Secret files & keys
    for file in [
        "/home/developer/project/.env",
        "/home/developer/project/.env.production",
        "/home/developer/certs/server.pem",
        "/home/developer/certs/private.key",
        "/home/developer/keys/id_rsa",
        "/home/developer/keys/id_ed25519",
        "/home/developer/notes.private.md",
    ] {
        assert!(
            check_path_protection(Path::new(file), &ctx).protected,
            "expected {file} to be protected"
        );
    }

    // VM disk images
    for vm in [
        "/home/developer/vms/disk.vmdk",
        "/home/developer/vms/disk.qcow2",
        "/home/developer/vms/disk.vhdx",
        "/home/developer/vms/disk.vdi",
        "/home/developer/vms/disk.raw",
        "/home/developer/vms/disk.img",
    ] {
        assert!(
            check_path_protection(Path::new(vm), &ctx).protected,
            "expected {vm} to be protected"
        );
    }

    // OS system roots
    for sys in [
        "/",
        "/System/Library",
        "/usr/local/bin",
        "/bin/sh",
        "/sbin/init",
        "/etc/hosts",
        "/Library/Preferences",
        "C:\\Windows\\System32",
    ] {
        assert!(
            check_path_protection(Path::new(sys), &ctx).protected,
            "expected {sys} to be protected"
        );
    }

    // Safe cache dir
    assert!(!check_path_protection(Path::new("/home/developer/.cache/npm"), &ctx).protected);
}

#[cfg(unix)]
#[test]
fn symlink_escape_and_dangling_symlink_fail_closed() {
    use std::os::unix::fs::symlink;

    let tmp = tempdir().unwrap();
    let home = tmp.path().join("home");
    let ssh_dir = home.join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();
    fs::write(ssh_dir.join("id_ed25519"), "dummy").unwrap();

    let work = tmp.path().join("work");
    fs::create_dir_all(&work).unwrap();

    // Symlink pointing to protected .ssh directory
    let link_to_ssh = work.join("innocent_dir");
    symlink(&ssh_dir, &link_to_ssh).unwrap();

    // Dangling symlink
    let dangling = work.join("dangling_link");
    symlink(tmp.path().join("does_not_exist"), &dangling).unwrap();

    let ctx = ProtectionContext::new(home, vec![]);
    let ssh_verdict = check_path_protection(&link_to_ssh.join("id_ed25519"), &ctx);
    assert!(ssh_verdict.protected, "symlink to .ssh must fail closed");

    let dangling_verdict = check_path_protection(&dangling, &ctx);
    assert!(
        dangling_verdict.protected,
        "dangling symlink must fail closed"
    );

    let child_of_dangling = check_path_protection(&dangling.join("nested"), &ctx);
    assert!(
        child_of_dangling.protected,
        "child of dangling symlink must fail closed"
    );
}

#[test]
fn scanner_bounds_determinism_and_thresholds() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    let big_dir = root.join("alpha_big");
    let small_dir = root.join("beta_small");
    let tied_a = root.join("a_tie");
    let tied_b = root.join("b_tie");
    let ssh_dir = root.join(".ssh");

    for d in [&big_dir, &small_dir, &tied_a, &tied_b, &ssh_dir] {
        fs::create_dir_all(d).unwrap();
    }

    fs::write(big_dir.join("blob.bin"), vec![0u8; 2000]).unwrap();
    fs::write(small_dir.join("tiny.bin"), vec![0u8; 100]).unwrap();
    fs::write(tied_a.join("tie.bin"), vec![0u8; 500]).unwrap();
    fs::write(tied_b.join("tie.bin"), vec![0u8; 500]).unwrap();
    fs::write(ssh_dir.join("id_ed25519"), vec![0u8; 9999]).unwrap();

    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    let opts = ScanOptions {
        max_depth: 2,
        top_n: 3,
        same_filesystem: false,
        thresholds: ScanThresholds {
            check_bytes: 1_000,
            alert_bytes: 2_500,
            floor_bytes: 5_000,
            stop_bytes: 10_000,
        },
    };

    let report = scan_directory(root, &ctx, &opts).unwrap();
    assert_eq!(report.schema, SCHEMA_STORAGE_V1);
    assert_eq!(report.entries.len(), 3);
    // Protected .ssh must be skipped and recorded
    assert!(
        report.skipped_protected.iter().any(|p| p.ends_with(".ssh")),
        "expected .ssh in skipped_protected: {:?}",
        report.skipped_protected
    );
    // Total bytes = 2000 + 100 + 500 + 500 = 3100 (excludes .ssh 9999)
    assert_eq!(report.total_bytes, 3100);
    assert_eq!(report.status, ScanStatus::Alert);

    // Deterministic sort: size desc, path asc
    assert_eq!(
        PathBuf::from(&report.entries[0].path)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap(),
        "alpha_big"
    );
    assert_eq!(
        PathBuf::from(&report.entries[1].path)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap(),
        "a_tie"
    );
    assert_eq!(
        PathBuf::from(&report.entries[2].path)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap(),
        "b_tie"
    );
}

#[test]
fn trash_discovery_is_read_only_and_flags_protected() {
    let tmp = tempdir().unwrap();
    let trash_dir = tmp.path().join("Trash");
    fs::create_dir_all(&trash_dir).unwrap();
    fs::write(trash_dir.join("old_archive.tar"), vec![1u8; 1024]).unwrap();
    fs::write(trash_dir.join("leaked.pem"), vec![2u8; 256]).unwrap();

    let ctx = ProtectionContext::new(tmp.path().to_path_buf(), vec![]);
    let report = discover_trash_at(&trash_dir, &ctx).unwrap();
    assert_eq!(report.schema, SCHEMA_TRASH_V1);
    assert!(report.exists);
    assert_eq!(report.item_count, 2);
    assert_eq!(report.total_bytes, 1280);
    assert_eq!(report.reclaimable_bytes, 1024);
    assert_eq!(report.protected_items.len(), 1);
    // Read-only: files still exist
    assert!(trash_dir.join("old_archive.tar").exists());
    assert!(trash_dir.join("leaked.pem").exists());
}

#[test]
fn orphan_git_validator_distinguishes_clean_pushed_from_unsafe_states() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let remotes_dir = root.join("remotes");
    let workspace_dir = root.join("workspaces");
    fs::create_dir_all(&remotes_dir).unwrap();
    fs::create_dir_all(&workspace_dir).unwrap();

    // Create a bare remote
    let bare_remote = remotes_dir.join("origin.git");
    fs::create_dir_all(&bare_remote).unwrap();
    run_git(&bare_remote, &["init", "--bare"]);

    // 1. Clean & pushed repo
    let clean_repo = workspace_dir.join("clean_pushed");
    run_git(
        &workspace_dir,
        &["clone", bare_remote.to_str().unwrap(), "clean_pushed"],
    );
    fs::write(clean_repo.join("README.md"), "hello\n").unwrap();
    run_git(&clean_repo, &["add", "README.md"]);
    run_git(&clean_repo, &["commit", "-m", "init"]);
    run_git(&clean_repo, &["push", "-u", "origin", "HEAD"]);

    // 2. Dirty untracked repo
    let dirty_repo = workspace_dir.join("dirty_untracked");
    run_git(
        &workspace_dir,
        &["clone", bare_remote.to_str().unwrap(), "dirty_untracked"],
    );
    fs::write(dirty_repo.join("scratch.txt"), "uncommitted\n").unwrap();

    // 3. Unpushed commit repo
    let unpushed_repo = workspace_dir.join("unpushed_commit");
    run_git(
        &workspace_dir,
        &["clone", bare_remote.to_str().unwrap(), "unpushed_commit"],
    );
    fs::write(unpushed_repo.join("local.txt"), "local only\n").unwrap();
    run_git(&unpushed_repo, &["add", "local.txt"]);
    run_git(&unpushed_repo, &["commit", "-m", "local"]);

    // 4. Stashed repo
    let stashed_repo = workspace_dir.join("stashed_repo");
    run_git(
        &workspace_dir,
        &["clone", bare_remote.to_str().unwrap(), "stashed_repo"],
    );
    fs::write(stashed_repo.join("README.md"), "modified\n").unwrap();
    run_git(&stashed_repo, &["stash", "push", "--include-untracked"]);

    // 5. Detached HEAD repo
    let detached_repo = workspace_dir.join("detached_repo");
    run_git(
        &workspace_dir,
        &["clone", bare_remote.to_str().unwrap(), "detached_repo"],
    );
    run_git(&detached_repo, &["checkout", "--detach", "HEAD"]);

    // 6. No remote repo
    let no_remote_repo = workspace_dir.join("no_remote");
    fs::create_dir_all(&no_remote_repo).unwrap();
    run_git(&no_remote_repo, &["init"]);
    fs::write(no_remote_repo.join("a.txt"), "a\n").unwrap();
    run_git(&no_remote_repo, &["add", "a.txt"]);
    run_git(&no_remote_repo, &["commit", "-m", "init"]);

    // 7. Nested dirty repo inside an otherwise clean outer repo
    let nested_outer = workspace_dir.join("nested_outer");
    run_git(
        &workspace_dir,
        &["clone", bare_remote.to_str().unwrap(), "nested_outer"],
    );
    let nested_inner = nested_outer.join("sub_repo");
    fs::create_dir_all(&nested_inner).unwrap();
    run_git(&nested_inner, &["init"]);
    fs::write(nested_inner.join("wip.txt"), "wip\n").unwrap();

    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    let report = inspect_orphans(&workspace_dir, &ctx, &OrphanOptions { max_depth: 5 }).unwrap();
    assert_eq!(report.schema, SCHEMA_ORPHANS_V1);

    let safe_names: Vec<String> = report
        .safe_to_prune
        .iter()
        .map(|c| {
            PathBuf::from(&c.path)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(safe_names, vec!["clean_pushed"]);

    assert!(report
        .blocked
        .iter()
        .any(|b| b.path.ends_with("dirty_untracked")));
    assert!(report
        .blocked
        .iter()
        .any(|b| b.path.ends_with("unpushed_commit")));
    assert!(report
        .blocked
        .iter()
        .any(|b| b.path.ends_with("stashed_repo")));
    assert!(report
        .blocked
        .iter()
        .any(|b| b.path.ends_with("detached_repo")));
    assert!(report.blocked.iter().any(|b| b.path.ends_with("no_remote")));
    assert!(report
        .blocked
        .iter()
        .any(|b| b.path.ends_with("nested_outer")));
}

#[test]
fn remediation_plan_is_deterministic_dry_run_and_fail_closed() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let trash_dir = root.join("Trash");
    fs::create_dir_all(&trash_dir).unwrap();
    let stale_file = trash_dir.join("stale_build.zip");
    fs::write(&stale_file, vec![7u8; 512]).unwrap();
    let protected_file = trash_dir.join("secret.env");
    fs::write(&protected_file, "SECRET=dummy").unwrap();

    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    let opts = PlanOptions {
        include_trash: true,
        include_orphans: false,
        trash_path_override: Some(trash_dir.clone()),
        orphan_max_depth: 5,
    };

    let plan1 = build_remediation_plan(root, &ctx, &opts).unwrap();
    let plan2 = build_remediation_plan(root, &ctx, &opts).unwrap();

    assert_eq!(plan1.schema, SCHEMA_PROPOSAL_V1);
    assert_eq!(plan1.mode, "dry-run");
    assert!(!plan1.mutated);
    assert_eq!(plan1.plan_sha256, plan2.plan_sha256);
    assert_eq!(plan1.items.len(), 1);
    assert_eq!(plan1.items[0].id, plan2.items[0].id);
    assert_eq!(plan1.protected_exclusions.len(), 1);
    assert!(stale_file.exists());
    assert!(protected_file.exists());

    // Fail-closed gate: wrong sha256 must fail without deleting
    let bad_gate = ExecutionGate {
        execute: true,
        confirm: true,
        plan_sha256: "0000".to_string(),
        item_id: plan1.items[0].id.clone(),
    };
    assert!(execute_plan_item(&plan1, &bad_gate, &ctx).is_err());
    assert!(stale_file.exists());

    // Valid gate: deletes only the targeted item
    let good_gate = ExecutionGate {
        execute: true,
        confirm: true,
        plan_sha256: plan1.plan_sha256.clone(),
        item_id: plan1.items[0].id.clone(),
    };
    execute_plan_item(&plan1, &good_gate, &ctx).unwrap();
    assert!(!stale_file.exists());
    assert!(protected_file.exists());
}
