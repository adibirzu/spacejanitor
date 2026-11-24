use sj_core::{
    orphans::{inspect_orphans, OrphanOptions},
    plan::{
        build_remediation_plan, execute_plan_item, execute_plan_item_with_roots, ExecutionGate,
        PlanOptions,
    },
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
    execute_plan_item_with_roots(&plan1, &good_gate, &ctx, &[trash_dir]).unwrap();
    assert!(!stale_file.exists());
    assert!(protected_file.exists());
}

#[test]
fn protect_normalizes_traversal_case_relative_and_system_volumes_data() {
    let home = Path::new("/home/developer");
    let ctx = ProtectionContext::new(home.to_path_buf(), vec![]);

    // 1. Lexical . / .. normalization
    assert!(
        check_path_protection(Path::new("/tmp/safe/../.ssh/id_rsa"), &ctx).protected,
        "traversal to .ssh/id_rsa must be protected"
    );
    assert!(
        check_path_protection(Path::new("/home/developer/foo/../.env"), &ctx).protected,
        "traversal to .env must be protected"
    );
    assert!(
        check_path_protection(Path::new("/tmp/foo/../../etc/passwd"), &ctx).protected,
        "traversal to /etc/passwd must be protected"
    );

    // 2. Case-insensitive protected segments
    for p in [
        "/home/developer/.SSH/id_rsa",
        "/home/developer/.CLAUDE/settings.json",
        "/home/developer/.CONFIG/GH/hosts.yml",
        "/tmp/work/.AWS/credentials",
    ] {
        assert!(
            check_path_protection(Path::new(p), &ctx).protected,
            "case-insensitive path {p} must be protected"
        );
    }

    // 3. Relative path resolution against current_dir
    let tmp = tempdir().unwrap();
    let work = tmp.path().join("rel_test");
    fs::create_dir_all(&work).unwrap();
    let prev_cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(&work).unwrap();
    let rel_verdict = check_path_protection(Path::new("sub/../.env"), &ctx);
    std::env::set_current_dir(&prev_cwd).unwrap();
    assert!(
        rel_verdict.protected,
        "relative traversal to .env must be protected"
    );

    // 4. /System/Volumes/Data prefix bypass
    for sys_data in [
        "/System/Volumes/Data/Library/Preferences",
        "/System/Volumes/Data/private/etc/hosts",
        "/System/Volumes/Data/private/var/db/something",
        "/System/Volumes/Data/System/Library",
    ] {
        assert!(
            check_path_protection(Path::new(sys_data), &ctx).protected,
            "{sys_data} must stay protected"
        );
    }
    assert!(
        !check_path_protection(
            Path::new("/System/Volumes/Data/Users/developer/.cache/npm"),
            &ctx
        )
        .protected,
        "user cache under /System/Volumes/Data should be allowed"
    );
}

#[test]
fn trash_and_plan_reject_directories_with_protected_descendants_or_symlinks() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let trash_dir = sj_core::trash::default_trash_paths(root)
        .into_iter()
        .next()
        .unwrap();
    fs::create_dir_all(&trash_dir).unwrap();

    // Folder in Trash containing a .env file
    let dir_with_env = trash_dir.join("old-backup");
    fs::create_dir_all(dir_with_env.join("nested")).unwrap();
    fs::write(dir_with_env.join("nested").join(".env"), "SECRET=1").unwrap();

    // Folder in Trash containing a symlink
    #[cfg(unix)]
    let dir_with_sym = {
        let d = trash_dir.join("sym-backup");
        fs::create_dir_all(&d).unwrap();
        std::os::unix::fs::symlink(root, d.join("escape")).unwrap();
        d
    };

    // Clean folder in Trash
    let clean_dir = trash_dir.join("clean-cache");
    fs::create_dir_all(&clean_dir).unwrap();
    fs::write(clean_dir.join("blob.bin"), vec![1u8; 64]).unwrap();

    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    let report = discover_trash_at(&trash_dir, &ctx).unwrap();

    assert!(
        report
            .protected_items
            .iter()
            .any(|i| i.path.ends_with("old-backup")),
        "dir containing .env must be marked protected: {:?}",
        report
    );
    assert!(
        !report.items.iter().any(|i| i.path.ends_with("old-backup")),
        "dir containing .env must not be reclaimable"
    );

    #[cfg(unix)]
    {
        assert!(
            report
                .protected_items
                .iter()
                .any(|i| i.path.ends_with("sym-backup")),
            "dir containing symlink must be marked protected"
        );
        let _ = dir_with_sym;
    }

    assert!(
        report.items.iter().any(|i| i.path.ends_with("clean-cache")),
        "clean dir should be reclaimable"
    );
}

#[test]
fn execute_plan_item_rejects_arbitrary_trash_path_outside_os_defaults() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let arbitrary_dir = root.join("not_os_trash");
    fs::create_dir_all(&arbitrary_dir).unwrap();
    let target = arbitrary_dir.join("important.tar");
    fs::write(&target, vec![9u8; 128]).unwrap();

    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    let opts = PlanOptions {
        include_trash: true,
        include_orphans: false,
        trash_path_override: Some(arbitrary_dir.clone()),
        orphan_max_depth: 5,
    };
    let plan = build_remediation_plan(root, &ctx, &opts).unwrap();
    assert_eq!(plan.items.len(), 1);

    let gate = ExecutionGate {
        execute: true,
        confirm: true,
        plan_sha256: plan.plan_sha256.clone(),
        item_id: plan.items[0].id.clone(),
    };
    let res = execute_plan_item(&plan, &gate, &ctx);
    assert!(
        res.is_err(),
        "execute_plan_item must refuse trash_item outside default OS trash roots"
    );
    assert!(target.exists(), "file outside OS trash must not be deleted");
}

#[test]
fn execute_plan_item_revalidates_orphan_worktree_before_removal() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let remotes_dir = root.join("remotes");
    let workspace_dir = root.join("workspaces");
    fs::create_dir_all(&remotes_dir).unwrap();
    fs::create_dir_all(&workspace_dir).unwrap();

    let bare_remote = remotes_dir.join("origin.git");
    fs::create_dir_all(&bare_remote).unwrap();
    run_git(&bare_remote, &["init", "--bare"]);

    let clean_repo = workspace_dir.join("clean_wt");
    run_git(
        &workspace_dir,
        &["clone", bare_remote.to_str().unwrap(), "clean_wt"],
    );
    fs::write(clean_repo.join("README.md"), "hello\n").unwrap();
    run_git(&clean_repo, &["add", "README.md"]);
    run_git(&clean_repo, &["commit", "-m", "init"]);
    run_git(&clean_repo, &["push", "-u", "origin", "HEAD"]);

    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    let opts = PlanOptions {
        include_trash: false,
        include_orphans: true,
        trash_path_override: None,
        orphan_max_depth: 5,
    };
    let plan = build_remediation_plan(&workspace_dir, &ctx, &opts).unwrap();
    assert_eq!(plan.items.len(), 1);

    // Mutate repo after planning (dirty file) -> execute must fail closed!
    fs::write(clean_repo.join("dirty.txt"), "unsaved\n").unwrap();
    let gate = ExecutionGate {
        execute: true,
        confirm: true,
        plan_sha256: plan.plan_sha256.clone(),
        item_id: plan.items[0].id.clone(),
    };
    let res = execute_plan_item(&plan, &gate, &ctx);
    assert!(
        res.is_err(),
        "execute_plan_item must re-validate orphan and refuse if dirtied after plan"
    );
    assert!(clean_repo.exists());
}

#[test]
fn orphans_hardening_commondir_dangling_dotgit_protected_prune_and_remote_verify() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("home");
    let remotes_dir = root.join("remotes");
    let workspace_dir = home.join("workspaces");
    let ssh_dir = home.join(".ssh");
    fs::create_dir_all(&remotes_dir).unwrap();
    fs::create_dir_all(&workspace_dir).unwrap();
    fs::create_dir_all(&ssh_dir).unwrap();

    // Put a fake .git repo inside .ssh to ensure orphan walker prunes .ssh
    let ssh_repo = ssh_dir.join("secret_repo");
    fs::create_dir_all(&ssh_repo).unwrap();
    run_git(&ssh_repo, &["init"]);

    // 1. Directory-form .git with commondir pointing to protected .ssh
    let evil_commondir_repo = workspace_dir.join("evil_commondir");
    fs::create_dir_all(&evil_commondir_repo).unwrap();
    run_git(&evil_commondir_repo, &["init"]);
    fs::write(
        evil_commondir_repo.join(".git").join("commondir"),
        ssh_dir.to_str().unwrap(),
    )
    .unwrap();

    // 2. Dangling .git symlink must be caught in blocked
    #[cfg(unix)]
    {
        let dangling_repo = workspace_dir.join("dangling_dotgit");
        fs::create_dir_all(&dangling_repo).unwrap();
        std::os::unix::fs::symlink(root.join("nonexistent_gitdir"), dangling_repo.join(".git"))
            .unwrap();
    }

    // 3. Deleted remote must fail closed as remote_unverified_or_unpushed
    let bare_remote = remotes_dir.join("deleted_origin.git");
    fs::create_dir_all(&bare_remote).unwrap();
    run_git(&bare_remote, &["init", "--bare"]);
    let deleted_remote_repo = workspace_dir.join("deleted_remote_repo");
    run_git(
        &workspace_dir,
        &[
            "clone",
            bare_remote.to_str().unwrap(),
            "deleted_remote_repo",
        ],
    );
    fs::write(deleted_remote_repo.join("README.md"), "hello\n").unwrap();
    run_git(&deleted_remote_repo, &["add", "README.md"]);
    run_git(&deleted_remote_repo, &["commit", "-m", "init"]);
    run_git(&deleted_remote_repo, &["push", "-u", "origin", "HEAD"]);
    fs::remove_dir_all(&bare_remote).unwrap();

    let ctx = ProtectionContext::new(home.clone(), vec![]);
    let report = inspect_orphans(&home, &ctx, &OrphanOptions { max_depth: 5 }).unwrap();

    assert!(
        !report.safe_to_prune.iter().any(|c| c.path.contains(".ssh"))
            && !report.blocked.iter().any(|b| b.path.contains(".ssh")),
        ".ssh must be pruned before orphan inspection: {:?}",
        report
    );
    assert!(
        report
            .blocked
            .iter()
            .any(|b| b.path.ends_with("evil_commondir")
                && b.reasons.iter().any(|r| r.contains("commondir"))),
        "directory-form .git commondir to .ssh must be blocked: {:?}",
        report.blocked
    );
    #[cfg(unix)]
    assert!(
        report
            .blocked
            .iter()
            .any(|b| b.path.ends_with("dangling_dotgit")),
        "dangling .git symlink must be reported in blocked: {:?}",
        report.blocked
    );
    assert!(
        report
            .blocked
            .iter()
            .any(|b| b.path.ends_with("deleted_remote_repo")
                && b.reasons
                    .iter()
                    .any(|r| r == "remote_unverified_or_unpushed")),
        "deleted remote must fail closed as remote_unverified_or_unpushed: {:?}",
        report.blocked
    );
}

#[test]
fn scan_rejects_protected_roots_and_zero_depth_but_allows_home() {
    let tmp = tempdir().unwrap();
    let home = tmp.path().join("home");
    let ssh_dir = home.join(".ssh");
    let work_dir = home.join("work");
    fs::create_dir_all(&ssh_dir).unwrap();
    fs::create_dir_all(&work_dir).unwrap();
    fs::write(ssh_dir.join("id_rsa"), vec![0u8; 500]).unwrap();
    fs::write(work_dir.join("data.bin"), vec![0u8; 100]).unwrap();

    let ctx = ProtectionContext::new(home.clone(), vec![]);

    // Reject max_depth == 0
    let zero_depth = scan_directory(
        &work_dir,
        &ctx,
        &ScanOptions {
            max_depth: 0,
            ..Default::default()
        },
    );
    assert!(zero_depth.is_err(), "max_depth == 0 must be rejected");

    // Reject protected credential directory as root
    assert!(
        scan_directory(&ssh_dir, &ctx, &ScanOptions::default()).is_err(),
        "scanning ~/.ssh directly must be rejected"
    );

    // Reject system root
    assert!(
        scan_directory(Path::new("/etc"), &ctx, &ScanOptions::default()).is_err(),
        "scanning /etc directly must be rejected"
    );

    // Allow scanning ~ itself while skipping .ssh inside it
    let home_report = scan_directory(&home, &ctx, &ScanOptions::default()).unwrap();
    assert_eq!(home_report.total_bytes, 100);
    assert!(home_report
        .skipped_protected
        .iter()
        .any(|p| p.ends_with(".ssh")));
}

#[test]
fn orphan_blocks_gitignored_files_at_preview_and_execute() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let remotes_dir = root.join("remotes");
    let workspace_dir = root.join("workspaces");
    fs::create_dir_all(&remotes_dir).unwrap();
    fs::create_dir_all(&workspace_dir).unwrap();

    let bare_remote = remotes_dir.join("origin.git");
    fs::create_dir_all(&bare_remote).unwrap();
    run_git(&bare_remote, &["init", "--bare"]);

    // 1. Repo with gitignored local.db at preview time
    let ignored_repo = workspace_dir.join("ignored_repo");
    run_git(
        &workspace_dir,
        &["clone", bare_remote.to_str().unwrap(), "ignored_repo"],
    );
    fs::write(ignored_repo.join(".gitignore"), "*.db\n").unwrap();
    fs::write(ignored_repo.join("README.md"), "hello\n").unwrap();
    run_git(&ignored_repo, &["add", ".gitignore", "README.md"]);
    run_git(&ignored_repo, &["commit", "-m", "init"]);
    run_git(&ignored_repo, &["push", "-u", "origin", "HEAD"]);
    fs::write(ignored_repo.join("local.db"), "sqlite data\n").unwrap();

    // 2. Clean repo at preview time, then ignored file created before execute
    let ignored_after = workspace_dir.join("ignored_after_plan");
    run_git(
        &workspace_dir,
        &["clone", bare_remote.to_str().unwrap(), "ignored_after_plan"],
    );
    fs::write(ignored_after.join("after.txt"), "clean\n").unwrap();
    run_git(&ignored_after, &["add", "after.txt"]);
    run_git(&ignored_after, &["commit", "-m", "after"]);
    run_git(&ignored_after, &["push", "-u", "origin", "HEAD"]);

    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    let report = inspect_orphans(&workspace_dir, &ctx, &OrphanOptions { max_depth: 5 }).unwrap();
    assert!(
        report.blocked.iter().any(|b| {
            b.path.ends_with("ignored_repo")
                && b.reasons.iter().any(|r| r == "ignored_files_present")
        }),
        "ignored_repo must be blocked with ignored_files_present: {:?}",
        report.blocked
    );
    assert!(
        !report
            .safe_to_prune
            .iter()
            .any(|c| c.path.ends_with("ignored_repo")),
        "ignored_repo must not be safe_to_prune"
    );

    let plan = build_remediation_plan(
        &workspace_dir,
        &ctx,
        &PlanOptions {
            include_trash: false,
            include_orphans: true,
            trash_path_override: None,
            orphan_max_depth: 5,
        },
    )
    .unwrap();
    let item = plan
        .items
        .iter()
        .find(|i| i.path.ends_with("ignored_after_plan"))
        .expect("ignored_after_plan should be planned while clean");

    // Create gitignored file between plan and execute
    fs::write(ignored_after.join("local.db"), "important local db\n").unwrap();
    let gate = ExecutionGate {
        execute: true,
        confirm: true,
        plan_sha256: plan.plan_sha256.clone(),
        item_id: item.id.clone(),
    };
    assert!(
        execute_plan_item(&plan, &gate, &ctx).is_err(),
        "execute_plan_item must refuse repo with gitignored files created after plan"
    );
    assert!(ignored_after.exists());
    assert!(ignored_after.join("local.db").exists());
}

#[test]
fn orphan_live_verifies_every_local_branch_not_just_head() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let remotes_dir = root.join("remotes");
    let workspace_dir = root.join("workspaces");
    fs::create_dir_all(&remotes_dir).unwrap();
    fs::create_dir_all(&workspace_dir).unwrap();

    let bare_remote = remotes_dir.join("origin.git");
    fs::create_dir_all(&bare_remote).unwrap();
    run_git(&bare_remote, &["init", "--bare"]);

    // 1. Repo where checked-out branch is pushed, but secondary branch `wip` was deleted on remote
    //    while stale `refs/remotes/origin/wip` remains locally.
    let stale_repo = workspace_dir.join("stale_secondary_branch");
    run_git(
        &workspace_dir,
        &[
            "clone",
            bare_remote.to_str().unwrap(),
            "stale_secondary_branch",
        ],
    );
    fs::write(stale_repo.join("README.md"), "hello\n").unwrap();
    run_git(&stale_repo, &["add", "README.md"]);
    run_git(&stale_repo, &["commit", "-m", "init"]);
    run_git(&stale_repo, &["push", "-u", "origin", "HEAD"]);
    let default_branch = String::from_utf8_lossy(
        &Command::new("git")
            .current_dir(&stale_repo)
            .args(["symbolic-ref", "--short", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();

    run_git(&stale_repo, &["checkout", "-b", "wip"]);
    fs::write(stale_repo.join("wip.txt"), "wip\n").unwrap();
    run_git(&stale_repo, &["add", "wip.txt"]);
    run_git(&stale_repo, &["commit", "-m", "wip"]);
    run_git(&stale_repo, &["push", "-u", "origin", "wip"]);
    // Delete wip on bare remote directly so local refs/remotes/origin/wip is stale
    run_git(&bare_remote, &["update-ref", "-d", "refs/heads/wip"]);
    run_git(&stale_repo, &["checkout", &default_branch]);

    // 2. Repo where both default branch and secondary branch `feat` are pushed to live remote
    let pushed_repo = workspace_dir.join("all_branches_pushed");
    run_git(
        &workspace_dir,
        &[
            "clone",
            bare_remote.to_str().unwrap(),
            "all_branches_pushed",
        ],
    );
    run_git(&pushed_repo, &["checkout", "-b", "feat"]);
    fs::write(pushed_repo.join("feat.txt"), "feat\n").unwrap();
    run_git(&pushed_repo, &["add", "feat.txt"]);
    run_git(&pushed_repo, &["commit", "-m", "feat"]);
    run_git(&pushed_repo, &["push", "-u", "origin", "feat"]);
    run_git(&pushed_repo, &["checkout", &default_branch]);

    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    let report = inspect_orphans(&workspace_dir, &ctx, &OrphanOptions { max_depth: 5 }).unwrap();

    assert!(
        report.blocked.iter().any(|b| {
            b.path.ends_with("stale_secondary_branch")
                && b.reasons
                    .iter()
                    .any(|r| r == "remote_unverified_or_unpushed")
        }),
        "repo with stale deleted secondary branch must be blocked: {:?}",
        report.blocked
    );
    assert!(
        report
            .safe_to_prune
            .iter()
            .any(|c| c.path.ends_with("all_branches_pushed")),
        "repo with all branches live-pushed must be safe_to_prune: {:?}",
        report
    );
}

#[test]
fn orphan_blocks_deep_nested_dirty_repo_beyond_depth_5() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let remotes_dir = root.join("remotes");
    let workspace_dir = root.join("workspaces");
    fs::create_dir_all(&remotes_dir).unwrap();
    fs::create_dir_all(&workspace_dir).unwrap();

    let bare_remote = remotes_dir.join("origin.git");
    fs::create_dir_all(&bare_remote).unwrap();
    run_git(&bare_remote, &["init", "--bare"]);

    // 1. Clean pushed outer repo with dirty repo at depth 7
    let deep_outer = workspace_dir.join("deep_outer");
    run_git(
        &workspace_dir,
        &["clone", bare_remote.to_str().unwrap(), "deep_outer"],
    );
    fs::write(deep_outer.join("README.md"), "hello\n").unwrap();
    run_git(&deep_outer, &["add", "README.md"]);
    run_git(&deep_outer, &["commit", "-m", "init"]);
    run_git(&deep_outer, &["push", "-u", "origin", "HEAD"]);

    let deep_inner = deep_outer.join("d1/d2/d3/d4/d5/d6/inner_dirty");
    fs::create_dir_all(&deep_inner).unwrap();
    run_git(&deep_inner, &["init"]);
    fs::write(deep_inner.join("unsaved.txt"), "unsaved\n").unwrap();

    // 2. Clean outer repo at plan time, then deep dirty nested repo added before execute
    let deep_after = workspace_dir.join("deep_after_plan");
    run_git(
        &workspace_dir,
        &["clone", bare_remote.to_str().unwrap(), "deep_after_plan"],
    );
    fs::write(deep_after.join("README2.md"), "hello2\n").unwrap();
    run_git(&deep_after, &["add", "README2.md"]);
    run_git(&deep_after, &["commit", "-m", "init2"]);
    run_git(&deep_after, &["push", "-u", "origin", "HEAD"]);

    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    let report = inspect_orphans(&workspace_dir, &ctx, &OrphanOptions { max_depth: 5 }).unwrap();
    assert!(
        report
            .blocked
            .iter()
            .any(|b| b.path.ends_with("deep_outer")),
        "deep_outer with depth-7 dirty nested repo must be blocked: {:?}",
        report.blocked
    );
    assert!(
        !report
            .safe_to_prune
            .iter()
            .any(|c| c.path.ends_with("deep_outer")),
        "deep_outer must not be safe_to_prune"
    );

    let plan = build_remediation_plan(
        &workspace_dir,
        &ctx,
        &PlanOptions {
            include_trash: false,
            include_orphans: true,
            trash_path_override: None,
            orphan_max_depth: 5,
        },
    )
    .unwrap();
    let item = plan
        .items
        .iter()
        .find(|i| i.path.ends_with("deep_after_plan"))
        .expect("deep_after_plan should be planned while clean");

    let after_inner = deep_after.join("d1/d2/d3/d4/d5/d6/inner_dirty");
    fs::create_dir_all(&after_inner).unwrap();
    run_git(&after_inner, &["init"]);
    fs::write(after_inner.join("unsaved.txt"), "unsaved\n").unwrap();

    let gate = ExecutionGate {
        execute: true,
        confirm: true,
        plan_sha256: plan.plan_sha256.clone(),
        item_id: item.id.clone(),
    };
    assert!(
        execute_plan_item(&plan, &gate, &ctx).is_err(),
        "execute_plan_item must block depth-7 dirty nested repo added after plan"
    );
    assert!(after_inner.join("unsaved.txt").exists());
}

#[cfg(unix)]
#[test]
fn handle_anchored_removal_happy_path_and_symlink_swap_refusal() {
    use std::os::unix::fs::symlink;

    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let trash_dir = root.join("Trash");
    let workspace_dir = root.join("workspaces");
    let remotes_dir = root.join("remotes");
    let outside_dir = root.join("outside");
    fs::create_dir_all(&trash_dir).unwrap();
    fs::create_dir_all(&workspace_dir).unwrap();
    fs::create_dir_all(&remotes_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    // Multi-level directory in Trash
    let trash_nested = trash_dir.join("nested_cache");
    fs::create_dir_all(trash_nested.join("a/b")).unwrap();
    fs::write(trash_nested.join("a/b/c.bin"), vec![3u8; 32]).unwrap();

    // Clean pushed orphan worktree
    let bare_remote = remotes_dir.join("origin.git");
    fs::create_dir_all(&bare_remote).unwrap();
    run_git(&bare_remote, &["init", "--bare"]);
    let clean_orphan = workspace_dir.join("clean_orphan");
    run_git(
        &workspace_dir,
        &["clone", bare_remote.to_str().unwrap(), "clean_orphan"],
    );
    fs::write(clean_orphan.join("README.md"), "hello\n").unwrap();
    run_git(&clean_orphan, &["add", "README.md"]);
    run_git(&clean_orphan, &["commit", "-m", "init"]);
    run_git(&clean_orphan, &["push", "-u", "origin", "HEAD"]);

    // File and dir in Trash for symlink swap tests
    let swap_file = trash_dir.join("swap_file.bin");
    fs::write(&swap_file, vec![4u8; 16]).unwrap();
    let swap_dir = trash_dir.join("swap_dir");
    fs::create_dir_all(&swap_dir).unwrap();
    fs::write(swap_dir.join("inner.txt"), "x").unwrap();

    let victim_file = outside_dir.join("victim.txt");
    fs::write(&victim_file, "keep me").unwrap();
    let victim_dir = outside_dir.join("victim_dir");
    fs::create_dir_all(&victim_dir).unwrap();
    fs::write(victim_dir.join("keep.txt"), "keep dir").unwrap();

    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    let plan = build_remediation_plan(
        &workspace_dir,
        &ctx,
        &PlanOptions {
            include_trash: true,
            include_orphans: true,
            trash_path_override: Some(trash_dir.clone()),
            orphan_max_depth: 5,
        },
    )
    .unwrap();

    // Happy path: remove multi-level trash dir and clean orphan
    let trash_nested_item = plan
        .items
        .iter()
        .find(|i| i.path.ends_with("nested_cache"))
        .unwrap();
    execute_plan_item_with_roots(
        &plan,
        &ExecutionGate {
            execute: true,
            confirm: true,
            plan_sha256: plan.plan_sha256.clone(),
            item_id: trash_nested_item.id.clone(),
        },
        &ctx,
        std::slice::from_ref(&trash_dir),
    )
    .unwrap();
    assert!(!trash_nested.exists());

    let orphan_item = plan
        .items
        .iter()
        .find(|i| i.path.ends_with("clean_orphan"))
        .unwrap();
    execute_plan_item_with_roots(
        &plan,
        &ExecutionGate {
            execute: true,
            confirm: true,
            plan_sha256: plan.plan_sha256.clone(),
            item_id: orphan_item.id.clone(),
        },
        &ctx,
        std::slice::from_ref(&trash_dir),
    )
    .unwrap();
    assert!(!clean_orphan.exists());

    // Symlink swap on file
    fs::remove_file(&swap_file).unwrap();
    symlink(&victim_file, &swap_file).unwrap();
    let swap_file_item = plan
        .items
        .iter()
        .find(|i| i.path.ends_with("swap_file.bin"))
        .unwrap();
    assert!(execute_plan_item_with_roots(
        &plan,
        &ExecutionGate {
            execute: true,
            confirm: true,
            plan_sha256: plan.plan_sha256.clone(),
            item_id: swap_file_item.id.clone(),
        },
        &ctx,
        std::slice::from_ref(&trash_dir),
    )
    .is_err());
    assert!(victim_file.exists());

    // Symlink swap on dir
    fs::remove_dir_all(&swap_dir).unwrap();
    symlink(&victim_dir, &swap_dir).unwrap();
    let swap_dir_item = plan
        .items
        .iter()
        .find(|i| i.path.ends_with("swap_dir"))
        .unwrap();
    assert!(execute_plan_item_with_roots(
        &plan,
        &ExecutionGate {
            execute: true,
            confirm: true,
            plan_sha256: plan.plan_sha256.clone(),
            item_id: swap_dir_item.id.clone(),
        },
        &ctx,
        std::slice::from_ref(&trash_dir),
    )
    .is_err());
    assert!(victim_dir.join("keep.txt").exists());
}

#[cfg(unix)]
#[test]
fn unreadable_directory_fails_closed_before_deleting_siblings() {
    use std::os::unix::fs::PermissionsExt;

    // Skip cleanly if running as root (uid 0 ignores chmod 0000)
    let id_out = Command::new("id").arg("-u").output().unwrap();
    if String::from_utf8_lossy(&id_out.stdout).trim() == "0" {
        return;
    }

    struct ChmodGuard(PathBuf, u32);
    impl Drop for ChmodGuard {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(self.1));
        }
    }

    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let trash_dir = root.join("Trash");
    fs::create_dir_all(&trash_dir).unwrap();

    // Case A: unreadable root dir
    let unreadable_root = trash_dir.join("unreadable_root");
    fs::create_dir_all(&unreadable_root).unwrap();
    fs::write(unreadable_root.join("hidden.txt"), "secret").unwrap();
    fs::set_permissions(&unreadable_root, fs::Permissions::from_mode(0o000)).unwrap();
    let _guard_a = ChmodGuard(unreadable_root.clone(), 0o755);

    // Case B: readable parent containing unreadable child + readable sibling
    let parent_dir = trash_dir.join("parent_with_locked_child");
    let locked_child = parent_dir.join("locked_sub");
    fs::create_dir_all(&locked_child).unwrap();
    fs::write(locked_child.join("inside.txt"), "inside").unwrap();
    let sibling = parent_dir.join("sibling.txt");
    fs::write(&sibling, "sibling").unwrap();

    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);

    // Plan while parent_dir is readable
    let plan = build_remediation_plan(
        root,
        &ctx,
        &PlanOptions {
            include_trash: true,
            include_orphans: false,
            trash_path_override: Some(trash_dir.clone()),
            orphan_max_depth: 5,
        },
    )
    .unwrap();
    let parent_item = plan
        .items
        .iter()
        .find(|i| i.path.ends_with("parent_with_locked_child"))
        .expect("readable parent_dir should be planned")
        .clone();

    // Now lock locked_child
    fs::set_permissions(&locked_child, fs::Permissions::from_mode(0o000)).unwrap();
    let _guard_b = ChmodGuard(locked_child.clone(), 0o755);

    assert!(
        sj_core::protect::check_dir_descendants_safe(&unreadable_root, &ctx, 100_000).protected,
        "unreadable root must be denied by check_dir_descendants_safe"
    );
    assert!(
        sj_core::protect::check_dir_descendants_safe(&parent_dir, &ctx, 100_000).protected,
        "parent with unreadable child must be denied by check_dir_descendants_safe"
    );

    let trash_report = discover_trash_at(&trash_dir, &ctx).unwrap();
    assert!(
        trash_report
            .protected_items
            .iter()
            .any(|i| i.path.ends_with("unreadable_root")),
        "unreadable_root must be protected in trash report"
    );
    assert!(
        trash_report
            .protected_items
            .iter()
            .any(|i| i.path.ends_with("parent_with_locked_child")),
        "parent_with_locked_child must be protected in trash report"
    );

    // Execute on planned parent_item must fail BEFORE deleting readable sibling
    let res = execute_plan_item_with_roots(
        &plan,
        &ExecutionGate {
            execute: true,
            confirm: true,
            plan_sha256: plan.plan_sha256.clone(),
            item_id: parent_item.id.clone(),
        },
        &ctx,
        std::slice::from_ref(&trash_dir),
    );
    assert!(res.is_err(), "execute must fail closed on unreadable child");
    assert!(
        sibling.exists(),
        "readable sibling must NOT be deleted when child is unreadable"
    );
}

#[test]
fn snapshot_binding_rejects_same_size_replacement_and_git_drift() {
    use std::io::Write;

    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let trash_dir = root.join("Trash");
    let workspace_dir = root.join("workspaces");
    let remotes_dir = root.join("remotes");
    fs::create_dir_all(&trash_dir).unwrap();
    fs::create_dir_all(&workspace_dir).unwrap();
    fs::create_dir_all(&remotes_dir).unwrap();

    // 1. Trash file replaced with same byte size (new inode)
    let replaced_file = trash_dir.join("replaced.bin");
    fs::write(&replaced_file, vec![b'A'; 64]).unwrap();

    // 2. Trash file overwritten in-place with same byte size (same inode)
    let inplace_file = trash_dir.join("inplace.bin");
    fs::write(&inplace_file, vec![b'C'; 64]).unwrap();

    // 3. Clean pushed orphan worktree that gets a new pushed commit after plan
    let bare_remote = remotes_dir.join("origin.git");
    fs::create_dir_all(&bare_remote).unwrap();
    run_git(&bare_remote, &["init", "--bare"]);
    let drifting_orphan = workspace_dir.join("drifting_orphan");
    run_git(
        &workspace_dir,
        &["clone", bare_remote.to_str().unwrap(), "drifting_orphan"],
    );
    fs::write(drifting_orphan.join("README.md"), "hello\n").unwrap();
    run_git(&drifting_orphan, &["add", "README.md"]);
    run_git(&drifting_orphan, &["commit", "-m", "init"]);
    run_git(&drifting_orphan, &["push", "-u", "origin", "HEAD"]);

    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    let plan = build_remediation_plan(
        &workspace_dir,
        &ctx,
        &PlanOptions {
            include_trash: true,
            include_orphans: true,
            trash_path_override: Some(trash_dir.clone()),
            orphan_max_depth: 5,
        },
    )
    .unwrap();

    // Replace file with same size (unlink + create)
    fs::remove_file(&replaced_file).unwrap();
    fs::write(&replaced_file, vec![b'B'; 64]).unwrap();
    let replaced_item = plan
        .items
        .iter()
        .find(|i| i.path.ends_with("replaced.bin"))
        .unwrap();
    assert!(
        execute_plan_item_with_roots(
            &plan,
            &ExecutionGate {
                execute: true,
                confirm: true,
                plan_sha256: plan.plan_sha256.clone(),
                item_id: replaced_item.id.clone(),
            },
            &ctx,
            std::slice::from_ref(&trash_dir),
        )
        .is_err(),
        "same-size unlink+recreate replacement must fail snapshot check"
    );
    assert!(replaced_file.exists());

    // Overwrite file in-place with same size
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .truncate(false)
            .open(&inplace_file)
            .unwrap();
        f.write_all(&[b'D'; 64]).unwrap();
        f.flush().unwrap();
    }
    let inplace_item = plan
        .items
        .iter()
        .find(|i| i.path.ends_with("inplace.bin"))
        .unwrap();
    assert!(
        execute_plan_item_with_roots(
            &plan,
            &ExecutionGate {
                execute: true,
                confirm: true,
                plan_sha256: plan.plan_sha256.clone(),
                item_id: inplace_item.id.clone(),
            },
            &ctx,
            std::slice::from_ref(&trash_dir),
        )
        .is_err(),
        "same-size in-place overwrite must fail snapshot check"
    );
    assert!(inplace_file.exists());

    // Re-commit and push drifting_orphan (still clean & pushed, but HEAD/tree changed)
    fs::write(drifting_orphan.join("README.md"), "world\n").unwrap();
    run_git(&drifting_orphan, &["add", "README.md"]);
    run_git(&drifting_orphan, &["commit", "-m", "second"]);
    run_git(&drifting_orphan, &["push", "origin", "HEAD"]);

    let orphan_item = plan
        .items
        .iter()
        .find(|i| i.path.ends_with("drifting_orphan"))
        .unwrap();
    assert!(
        execute_plan_item_with_roots(
            &plan,
            &ExecutionGate {
                execute: true,
                confirm: true,
                plan_sha256: plan.plan_sha256.clone(),
                item_id: orphan_item.id.clone(),
            },
            &ctx,
            std::slice::from_ref(&trash_dir),
        )
        .is_err(),
        "re-committed orphan_worktree must fail snapshot check"
    );
    assert!(drifting_orphan.exists());
}
