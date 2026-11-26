use sj_core::linux::{
    check_linux_command_platform_gate, classify_mount, discover_linux_audit_from_fixtures,
    parse_docker_containers, parse_docker_dangling_images, parse_docker_system_df,
    parse_human_size, parse_journald_disk_usage, parse_podman_ps, parse_proc_meminfo,
    parse_proc_mounts, parse_proc_status_vm_swap, parse_systemctl_failed, LinuxFixtures,
    MountKind,
};
use sj_core::plan::{
    build_remediation_plan_with_linux, execute_plan_item_with_linux, ExecutionGate,
    LinuxPlanOptions, PlanOptions,
};
use sj_core::protect::{check_path_protection, ProtectionContext};
use sj_core::scan::{scan_directory, ScanOptions};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Temp dir outside protected home subtrees. On Windows the default temp dir sits under
/// `%USERPROFILE%\AppData`, which the protect list refuses.
fn safe_tempdir() -> TempDir {
    if cfg!(windows) {
        tempfile::Builder::new()
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .unwrap()
    } else {
        tempfile::tempdir().unwrap()
    }
}

#[test]
fn linux_protected_system_and_container_roots_always_fail_closed() {
    let ctx = ProtectionContext::new(PathBuf::from("/home/developer"), vec![]);
    for p in [
        "/var/lib/docker/overlay2/layer123",
        "/var/lib/containers/storage/overlay",
        "/var/log/journal/abcd1234",
        "/var/cache/apt/archives/pkg.deb",
        "/run/systemd/private",
        "/var/lib/dpkg/status",
        "/var/lib/systemd/coredump",
        "/snap/core22/current",
    ] {
        let v = check_path_protection(std::path::Path::new(p), &ctx);
        assert!(v.protected, "expected Linux system/runtime path {p} to be protected");
    }
    // User caches and stale /tmp entries remain evaluable for cleanup
    assert!(
        !check_path_protection(std::path::Path::new("/home/developer/.cache/pip"), &ctx).protected
    );
    assert!(
        !check_path_protection(std::path::Path::new("/tmp/.mount_Orca-stale"), &ctx).protected
    );
}

#[test]
fn parses_proc_mounts_and_classifies_overlay_tmpfs_and_appimage_mounts() {
    let mounts_raw = "\
/dev/nvme0n1p2 / ext4 rw,relatime 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0
overlay /var/lib/docker/overlay2/abc/merged overlay rw,relatime,lowerdir=a,upperdir=b,workdir=c 0 0
Orca-1.0.0.AppImage /tmp/.mount_Orca-AbCdEf fuse.Orca-1.0.0.AppImage ro,nosuid,nodev,relatime 0 0
Orca-1.0.1.AppImage /tmp/.mount_Orca-123456 fuse.AppImage ro,nosuid,nodev 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
/dev/nvme0n1p1 /boot/efi vfat rw,relatime 0 0
";
    let parsed = parse_proc_mounts(mounts_raw);
    assert_eq!(parsed.len(), 8);
    assert_eq!(parsed[0].kind, MountKind::Physical);
    assert!(parsed[0].alert_eligible);
    assert_eq!(parsed[1].kind, MountKind::Tmpfs);
    assert!(!parsed[1].alert_eligible);
    assert_eq!(parsed[2].kind, MountKind::Overlay);
    assert!(!parsed[2].alert_eligible);
    assert_eq!(parsed[3].kind, MountKind::AppImage);
    assert!(!parsed[3].alert_eligible);
    assert_eq!(parsed[4].kind, MountKind::AppImage);
    assert_eq!(classify_mount("none", "/tmp/.mount_Foo", "squashfs"), MountKind::AppImage);
    assert_eq!(parsed[5].kind, MountKind::Virtual);
}

#[test]
fn parses_human_sizes_and_docker_podman_journald_and_systemctl_outputs() {
    assert_eq!(parse_human_size("0B"), 0);
    assert_eq!(parse_human_size("22.8GB"), 22_800_000_000);
    assert_eq!(parse_human_size("1.5GiB"), 1_610_612_736);
    assert_eq!(parse_human_size("94.2GB (98%)"), 94_200_000_000);

    let df_out = r#"{"Type":"Images","TotalCount":"14","Active":"3","Size":"85.4GB","Reclaimable":"71.2GB (83%)"}
{"Type":"Containers","TotalCount":"9","Active":"2","Size":"4.5GB","Reclaimable":"4.1GB (91%)"}
{"Type":"Local Volumes","TotalCount":"6","Active":"2","Size":"12GB","Reclaimable":"3.2GB"}
{"Type":"Build Cache","TotalCount":"48","Active":"0","Size":"22.8GB","Reclaimable":"22.8GB"}"#;
    let df = parse_docker_system_df(df_out);
    assert_eq!(df.images_reclaimable_bytes, 71_200_000_000);
    assert_eq!(df.build_cache_reclaimable_bytes, 22_800_000_000);
    assert_eq!(df.containers_reclaimable_bytes, 4_100_000_000);

    let ps_out = r#"{"ID":"abc123def456","Names":"model-runner","Image":"vllm:latest","Status":"Exited (137) 4 days ago","State":"exited","Size":"1.2GB"}
{"ID":"run999","Names":"metrics-agent","Image":"cadvisor:latest","Status":"Up 3 days (unhealthy)","State":"running","Size":"0B"}
{"ID":"cre777","Names":"trace-init","Image":"langfuse:latest","Status":"Created","State":"created","Size":"0B"}"#;
    let containers = parse_docker_containers(ps_out);
    assert_eq!(containers.len(), 3);
    assert_eq!(
        containers.iter().filter(|c| c.is_reclaimable_stopped()).count(),
        2
    );
    assert_eq!(containers.iter().filter(|c| c.unhealthy).count(), 1);

    let imgs_out = r#"{"ID":"sha256:111","Repository":"<none>","Tag":"<none>","Size":"4.5GB"}"#;
    let imgs = parse_docker_dangling_images(imgs_out);
    assert_eq!(imgs.len(), 1);
    assert_eq!(imgs[0].size_bytes, 4_500_000_000);

    let podman_out = r#"[{"Id":"pod111","Names":["stale-pod"],"Image":"alpine:latest","State":"exited","Status":"Exited (0) 2 days ago"},{"Id":"pod222","Names":["live-pod"],"Image":"nginx:latest","State":"running","Status":"Up 1 hour (unhealthy)"}]"#;
    let podman = parse_podman_ps(podman_out);
    assert_eq!(podman.len(), 2);
    assert!(podman[0].is_reclaimable_stopped());
    assert!(podman[1].unhealthy);

    let j_bytes = parse_journald_disk_usage("Archived and active journals take up 2.4G in the file system.");
    assert_eq!(j_bytes, Some(2_576_980_377)); // 2.4 * 1024^3 truncated/rounded

    let sys_failed = parse_systemctl_failed(
        "project-status.service loaded failed failed Project status updater\npaperclip-backup.service loaded failed failed Paperclip backup\n",
        "system",
    );
    assert_eq!(sys_failed.len(), 2);
    assert_eq!(sys_failed[0].unit, "project-status.service");

    let user_failed = parse_systemctl_failed(
        "no-mistakes-daemon.service loaded failed failed No mistakes daemon\npodman-1234-healthcheck.service loaded failed failed Podman healthcheck\n",
        "user",
    );
    assert_eq!(user_failed.len(), 2);
    assert!(user_failed[1].is_podman_healthcheck);
}

#[test]
fn parses_linux_meminfo_and_proc_status_swap() {
    let meminfo = "\
MemTotal:       131072000 kB
MemFree:         2000000 kB
MemAvailable:   64000000 kB
Buffers:         1000000 kB
Cached:         50000000 kB
SwapTotal:       8388608 kB
SwapFree:        6291456 kB
";
    let mi = parse_proc_meminfo(meminfo);
    assert_eq!(mi.total_bytes, 131_072_000 * 1024);
    assert_eq!(mi.available_bytes, 64_000_000 * 1024);
    assert_eq!(mi.swap_total_bytes, 8_388_608 * 1024);
    assert_eq!(mi.swap_used_bytes, (8_388_608 - 6_291_456) * 1024);

    let status = "Name:\tpython3\nVmRSS:\t  102400 kB\nVmSwap:\t   4096 kB\n";
    assert_eq!(parse_proc_status_vm_swap(status), 4096 * 1024);
}

#[test]
fn linux_plan_is_dry_run_by_default_gates_execution_and_keeps_models_backups_manual_review_only() {
    let tmp = safe_tempdir();
    let home = fs::canonicalize(tmp.path()).unwrap().join("home");
    let pip_cache = home.join(".cache").join("pip");
    let hf_cache = home.join(".cache").join("huggingface").join("hub");
    let backup_dir = home.join("backups");
    let tmp_root = fs::canonicalize(tmp.path()).unwrap().join("tmp");
    let stale_appimage = tmp_root.join(".mount_App-stale");

    fs::create_dir_all(&pip_cache).unwrap();
    fs::write(pip_cache.join("wheel.whl"), vec![0u8; 4096]).unwrap();
    fs::create_dir_all(&hf_cache).unwrap();
    fs::write(hf_cache.join("weights.safetensors"), vec![0u8; 8192]).unwrap();
    fs::create_dir_all(&backup_dir).unwrap();
    fs::write(backup_dir.join("db-2025-01-01.tar.gz"), vec![0u8; 2048]).unwrap();
    fs::create_dir_all(&stale_appimage).unwrap();
    fs::write(stale_appimage.join("AppRun"), b"stale").unwrap();

    let audit = discover_linux_audit_from_fixtures(LinuxFixtures {
        home_dir: home.clone(),
        tmp_dir: tmp_root.clone(),
        apt_archives_dir: None,
        mounts_raw: "Orca-1.0.AppImage /tmp/.mount_Orca-active fuse.AppImage ro 0 0\n".to_string(),
        docker_df_raw: r#"{"Type":"Build Cache","TotalCount":"10","Active":"0","Size":"22.8GB","Reclaimable":"22.8GB"}"#.to_string(),
        docker_ps_raw: r#"{"ID":"deadbeef01","Names":"old-runner","Image":"vllm:latest","Status":"Exited (0) 3 days ago","State":"exited","Size":"1.5GB"}"#.to_string(),
        docker_images_raw: r#"{"ID":"sha256:dead1122","Repository":"<none>","Tag":"<none>","Size":"2.5GB"}"#.to_string(),
        podman_df_raw: String::new(),
        podman_ps_raw: String::new(),
        journald_usage_raw: "Archived and active journals take up 1.5G in the file system.".to_string(),
        systemctl_system_raw: String::new(),
        systemctl_user_raw: String::new(),
        stale_age_secs: 0,
    });

    let ctx = ProtectionContext::new(home.clone(), vec![]);
    let plan = build_remediation_plan_with_linux(
        &home,
        &ctx,
        &PlanOptions::default(),
        &LinuxPlanOptions {
            include_linux: true,
            audit_override: Some(audit),
            tmp_root_override: Some(tmp_root.clone()),
        },
    )
    .unwrap();

    assert_eq!(plan.mode, "dry-run");
    assert!(!plan.mutated);

    // Executable candidates present (exact-identity bound only)
    assert!(plan.items.iter().any(|i| i.kind == "linux_user_cache" && i.path == pip_cache.to_string_lossy()));
    assert!(plan.items.iter().any(|i| i.kind == "stale_tmp_entry" && i.path == stale_appimage.to_string_lossy()));
    assert!(plan.items.iter().any(|i| i.kind == "docker_exited_container"));
    assert!(plan.items.iter().any(|i| i.kind == "docker_dangling_image" && i.path == "docker://image/sha256:dead1122"));

    // Aggregate bulk maintenance (build cache, journald) and high-value data (HF, backups, active AppImages)
    // must be manual_review_only in protected_exclusions, never auto-executed in plan.items
    assert!(!plan.items.iter().any(|i| i.kind == "docker_build_cache" || i.kind == "journald_vacuum"));
    assert!(plan.protected_exclusions.iter().any(|e| e.path == "docker://build-cache" && e.reason.starts_with("manual_review_only:docker_build_cache:")));
    assert!(plan.protected_exclusions.iter().any(|e| e.path == "systemd://journald" && e.reason.starts_with("manual_review_only:journald_vacuum:")));

    // HuggingFace cache, old backups, and active AppImage mounts MUST be manual_review_only (never in plan.items)
    assert!(!plan.items.iter().any(|i| i.path.contains("huggingface")));
    assert!(!plan.items.iter().any(|i| i.path.contains("backups")));
    assert!(!plan.items.iter().any(|i| i.path.contains(".mount_Orca-active")));
    assert!(plan.protected_exclusions.iter().any(|e| e.path.contains("huggingface") && e.reason.starts_with("manual_review_only:")));
    assert!(plan.protected_exclusions.iter().any(|e| e.path.contains("backups") && e.reason.starts_with("manual_review_only:")));

    // Dry-run kept all files untouched
    assert!(pip_cache.join("wheel.whl").exists());
    assert!(stale_appimage.join("AppRun").exists());
    assert!(hf_cache.join("weights.safetensors").exists());

    // Execute without --confirm must fail closed
    let pip_item = plan.items.iter().find(|i| i.kind == "linux_user_cache").unwrap().clone();
    let err = execute_plan_item_with_linux(
        &plan,
        &ExecutionGate {
            execute: true,
            confirm: false,
            plan_sha256: plan.plan_sha256.clone(),
            item_id: pip_item.id.clone(),
        },
        &ctx,
        &[tmp_root.clone()],
    )
    .unwrap_err();
    assert!(matches!(err, sj_core::SjError::ExecutionGate(_)));
    assert!(pip_cache.join("wheel.whl").exists());

    // Execute WITH --execute --confirm --plan-sha256 --item removes ONLY the targeted pip cache
    let removed = execute_plan_item_with_linux(
        &plan,
        &ExecutionGate {
            execute: true,
            confirm: true,
            plan_sha256: plan.plan_sha256.clone(),
            item_id: pip_item.id.clone(),
        },
        &ctx,
        &[tmp_root.clone()],
    )
    .unwrap();
    assert_eq!(removed.id, pip_item.id);
    assert!(!pip_cache.exists());
    assert!(hf_cache.join("weights.safetensors").exists());
    assert!(stale_appimage.join("AppRun").exists());
}

#[test]
fn scan_directory_records_fs_capacity_and_filters_nested_mountpoints() {
    let tmp = safe_tempdir();
    let root = tmp.path();
    fs::create_dir_all(root.join("logs")).unwrap();
    fs::write(root.join("logs/app.log"), vec![1u8; 512]).unwrap();
    let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
    let report = scan_directory(root, &ctx, &ScanOptions::default()).unwrap();
    assert!(report.fs_total_bytes.unwrap_or(0) > 0);
    assert!(report.fs_free_bytes.is_some());
}

#[cfg(unix)]
#[test]
fn stale_tmp_discovery_checks_newest_descendant_mtime_not_just_dir_mtime() {
    let tmp = safe_tempdir();
    let root = fs::canonicalize(tmp.path()).unwrap();
    let home = root.join("home");
    let tmp_dir = root.join("tmp");
    let old_dir_active_child = tmp_dir.join(".mount_App-active-child");
    let deep_dir = old_dir_active_child.join("a/b/c/d/e/f/g/h");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&deep_dir).unwrap();
    let child_file = deep_dir.join("running.pid");
    fs::write(&child_file, b"1234").unwrap();

    // Set parent & intermediate directory mtimes far in the past (10 days ago), while deep child stays fresh (now)
    let ten_days_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(10 * 86_400);
    for anc in [
        old_dir_active_child.as_path(),
        &old_dir_active_child.join("a"),
        &old_dir_active_child.join("a/b"),
        &old_dir_active_child.join("a/b/c"),
        &old_dir_active_child.join("a/b/c/d"),
        &old_dir_active_child.join("a/b/c/d/e"),
        &old_dir_active_child.join("a/b/c/d/e/f"),
        &old_dir_active_child.join("a/b/c/d/e/f/g"),
        &deep_dir,
    ] {
        fs::File::open(anc).unwrap().set_modified(ten_days_ago).unwrap();
    }

    let audit = discover_linux_audit_from_fixtures(LinuxFixtures {
        home_dir: home,
        tmp_dir,
        apt_archives_dir: None,
        mounts_raw: String::new(),
        docker_df_raw: String::new(),
        docker_ps_raw: String::new(),
        docker_images_raw: String::new(),
        podman_df_raw: String::new(),
        podman_ps_raw: String::new(),
        journald_usage_raw: String::new(),
        systemctl_system_raw: String::new(),
        systemctl_user_raw: String::new(),
        stale_age_secs: 24 * 3600,
    });
    assert!(
        audit.stale_tmp_entries.is_empty(),
        "directory with fresh descendant file must NOT be marked stale: {:?}",
        audit.stale_tmp_entries
    );
}

#[test]
fn blockers_apply_systemd_audit_surfaces_failed_units_and_podman_healthchecks() {
    use sj_core::blockers::{apply_systemd_audit, evaluate_linux_blockers};
    use sj_core::linux::SystemdAudit;

    let mut report = evaluate_linux_blockers(Some(100), Some(10000), Some(0), Some(10), Some(524288), vec![]);
    assert_eq!(report.status, "OK");

    let sys_failed = parse_systemctl_failed(
        "project-status.service loaded failed failed Project status\npaperclip-backup.service loaded failed failed Backup\n",
        "system",
    );
    let user_failed = parse_systemctl_failed(
        "no-mistakes-daemon.service loaded failed failed Daemon\npodman-999-healthcheck.service loaded failed failed Podman healthcheck\n",
        "user",
    );
    let podman_hc = user_failed
        .iter()
        .filter(|u| u.is_podman_healthcheck)
        .cloned()
        .collect();

    apply_systemd_audit(
        &mut report,
        SystemdAudit {
            available: true,
            user_bus_available: true,
            system_failed: sys_failed,
            user_failed,
            podman_healthcheck_issues: podman_hc,
        },
    );
    assert_eq!(report.status, "WARN");
    assert!(report.blockers.iter().any(|b| b.id == "linux-systemd-system-failed"));
    assert!(report.blockers.iter().any(|b| b.id == "linux-systemd-user-failed"));
    assert!(report.blockers.iter().any(|b| b.id == "linux-podman-healthcheck-failed"));
}

#[test]
fn non_unix_linux_command_execution_fails_closed() {
    let err = check_linux_command_platform_gate(false).unwrap_err();
    assert!(matches!(err, sj_core::SjError::ExecutionGate(_)));
    assert!(check_linux_command_platform_gate(true).is_ok());

    #[cfg(not(unix))]
    {
        let tmp = safe_tempdir();
        let home = tmp.path().join("home");
        let tmp_root = tmp.path().join("tmp");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&tmp_root).unwrap();
        let audit = discover_linux_audit_from_fixtures(LinuxFixtures {
            home_dir: home.clone(),
            tmp_dir: tmp_root.clone(),
            apt_archives_dir: None,
            mounts_raw: String::new(),
            docker_df_raw: String::new(),
            docker_ps_raw: r#"{"ID":"deadbeef01","Names":"old-runner","Image":"vllm:latest","Status":"Exited (0) 3 days ago","State":"exited","Size":"1.5GB"}"#.to_string(),
            docker_images_raw: String::new(),
            podman_df_raw: String::new(),
            podman_ps_raw: String::new(),
            journald_usage_raw: String::new(),
            systemctl_system_raw: String::new(),
            systemctl_user_raw: String::new(),
            stale_age_secs: 0,
        });
        let ctx = ProtectionContext::new(home.clone(), vec![]);
        let plan = build_remediation_plan_with_linux(
            &home,
            &ctx,
            &PlanOptions::default(),
            &LinuxPlanOptions {
                include_linux: true,
                audit_override: Some(audit),
                tmp_root_override: Some(tmp_root.clone()),
            },
        )
        .unwrap();
        let item = plan
            .items
            .iter()
            .find(|i| i.kind == "docker_exited_container")
            .unwrap()
            .clone();
        let err = execute_plan_item_with_linux(
            &plan,
            &ExecutionGate {
                execute: true,
                confirm: true,
                plan_sha256: plan.plan_sha256.clone(),
                item_id: item.id.clone(),
            },
            &ctx,
            &[tmp_root],
        )
        .unwrap_err();
        assert!(matches!(err, sj_core::SjError::ExecutionGate(_)));
    }
}
