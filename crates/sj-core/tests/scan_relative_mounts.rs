//! Bugbot #18 (a): `skip_mount_set` compared absolute /proc/mounts mountpoints with raw walk
//! paths, so a relative scan root (the CLI default ".") never skipped overlay/tmpfs mounts.
//! Own test binary: it changes the process cwd.
#![cfg(unix)]
use sj_core::linux::{MountInfo, MountKind};
use sj_core::protect::ProtectionContext;
use sj_core::scan::{scan_directory_with_mounts, ScanOptions};
use std::fs;
use std::path::PathBuf;

fn mount(mountpoint: &std::path::Path, kind: MountKind) -> MountInfo {
    MountInfo {
        device: "fake".into(),
        mountpoint: mountpoint.to_string_lossy().into_owned(),
        fstype: "tmpfs".into(),
        kind,
        alert_eligible: false,
        total_bytes: None,
        free_bytes: None,
        used_percent: None,
    }
}

#[test]
fn relative_and_absolute_roots_skip_the_same_mounts() {
    let tmp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(tmp.path()).unwrap();
    fs::create_dir_all(base.join("real")).unwrap();
    fs::create_dir_all(base.join("ovl")).unwrap();
    fs::write(base.join("real/a.txt"), b"hi").unwrap();
    fs::write(base.join("ovl/big"), vec![7u8; 4096]).unwrap();
    let ctx = ProtectionContext::new(PathBuf::from("/nonexistent-home-for-test"), vec![]);
    let opts = ScanOptions::default();
    let mounts = vec![mount(&base.join("ovl"), MountKind::Tmpfs)];

    let abs = scan_directory_with_mounts(&base, &ctx, &opts, mounts.clone()).unwrap();
    assert_eq!(abs.total_bytes, 2, "absolute root skips the tmpfs mount");
    assert_eq!(abs.skipped_mounts.len(), 1);

    std::env::set_current_dir(&base).unwrap();
    let rel = scan_directory_with_mounts(std::path::Path::new("."), &ctx, &opts, mounts.clone()).unwrap();
    assert_eq!(rel.total_bytes, abs.total_bytes, "relative '.' root must skip the same mounts");
    assert_eq!(rel.skipped_mounts.len(), 1);

    std::env::set_current_dir(base.parent().unwrap()).unwrap();
    let name = base.file_name().unwrap();
    let rel2 = scan_directory_with_mounts(std::path::Path::new(name), &ctx, &opts, mounts).unwrap();
    assert_eq!(rel2.total_bytes, abs.total_bytes, "relative subdir root must skip the same mounts");
}
