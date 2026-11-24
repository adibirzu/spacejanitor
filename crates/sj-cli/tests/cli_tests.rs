use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn sj_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sj")
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

    // plan --execute without confirmation must fail and not mutate
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
    assert_ne!(exec_fail.status.code(), Some(0));
    assert!(trash_dir.join("cache.tar").exists());
}
