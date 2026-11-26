//! PR #18 probe review (d): model caches and backups must pass the protect layer; env-supplied
//! roots (HF_HOME / OLLAMA_MODELS) must not point the audit at credential directories.
//! Own test binary: sets process env.
#![cfg(unix)]
use sj_core::linux::{discover_linux_audit_from_fixtures, LinuxFixtures};
use sj_core::plan::{build_remediation_plan_with_linux, LinuxPlanOptions, PlanOptions};
use sj_core::protect::ProtectionContext;
use std::fs;

#[test]
fn model_caches_and_backups_never_list_protected_paths() {
    let td = tempfile::tempdir().unwrap();
    let home = fs::canonicalize(td.path()).unwrap().join("home");
    let tmp = td.path().join("tmp");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::create_dir_all(home.join(".kube")).unwrap();
    fs::create_dir_all(home.join("backups")).unwrap();
    fs::create_dir_all(home.join(".cache/huggingface/hub")).unwrap();
    fs::create_dir_all(&tmp).unwrap();
    fs::write(home.join(".ssh/id_rsa"), b"x").unwrap();
    fs::write(home.join(".kube/config"), b"x").unwrap();
    fs::write(home.join("backups/.env"), b"K=V").unwrap();
    fs::write(home.join("backups/id_rsa"), b"x").unwrap();
    fs::write(home.join("backups/db.tar"), b"x").unwrap();
    fs::write(home.join(".cache/huggingface/hub/m.bin"), b"x").unwrap();
    // A backup directory that contains a credential file anywhere below it.
    fs::create_dir_all(home.join("backups/nested")).unwrap();
    fs::write(home.join("backups/nested/.env"), b"K=V").unwrap();

    std::env::set_var("HF_HOME", home.join(".ssh"));
    std::env::set_var("OLLAMA_MODELS", "../relative/escape");
    let fx = LinuxFixtures {
        home_dir: home.clone(),
        tmp_dir: tmp,
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
        stale_age_secs: 0,
    };
    let audit = discover_linux_audit_from_fixtures(fx);
    let listed: Vec<String> = audit
        .model_caches
        .iter()
        .chain(audit.old_backups.iter())
        .map(|a| a.path.clone())
        .collect();
    let joined = listed.join("\n");
    for bad in [".ssh", ".kube", ".env", "id_rsa", "relative/escape", "nested"] {
        assert!(!joined.contains(bad), "protected/unsafe path listed ({bad}):\n{joined}");
    }
    assert!(joined.contains("db.tar"), "plain backup still listed:\n{joined}");
    assert!(joined.contains("huggingface/hub"), "plain model cache still listed:\n{joined}");

    let ctx = ProtectionContext::new(home.clone(), vec![]);
    let plan = build_remediation_plan_with_linux(
        &home,
        &ctx,
        &PlanOptions::default(),
        &LinuxPlanOptions { include_linux: true, audit_override: Some(audit), tmp_root_override: None },
    )
    .unwrap();
    for it in &plan.items {
        for bad in [".ssh", ".kube", ".env", "id_rsa"] {
            assert!(!it.path.contains(bad), "plan item reached a protected path: {}", it.path);
        }
    }
    let excl = plan.protected_exclusions.iter().map(|e| e.path.clone()).collect::<Vec<_>>().join("\n");
    for bad in [".ssh", ".kube", "id_rsa"] {
        assert!(!excl.contains(bad), "exclusions list protected path ({bad}): {excl}");
    }
}
