//! Live-process probes: fake `docker`/`podman`/`systemctl`/`journalctl` binaries on PATH.
//! Own test binary; PATH is process-global so every test takes SHIM_LOCK.
#![cfg(unix)]
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Mutex;

static SHIM_LOCK: Mutex<()> = Mutex::new(());

fn write_shim(dir: &Path, name: &str, body: &str) {
    let p = dir.join(name);
    fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
}

fn with_path<T>(shims: &Path, f: impl FnOnce() -> T) -> T {
    let _g = SHIM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let old = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![shims.to_path_buf()];
    paths.extend(std::env::split_paths(&old));
    std::env::set_var("PATH", std::env::join_paths(paths).unwrap());
    let out = f();
    std::env::set_var("PATH", old);
    out
}

/// Bugbot #18 (b): `docker ps -a` leaves `.Size` empty unless `--size` is passed.
#[test]
fn docker_and_podman_container_sizes_are_real_when_runtime_needs_size_flag() {
    let td = tempfile::tempdir().unwrap();
    let shims = td.path().join("bin");
    fs::create_dir_all(&shims).unwrap();
    let log = td.path().join("argv.log");
    write_shim(
        &shims,
        "docker",
        &format!(
            r#"echo "docker $*" >> {log}
case "$1" in
 ps) size=""; for a in "$@"; do [ "$a" = "--size" ] || [ "$a" = "-s" ] && size="5MB (virtual 120MB)"; done
     echo '{{"ID":"abc123","Names":"c1","Image":"x","Status":"Exited (0) 2 days ago","State":"exited","Size":"'"$size"'"}}';;
esac"#,
            log = log.display()
        ),
    );
    write_shim(
        &shims,
        "podman",
        &format!(
            r#"echo "podman $*" >> {log}
case "$1" in
 ps) size=0; for a in "$@"; do [ "$a" = "--size" ] || [ "$a" = "-s" ] && size=7000000; done
     echo '[{{"Id":"p1","Names":["pc1"],"Image":"y","State":"exited","Status":"Exited (0) 5d ago","Size":{{"rwSize":'"$size"'}}}}]';;
esac"#,
            log = log.display()
        ),
    );
    let home = td.path().join("home");
    let tmp = td.path().join("tmp");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&tmp).unwrap();
    let audit = with_path(&shims, || sj_core::linux::discover_linux_audit(&home, Some(&tmp)));
    let argv = fs::read_to_string(&log).unwrap_or_default();
    assert!(argv.contains("docker ps") && argv.contains("--size"), "docker ps must request sizes: {argv}");
    assert_eq!(audit.docker.exited_containers.len(), 1);
    assert_eq!(audit.docker.exited_containers[0].size_bytes, 5_000_000);
    assert!(argv.contains("podman ps") && argv.lines().any(|l| l.starts_with("podman ps") && l.contains("--size")), "{argv}");
    assert_eq!(audit.podman.exited_containers.len(), 1);
    assert_eq!(audit.podman.exited_containers[0].size_bytes, 7_000_000);
}

const SECRETS: [&str; 6] = [
    "PROBE_NAME_SECRET",
    "PROBE_IMAGE_SECRET",
    "PROBE_STATUS_SECRET",
    "PROBE_STATE_SECRET",
    "PROBE_UNIT_DESC_SECRET",
    "PROBE_UNIT_NAME_SECRET",
];

fn assert_no_secrets(label: &str, text: &str) {
    for s in SECRETS {
        assert!(!text.contains(s), "{label} leaked {s}: {text}");
    }
}

/// PR #18 probe review (c): container metadata and systemd descriptions are free text.
#[test]
fn container_metadata_never_reaches_output_unredacted() {
    let rows = [
        r#"{"ID":"abc123","Names":"worker --token=PROBE_NAME_SECRET","Image":"user:PROBE_IMAGE_SECRET@registry.example.com/app:1","Status":"Exited (0) 2 days ago sk-ant-PROBE_STATUS_SECRET","State":"exited PROBE_STATE_SECRET"}"#,
        r#"{"ID":"-f","Names":"flaglike","Image":"x","Status":"Exited (0) 1 day ago","State":"exited"}"#,
        r#"{"ID":"ok1","Names":"plain_name-1","Image":"nginx:1.27","Status":"Exited (0) 3 days ago","State":"exited"}"#,
    ]
    .join("\n");
    let docker = sj_core::linux::parse_docker_containers(&rows);
    let json = serde_json::to_string(&docker).unwrap();
    assert_no_secrets("docker containers", &json);
    assert!(docker.iter().all(|c| !c.id.starts_with('-')), "flag-like container ids must be dropped: {json}");
    let ok = docker.iter().find(|c| c.id == "ok1").expect("plain container kept");
    assert_eq!(ok.name, "plain_name-1");
    assert_eq!(ok.image, "nginx:1.27");
    assert_eq!(ok.status, "Exited (0) 3 days ago");

    let podman_raw = r#"[{"Id":"p1","Names":["pod-PROBE_NAME_SECRET=1"],"Image":"quay.io/app:PROBE_IMAGE_SECRET@x","State":"exited","Status":"Exited (0) 5d ago PROBE_STATUS_SECRET"}]"#;
    let podman = sj_core::linux::parse_podman_ps(podman_raw);
    assert_no_secrets("podman containers", &serde_json::to_string(&podman).unwrap());

    let units = "PROBE_UNIT_NAME_SECRET=x.service loaded failed failed Backup --password=PROBE_UNIT_DESC_SECRET\nok.service loaded failed failed Plain description\n";
    let issues = sj_core::linux::parse_systemctl_failed(units, "system");
    assert_no_secrets("systemd units", &serde_json::to_string(&issues).unwrap());
    assert!(issues.iter().any(|u| u.unit == "ok.service"));
}

/// End to end: shimmed runtime output goes through audit + plan and nothing leaks.
#[test]
fn shimmed_runtime_secrets_do_not_reach_audit_or_plan_output() {
    let td = tempfile::tempdir().unwrap();
    let shims = td.path().join("bin");
    fs::create_dir_all(&shims).unwrap();
    write_shim(
        &shims,
        "docker",
        r#"case "$1" in
 ps) echo '{"ID":"abc123","Names":"w --token=PROBE_NAME_SECRET","Image":"x:PROBE_IMAGE_SECRET@h","Status":"Exited (0) 2 days ago PROBE_STATUS_SECRET","State":"exited","Size":"1MB"}';;
 inspect) echo exited;;
esac"#,
    );
    write_shim(&shims, "podman", "echo '[]'");
    let home = td.path().join("home");
    let tmp = td.path().join("tmp");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&tmp).unwrap();
    let audit = with_path(&shims, || sj_core::linux::discover_linux_audit(&home, Some(&tmp)));
    assert_eq!(audit.docker.exited_containers.len(), 1);
    assert_no_secrets("audit json", &serde_json::to_string(&audit).unwrap());
}
