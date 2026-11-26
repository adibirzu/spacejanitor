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
