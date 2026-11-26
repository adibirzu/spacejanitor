//! Shared fixtures for the git-proof hardening probes (B35/B36/B37): real git repositories, git
//! shims and a fake attacker proxy. No credential literal exists in source: everything that looks
//! like a secret is assembled at runtime.
#![allow(dead_code)]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Serialises tests that mutate the process environment.
pub static ENV_LOCK: Mutex<()> = Mutex::new(());

pub fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Probe")
        .env("GIT_AUTHOR_EMAIL", "probe@example.invalid")
        .env("GIT_COMMITTER_NAME", "Probe")
        .env("GIT_COMMITTER_EMAIL", "probe@example.invalid")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {:?} failed in {}: {}",
        args,
        dir.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A clean repository whose only branch is pushed to a local bare remote.
pub fn clean_pushed_repo(root: &Path, name: &str) -> PathBuf {
    let remote = root.join("remotes").join(format!("{name}.git"));
    fs::create_dir_all(&remote).unwrap();
    git(&remote, &["init", "--bare"]);
    let ws = root.join("ws");
    fs::create_dir_all(&ws).unwrap();
    git(&ws, &["clone", remote.to_str().unwrap(), name]);
    let repo = ws.join(name);
    fs::write(repo.join("README.md"), "hello\n").unwrap();
    git(&repo, &["add", "README.md"]);
    git(&repo, &["commit", "-m", "init"]);
    git(&repo, &["push", "-u", "origin", "HEAD"]);
    repo
}

#[cfg(unix)]
pub fn write_script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Fake attacker proxy: answers every request with a Basic auth challenge and records the raw
/// request bytes, so a client that follows the challenge with credentials is caught red-handed.
pub struct AttackerProxy {
    pub port: u16,
    stop: Arc<AtomicBool>,
    captured: Arc<Mutex<Vec<String>>>,
}

impl AttackerProxy {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let captured = Arc::new(Mutex::new(Vec::new()));
        let (s2, c2) = (stop.clone(), captured.clone());
        std::thread::spawn(move || {
            while !s2.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut conn, _)) => {
                        let _ = conn.set_nonblocking(false);
                        let _ = conn.set_read_timeout(Some(Duration::from_millis(500)));
                        let mut buf = vec![0u8; 8192];
                        let n = conn.read(&mut buf).unwrap_or(0);
                        c2.lock()
                            .unwrap()
                            .push(String::from_utf8_lossy(&buf[..n]).into_owned());
                        let _ = conn.write_all(
                            b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"x\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        Self {
            port,
            stop,
            captured,
        }
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn requests(&self) -> Vec<String> {
        self.captured.lock().unwrap().clone()
    }

    pub fn saw_credentials(&self) -> bool {
        self.requests()
            .iter()
            .any(|r| r.to_ascii_lowercase().contains("authorization:"))
    }
}

impl Drop for AttackerProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// A user-level gitconfig with a credential helper that would answer any prompt. The password is
/// assembled at runtime so no secret-shaped literal exists in the repository.
pub fn write_user_gitconfig_with_helper(path: &Path) {
    let pw = format!("{}{}", "probe-pass-", 42 * 1000 + 7);
    fs::write(
        path,
        format!(
            "[credential]\n\thelper = \"!f() {{ echo username=probeuser; echo password={pw}; }}; f\"\n"
        ),
    )
    .unwrap();
}

pub fn pid_alive(pid: i32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
