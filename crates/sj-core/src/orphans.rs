use crate::protect::{
    check_dir_descendants_safe_logical, check_path_protection_anchored, is_quarantine_stage_name,
    is_symlink_path, ProtectionContext, ProtectionVerdict,
};
use crate::{SjError, SCHEMA_ORPHANS_V1};
use jwalk::WalkDir;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Hard per-git-call timeout and per-repo proof budget. A proof that cannot finish fails closed.
const GIT_CALL_TIMEOUT: Duration = Duration::from_secs(25);
const REPO_PROOF_BUDGET: Duration = Duration::from_secs(90);
/// Wall-clock cap for a whole scan (all repositories together).
const SCAN_BUDGET: Duration = Duration::from_secs(300);
/// Most distinct tag/worktree-ref/reflog commits one repository may carry before the proof refuses
/// with `too_many_local_commits_to_verify` (checked in batches, so this is a memory bound, not an
/// accuracy trade-off).
const MAX_EXTRA_COMMITS: usize = 200_000;

/// Time limits for git proofs. Every git call is bounded, every repository is bounded, and the
/// whole scan is bounded; anything that cannot finish in time fails closed (never "safe").
#[derive(Debug, Clone, Copy)]
pub struct ProofLimits {
    pub call_timeout: Duration,
    pub repo_budget: Duration,
    pub scan_budget: Duration,
    pub max_extra_commits: usize,
}

impl Default for ProofLimits {
    fn default() -> Self {
        Self {
            call_timeout: GIT_CALL_TIMEOUT,
            repo_budget: REPO_PROOF_BUDGET,
            scan_budget: SCAN_BUDGET,
            max_extra_commits: MAX_EXTRA_COMMITS,
        }
    }
}

thread_local! {
    static ACTIVE_LIMITS: std::cell::Cell<ProofLimits> = std::cell::Cell::new(ProofLimits::default());
    static SCAN_DEADLINE: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}

fn active_limits() -> ProofLimits {
    ACTIVE_LIMITS.with(|l| l.get())
}

fn scan_deadline_passed() -> bool {
    SCAN_DEADLINE.with(|d| d.get()).is_some_and(|d| Instant::now() >= d)
}

/// Installs the limits and the scan-wide deadline for this thread and restores the previous state
/// on drop, so nested or later calls (e.g. the pre-removal re-validation) are unaffected.
struct ScanScope {
    prev_limits: ProofLimits,
    prev_deadline: Option<Instant>,
    _home: HomeLease,
}

impl ScanScope {
    fn enter(limits: ProofLimits) -> Self {
        let prev_limits = ACTIVE_LIMITS.with(|l| l.replace(limits));
        let prev_deadline =
            SCAN_DEADLINE.with(|d| d.replace(Some(Instant::now() + limits.scan_budget)));
        Self { prev_limits, prev_deadline, _home: HomeLease::acquire() }
    }
}

impl Drop for ScanScope {
    fn drop(&mut self) {
        ACTIVE_LIMITS.with(|l| l.set(self.prev_limits));
        SCAN_DEADLINE.with(|d| d.set(self.prev_deadline));
    }
}

#[derive(Debug, Clone)]
pub struct OrphanOptions {
    pub max_depth: usize,
}

impl Default for OrphanOptions {
    fn default() -> Self {
        Self { max_depth: 5 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrphanCandidate {
    pub path: String,
    pub is_worktree: bool,
    pub branch: Option<String>,
    pub head: Option<String>,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockedOrphan {
    pub path: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrphansReport {
    pub schema: String,
    pub root: String,
    pub candidates_scanned: usize,
    pub safe_to_prune: Vec<OrphanCandidate>,
    pub blocked: Vec<BlockedOrphan>,
}

struct GitExecContext {
    work_tree: PathBuf,
    git_dir: PathBuf,
    alternate_object_dirs: Option<OsString>,
}

fn anchor_to_cwd(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        let cwd = std::env::current_dir().map_err(|_| "unresolvable_current_dir".to_string())?;
        Ok(cwd.join(path))
    }
}

fn resolve_relative_from_dir(base_dir: &Path, rel: &Path) -> PathBuf {
    if rel.is_absolute() {
        return rel.to_path_buf();
    }
    if base_dir.exists() {
        return base_dir.join(rel);
    }
    let mut missing: Vec<OsString> = Vec::new();
    for anc in base_dir.ancestors() {
        if anc.as_os_str().is_empty() {
            break;
        }
        if let Ok(canon) = std::fs::canonicalize(anc) {
            let mut out = canon;
            let mut pending_missing: Vec<OsString> = missing.into_iter().rev().collect();
            let mut comps = rel.components();
            while !pending_missing.is_empty() {
                match comps.next() {
                    None => break,
                    Some(Component::CurDir) => {}
                    Some(Component::ParentDir) => {
                        pending_missing.pop();
                    }
                    Some(Component::Normal(s)) => {
                        pending_missing.push(s.to_os_string());
                    }
                    Some(other) => {
                        for seg in pending_missing.drain(..) {
                            out.push(seg);
                        }
                        out.push(other.as_os_str());
                        break;
                    }
                }
            }
            for seg in pending_missing {
                out.push(seg);
            }
            for rest in comps {
                out.push(rest.as_os_str());
            }
            return out;
        }
        if let Some(comp) = anc.components().next_back() {
            match comp {
                Component::Normal(s) => missing.push(s.to_os_string()),
                Component::ParentDir => missing.push(OsString::from("..")),
                _ => {}
            }
        }
    }
    base_dir.join(rel)
}

/// Git config keys (lowercased `section.subsection.key`) that can make git EXECUTE a command or be
/// steered somewhere else during a read-only proof. Shared vectors:
/// crates/sj-core/tests/fixtures/exec_config_keys.json.
pub fn executable_config_key(key: &str) -> Option<String> {
    let k = key.to_ascii_lowercase();
    let ends = |suffixes: &[&str]| suffixes.iter().any(|s| k.ends_with(&format!(".{s}")));
    let hit = (k.starts_with("filter.") && ends(&["clean", "smudge", "process"]))
        || (k.starts_with("remote.") && ends(&["uploadpack", "receivepack", "vcs", "proxy"]))
        || matches!(
            k.as_str(),
            "core.sshcommand" | "core.gitproxy" | "core.askpass" | "core.pager" | "core.editor"
                | "core.alternaterefscommand" | "diff.external" | "gpg.program"
                | "http.proxy" | "http.sslcertpasswordprotected"
        )
        // URL-scoped http.<url>.* (proxy, sslVerify, sslCAInfo, extraHeader, ...) is MORE specific than
        // anything we pass with -c, so it would win; block every http.* key except the plain
        // `http.sslverify`, which our own `-c http.sslVerify=true` overrides.
        || (k.starts_with("http.") && k != "http.sslverify")
        || k.starts_with("https.")
        // protocol.<scheme>.allow is more specific than our `-c protocol.allow=never` and would
        // re-enable any git-remote-<scheme> helper (or fd::); only protocol.version is harmless
        || (k.starts_with("protocol.") && k != "protocol.version")
        || k.starts_with("credential.")
        || (k.starts_with("url.") && ends(&["insteadof", "pushinsteadof"]))
        || k.starts_with("include.")
        || k.starts_with("includeif.")
        || (k.starts_with("diff.") && ends(&["textconv", "command"]))
        || (k.starts_with("gpg.") && ends(&["program"]))
        || k.starts_with("uploadpack.")
        || k.starts_with("ssh.")
        // git-lfs runs `lfs.extension.<n>.clean/smudge` commands from config and spawns
        // `lfs.customtransfer.<n>.path`: allowing the lfs FILTER must not open these doors
        || k.starts_with("lfs.extension.")
        || k.starts_with("lfs.customtransfer.")
        || k == "lfs.standalonetransferagent";
    hit.then_some(k)
}

/// Exact filter command lines `git lfs install` writes, per slot. Matched whole, never by prefix,
/// so nothing can be appended (`; cmd`, `&& cmd`, `$(cmd)`, a path-qualified binary).
const BENIGN_LFS_FILTERS: &[(&str, &[&str])] = &[
    ("clean", &["git-lfs clean -- %f"]),
    ("smudge", &["git-lfs smudge -- %f", "git-lfs smudge --skip -- %f"]),
    ("process", &["git-lfs filter-process", "git-lfs filter-process --skip"]),
];

/// Credential helper values that name a stock helper (resolved as `git-credential-<name>`, never an
/// arbitrary path or shell snippet) plus the one very common `gh` form.
const BENIGN_CREDENTIAL_HELPERS: &[&str] = &[
    "",
    "osxkeychain",
    "store",
    "cache",
    "manager",
    "manager-core",
    "libsecret",
    "wincred",
    "!gh auth git-credential",
];

fn benign_credential_helper(v: &str) -> bool {
    if BENIGN_CREDENTIAL_HELPERS.contains(&v) {
        return true;
    }
    // `cache --timeout=<seconds>`: the only argument form we vouch for
    v.strip_prefix("cache --timeout=")
        .is_some_and(|n| !n.is_empty() && n.len() <= 8 && n.chars().all(|c| c.is_ascii_digit()))
}

/// Entry-level verdict: like [`executable_config_key`] but with the value in hand, so the KNOWN
/// benign forms (git-lfs filters, stock credential helpers) are not over-blocked while anything that
/// can run an attacker-chosen command still is. `value` is `None` for a valueless (boolean) key.
pub fn executable_config_entry(key: &str, value: Option<&str>) -> Option<String> {
    let hit = executable_config_key(key)?;
    let benign = match value {
        None => false,
        Some(v) => {
            let filter_ok = hit.starts_with("filter.")
                && BENIGN_LFS_FILTERS
                    .iter()
                    .any(|(slot, vals)| hit.ends_with(&format!(".{slot}")) && vals.contains(&v));
            let helper_ok = hit.starts_with("credential.")
                && hit.ends_with(".helper")
                && benign_credential_helper(v);
            filter_ok || helper_ok
        }
    };
    (!benign).then_some(hit)
}

/// The scrubbed git environment's private HOME (empty, so curl finds no `~/.netrc`) plus the
/// sanitized user gitconfig that lives inside it. Created lazily, shared by nested [`HomeLease`]s on
/// one thread, and REMOVED when the last lease drops, whatever way the scope ends (success, `?`,
/// timeout, panic).
#[derive(Default)]
struct HomeState {
    depth: usize,
    dir: Option<PathBuf>,
    gitconfig: Option<PathBuf>,
}

thread_local! {
    static HOME: std::cell::RefCell<HomeState> = std::cell::RefCell::new(HomeState::default());
}

pub(crate) struct HomeLease;

impl HomeLease {
    pub(crate) fn acquire() -> Self {
        HOME.with(|h| h.borrow_mut().depth += 1);
        Self
    }
}

impl Drop for HomeLease {
    fn drop(&mut self) {
        let dir = HOME.with(|h| {
            let mut h = h.borrow_mut();
            h.depth = h.depth.saturating_sub(1);
            if h.depth == 0 {
                h.gitconfig = None;
                h.dir.take()
            } else {
                None
            }
        });
        if let Some(dir) = dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

fn create_private_dir() -> Option<PathBuf> {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("sj-git-home-{}-{nanos}-{seq}", std::process::id()));
    // create_dir (not create_dir_all): never adopt a pre-existing, possibly attacker-owned dir
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(&dir).ok().map(|_| dir)
}

/// The HOME for the next scrubbed git call. Outside any lease nothing is created or leaked: a
/// nonexistent path is just as empty for curl.
fn empty_home_dir() -> PathBuf {
    let existing = HOME.with(|h| {
        let h = h.borrow();
        (h.depth > 0).then(|| h.dir.clone())
    });
    match existing {
        Some(Some(dir)) => dir,
        Some(None) => match create_private_dir() {
            Some(dir) => {
                HOME.with(|h| h.borrow_mut().dir = Some(dir.clone()));
                dir
            }
            None => unleased_home(),
        },
        None => unleased_home(),
    }
}

fn unleased_home() -> PathBuf {
    std::env::temp_dir().join(format!("sj-no-home-{}", std::process::id()))
}

/// Non-executable user settings that change how git SEES the working tree (line endings). Without
/// them every clean checkout made with `core.autocrlf=true` (the Git for Windows default) would
/// look modified. Copied by value into a private file that replaces the user's global config, so
/// no other user key (credential helpers, proxies, filters, aliases) is ever honoured.
const USER_CONFIG_ALLOWLIST: &[&str] = &["core.autocrlf", "core.eol", "core.safecrlf"];

fn sanitized_user_config() -> PathBuf {
    if let Some(path) = HOME.with(|h| h.borrow().gitconfig.clone()) {
        return path;
    }
    let home = empty_home_dir();
    let leased = HOME.with(|h| h.borrow().dir.as_ref() == Some(&home));
    if !leased {
        // no lease: honour NO user config at all (the strictest answer)
        return PathBuf::from(NULL_DEVICE);
    }
    let path = home.join("gitconfig");
    let mut body = String::from("[core]\n");
    for key in USER_CONFIG_ALLOWLIST {
        let mut cmd = Command::new("git");
        cmd.current_dir(&home)
            .args(["config", "--get", key])
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .stdin(Stdio::null())
            .stderr(Stdio::null());
        if let Ok(out) = cmd.output() {
            let val = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let simple =
                !val.is_empty() && val.len() < 16 && val.chars().all(|c| c.is_ascii_alphanumeric());
            if out.status.success() && simple {
                let name = key.trim_start_matches("core.");
                body.push_str(&format!("\t{name} = {val}\n"));
            }
        }
    }
    let _ = std::fs::write(&path, body);
    HOME.with(|h| h.borrow_mut().gitconfig = Some(path.clone()));
    path
}

const NULL_DEVICE: &str = if cfg!(windows) { "NUL" } else { "/dev/null" };

/// A `git` command with a SCRUBBED environment and config: nothing is inherited except the few
/// variables git/ssh need to run (`PATH`, `HOME`, `SSH_AUTH_SOCK`, Windows system dirs). No
/// global/system config, no proxy variables, no credential helpers, no askpass, no hooks, no
/// fsmonitor, no submodule recursion. Repo-controlled config that could still steer git is gated
/// separately by `executable_config_risk` before any proof call.
fn scrubbed_git() -> Command {
    let mut cmd = Command::new("git");
    cmd.env_clear();
    // HOME/USERPROFILE point at an EMPTY directory: curl would otherwise read ~/.netrc and send those
    // credentials to whatever host a hostile repo names. ssh resolves `~` through the passwd entry,
    // so its keys and known_hosts are unaffected.
    let empty_home = empty_home_dir();
    cmd.env("HOME", &empty_home).env("USERPROFILE", &empty_home);
    for key in [
        "PATH", "SSH_AUTH_SOCK", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR",
    ] {
        if let Some(v) = std::env::var_os(key) {
            cmd.env(key, v);
        }
    }
    cmd.env("GIT_CONFIG_GLOBAL", sanitized_user_config())
        .env("GIT_CONFIG_SYSTEM", NULL_DEVICE)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "")
        .env("SSH_ASKPASS", "")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes")
        .env("LC_ALL", "C")
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            &format!("core.hooksPath={NULL_DEVICE}"),
            "-c",
            "protocol.ext.allow=never",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.file.allow=always",
            "-c",
            "protocol.http.allow=always",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "protocol.ssh.allow=always",
            "-c",
            "protocol.git.allow=always",
            "-c",
            &format!("core.attributesFile={NULL_DEVICE}"),
            "-c",
            &format!("core.excludesFile={NULL_DEVICE}"),
            "-c",
            "credential.helper=",
            "-c",
            "http.proxy=",
            "-c",
            "http.sslVerify=true",
            "-c",
            "submodule.recurse=false",
            "-c",
            "status.submoduleSummary=false",
            "-c",
            "diff.ignoreSubmodules=all",
        ]);
    cmd
}

/// Read a small text file that must be a regular, non-symlink file. Opening is non-blocking so a
/// FIFO planted in its place can never hang the scan, and the type is checked on the open handle.
fn read_regular_text(path: &Path) -> Result<String, String> {
    const MAX: u64 = 1 << 20;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let f = opts.open(path).map_err(|_| "unreadable".to_string())?;
    let meta = f.metadata().map_err(|_| "unreadable".to_string())?;
    if !meta.is_file() {
        return Err("non_regular_file".to_string());
    }
    let mut buf = String::new();
    f.take(MAX)
        .read_to_string(&mut buf)
        .map_err(|_| "unreadable".to_string())?;
    Ok(buf)
}

/// Parse (never execute) the repo-local and per-worktree config and return the first key that could
/// run a command. An unreadable config fails closed.
fn executable_config_risk(git_ctx: &GitExecContext) -> Option<String> {
    const UNREADABLE: &str = "repo_config_can_execute:unreadable_config";
    let mut common = git_ctx.git_dir.clone();
    let commondir = git_ctx.git_dir.join("commondir");
    if std::fs::symlink_metadata(&commondir).is_ok() {
        let Ok(rel) = read_regular_text(&commondir) else {
            return Some(UNREADABLE.to_string());
        };
        let rel = rel.trim();
        if !rel.is_empty() {
            common = resolve_relative_from_dir(&git_ctx.git_dir, Path::new(rel));
        }
    }
    for name in ["info/attributes", "info/exclude"] {
        let f = common.join(name);
        match std::fs::symlink_metadata(&f) {
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(_) => return Some(UNREADABLE.to_string()),
            Ok(_) => {
                if read_regular_text(&f).is_err() {
                    return Some(UNREADABLE.to_string());
                }
            }
        }
    }
    let mut files = vec![common.join("config")];
    let wt_cfg = git_ctx.git_dir.join("config.worktree");
    if std::fs::symlink_metadata(&wt_cfg).is_ok() {
        files.push(wt_cfg);
    }
    for f in files {
        match std::fs::symlink_metadata(&f) {
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(_) => return Some(UNREADABLE.to_string()),
            Ok(_) => {}
        }
        // a FIFO/device/symlink at the config path must never reach `git config --file`, which
        // would block on it: check the type on an O_NONBLOCK handle first
        if read_regular_text(&f).is_err() {
            return Some(UNREADABLE.to_string());
        }
        let mut cmd = scrubbed_git();
        cmd.args(["config", "--file"])
            .arg(&f)
            .args(["--list", "-z"]);
        let Ok((true, out)) = run_with_timeout(cmd, None, call_timeout()) else {
            return Some(UNREADABLE.to_string());
        };
        // `-z` entries are `key\nvalue\0` (a valueless key has no newline)
        for entry in out.split('\0') {
            if entry.is_empty() {
                continue;
            }
            let (key, value) = match entry.split_once('\n') {
                Some((k, v)) => (k, Some(v)),
                None => (entry, None),
            };
            if let Some(hit) = executable_config_entry(key, value) {
                return Some(format!("repo_config_can_execute:{hit}"));
            }
        }
    }
    None
}

/// Per-call timeout, capped by what is left of the scan-wide deadline. `Duration::ZERO` once the
/// deadline has passed (the call then fails closed immediately).
fn call_timeout() -> Duration {
    let per_call = active_limits().call_timeout;
    match SCAN_DEADLINE.with(|d| d.get()) {
        Some(deadline) => per_call.min(deadline.saturating_duration_since(Instant::now())),
        None => per_call,
    }
}

/// Run a command with a hard timeout, optional stdin, and stdout capture on a reader thread (so a
/// large output cannot deadlock the wait loop). Timeout kills the child and reports `git_timeout`.
fn run_with_timeout(
    mut cmd: Command,
    input: Option<Vec<u8>>,
    timeout: Duration,
) -> Result<(bool, String), SjError> {
    if timeout.is_zero() {
        return Err(SjError::Git("git_timeout".to_string()));
    }
    cmd.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    crate::proc_tree::configure(&mut cmd);
    let mut child = cmd.spawn()?;
    // Dropping `tree` kills everything git spawned on EVERY exit path (success, error, timeout).
    let tree = match crate::proc_tree::ProcTree::adopt(&child) {
        Ok(t) => t,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SjError::Git(format!("git_containment_failed:{e}")));
        }
    };
    if let (Some(data), Some(mut si)) = (input, child.stdin.take()) {
        std::thread::spawn(move || {
            let _ = si.write_all(&data);
        });
    }
    let mut so = child
        .stdout
        .take()
        .ok_or_else(|| SjError::Git("git_stdout_unavailable".to_string()))?;
    let (out_tx, out_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = so.read_to_end(&mut buf);
        let _ = out_tx.send(buf);
    });
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait()? {
            Some(status) => {
                // git is gone; reap anything it left holding our pipes so the join cannot block
                tree.kill();
                // bounded: a descendant that escaped the group (setsid) may still hold the pipe
                let left = deadline.saturating_duration_since(Instant::now());
                let out = out_rx
                    .recv_timeout(left.max(Duration::from_millis(250)))
                    .map_err(|_| SjError::Git("git_timeout".to_string()))?;
                return Ok((status.success(), String::from_utf8_lossy(&out).into_owned()));
            }
            None => {
                if Instant::now() >= deadline {
                    tree.kill();
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(SjError::Git("git_timeout".to_string()));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

fn run_git_raw_ctx<I, S>(git_ctx: &GitExecContext, args: I) -> Result<(bool, String), SjError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_git_raw_ctx_in(git_ctx, args, None)
}

fn run_git_raw_ctx_in<I, S>(
    git_ctx: &GitExecContext,
    args: I,
    input: Option<Vec<u8>>,
) -> Result<(bool, String), SjError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = scrubbed_git();
    cmd.current_dir(&git_ctx.work_tree)
        .arg("--no-optional-locks")
        .arg("--git-dir")
        .arg(&git_ctx.git_dir)
        .arg("--work-tree")
        .arg(&git_ctx.work_tree)
        .args(args);
    if let Some(ref alt) = git_ctx.alternate_object_dirs {
        cmd.env("GIT_ALTERNATE_OBJECT_DIRECTORIES", alt);
    }
    run_with_timeout(cmd, input, call_timeout())
}

/// Of the given object ids, keep those that exist in this repository (remote tips we never fetched
/// cannot be negative revs).
fn present_objects(git_ctx: &GitExecContext, ids: &[String]) -> Vec<String> {
    if ids.is_empty() {
        return Vec::new();
    }
    let input = ids.join("\n") + "\n";
    let Ok((true, out)) = run_git_raw_ctx_in(git_ctx, ["cat-file", "--batch-check"], Some(input.into_bytes()))
    else {
        return Vec::new();
    };
    out.lines()
        .filter(|l| !l.ends_with(" missing"))
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// How many of `shas` are NOT reachable from any of `tips` (plus `extra_not` pseudo-args such as
/// `--reflog`). One git process for any number of commits; Err(()) = could not be determined.
fn count_unreachable(
    git_ctx: &GitExecContext,
    shas: &[String],
    tips: &[String],
    pre_args: &[&str],
    not_args: &[&str],
) -> Result<u64, ()> {
    // Batches bound each git process's stdin; every sha is judged independently of the others, so
    // the per-batch counts simply add up. The per-call timeout and the scan deadline still apply to
    // every batch (a repository too large to finish in time fails closed, never "safe").
    const BATCH: usize = 5_000;
    let mut total = 0u64;
    for chunk in shas.chunks(BATCH) {
        total = total.saturating_add(count_unreachable_batch(git_ctx, chunk, tips, pre_args, not_args)?);
    }
    Ok(total)
}

fn count_unreachable_batch(
    git_ctx: &GitExecContext,
    shas: &[String],
    tips: &[String],
    pre_args: &[&str],
    not_args: &[&str],
) -> Result<u64, ()> {
    if shas.is_empty() {
        return Ok(0);
    }
    let mut input = String::new();
    for s in shas {
        input.push_str(s);
        input.push('\n');
    }
    for t in tips {
        input.push('^');
        input.push_str(t);
        input.push('\n');
    }
    let mut args: Vec<&str> = vec!["rev-list", "--count"];
    args.extend_from_slice(pre_args);
    args.push("--stdin");
    if !not_args.is_empty() {
        args.push("--not");
        args.extend_from_slice(not_args);
    }
    match run_git_raw_ctx_in(git_ctx, args, Some(input.into_bytes())) {
        Ok((true, out)) => out.trim().parse::<u64>().map_err(|_| ()),
        _ => Err(()),
    }
}

fn run_git_ctx<I, S>(git_ctx: &GitExecContext, args: I) -> Result<(bool, String), SjError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let (ok, raw) = run_git_raw_ctx(git_ctx, args)?;
    Ok((ok, raw.trim().to_string()))
}

fn sha256_hex_str(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Commits that removing the repo/worktree could orphan besides refs/heads: (a) tags and the
/// per-worktree ref namespaces (refs/worktree, refs/bisect, refs/rewritten) and (b) this checkout's
/// HEAD reflog (commits made on a detached HEAD and then left behind). Err = could not enumerate.
fn collect_extra_local_commits(
    git_ctx: &GitExecContext,
) -> Result<(Vec<String>, Vec<String>), String> {
    let (ok, out) = run_git_raw_ctx(
        git_ctx,
        [
            "for-each-ref",
            "--format=%(objectname)",
            "refs/tags",
            "refs/worktree",
            "refs/bisect",
            "refs/rewritten",
        ],
    )
    .map_err(|_| "git_for_each_ref_failed".to_string())?;
    if !ok {
        return Err("git_for_each_ref_failed".to_string());
    }
    let refs: BTreeSet<String> = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    let (rok, rout) = run_git_raw_ctx(git_ctx, ["reflog", "show", "--format=%H", "HEAD"])
        .map_err(|_| "git_reflog_failed".to_string())?;
    if !rok {
        return Err("git_reflog_failed".to_string());
    }
    let reflog: BTreeSet<String> = rout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    if refs.len() + reflog.len() > active_limits().max_extra_commits {
        return Err("too_many_local_commits_to_verify".to_string());
    }
    if refs
        .iter()
        .chain(reflog.iter())
        .any(|s| !s.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err("malformed_ref_listing".to_string());
    }
    Ok((refs.into_iter().collect(), reflog.into_iter().collect()))
}

/// The common git dir of a LINKED worktree (`<git_dir>/commondir`), canonical. None for a git dir
/// that is itself the common one (a standalone repository or a `.git` file pointing at one).
fn linked_common_dir(git_dir: &Path) -> Option<PathBuf> {
    let rel = read_regular_text(&git_dir.join("commondir")).ok()?;
    let rel = rel.trim();
    if rel.is_empty() {
        return None;
    }
    // canonical, so `wt/.git/../..` style relative pointers become the real directory
    std::fs::canonicalize(resolve_relative_from_dir(git_dir, Path::new(rel))).ok()
}

/// Git context for the SHARED git dir of a linked worktree (its branch reflogs live there and
/// survive the worktree being removed). None for a standalone repo. The work tree handed to git is
/// the main checkout for a normal repository and the common dir ITSELF for a bare one: never a
/// guessed parent directory (those git calls only read refs and reflogs, never the work tree).
fn shared_git_ctx(git_ctx: &GitExecContext) -> Option<GitExecContext> {
    let common = linked_common_dir(&git_ctx.git_dir)?;
    let work_tree = match common.file_name() {
        Some(n) if n == ".git" => common.parent().map(Path::to_path_buf).unwrap_or_else(|| common.clone()),
        _ => common.clone(),
    };
    Some(GitExecContext {
        work_tree,
        git_dir: common,
        alternate_object_dirs: None,
    })
}

/// True when the repository's own config says `core.bare = true`. Read by PARSING the file (never
/// by running anything repo-controlled); anything unreadable counts as bare (fail closed).
fn common_dir_is_bare(common: &Path) -> bool {
    let mut cmd = scrubbed_git();
    cmd.args(["config", "--file"])
        .arg(common.join("config"))
        .args(["--bool", "--get", "core.bare"]);
    match run_with_timeout(cmd, None, call_timeout()) {
        Ok((true, out)) => out.trim() == "true",
        // exit 1 = key not set (not bare); a spawn/timeout failure is "cannot tell"
        Ok((false, _)) => false,
        Err(_) => true,
    }
}

/// Linked worktrees of this repository as (path, locked) from `git worktree list --porcelain`.
fn list_worktrees(git_ctx: &GitExecContext) -> Result<Vec<(String, bool)>, String> {
    let (ok, out) = run_git_raw_ctx(git_ctx, ["worktree", "list", "--porcelain"])
        .map_err(|_| "git_worktree_list_failed".to_string())?;
    if !ok {
        return Err("git_worktree_list_failed".to_string());
    }
    let mut entries: Vec<(String, bool)> = Vec::new();
    for line in out.lines() {
        if let Some(p) = line.strip_prefix("worktree ") {
            entries.push((p.to_string(), false));
        } else if line == "locked" || line.starts_with("locked ") {
            if let Some(last) = entries.last_mut() {
                last.1 = true;
            }
        }
    }
    Ok(entries)
}

fn snapshot_local_branches(git_ctx: &GitExecContext) -> Result<Vec<(String, String)>, String> {
    let (ok, out) = run_git_raw_ctx(
        git_ctx,
        [
            "for-each-ref",
            "--format=%(refname)%09%(objectname)",
            "refs/heads",
        ],
    )
    .map_err(|_| "git_for_each_ref_failed".to_string())?;
    if !ok {
        return Err("git_for_each_ref_failed".to_string());
    }
    let mut branches = Vec::new();
    for line in out.lines() {
        if line.is_empty() {
            continue;
        }
        let Some((refname, sha)) = line.split_once('\t') else {
            return Err("malformed_for_each_ref".to_string());
        };
        if refname.is_empty() || sha.is_empty() || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("malformed_for_each_ref".to_string());
        }
        branches.push((refname.to_string(), sha.to_string()));
    }
    if branches.is_empty() {
        return Err("no_local_branches".to_string());
    }
    branches.sort();
    Ok(branches)
}

pub(crate) fn capture_git_snapshot_identity_staged(
    actual_repo: &Path,
    logical_repo: &Path,
    ctx: &ProtectionContext,
) -> Result<(String, String, String), SjError> {
    let _home = HomeLease::acquire();
    let (git_ctx, _) =
        build_git_exec_context(actual_repo, logical_repo, ctx).map_err(SjError::Git)?;
    let (head_ok, head) = run_git_ctx(&git_ctx, ["rev-parse", "--verify", "HEAD"])?;
    if !head_ok || head.is_empty() {
        return Err(SjError::Git("failed to resolve HEAD".to_string()));
    }
    let (tree_ok, tree) = run_git_ctx(&git_ctx, ["rev-parse", "--verify", "HEAD^{tree}"])?;
    if !tree_ok || tree.is_empty() {
        return Err(SjError::Git("failed to resolve HEAD^{tree}".to_string()));
    }
    let branches = snapshot_local_branches(&git_ctx).map_err(SjError::Git)?;
    let refs_joined = branches
        .iter()
        .map(|(r, s)| format!("{r}\t{s}"))
        .collect::<Vec<_>>()
        .join("\n");
    let refs_sha = sha256_hex_str(&refs_joined);
    Ok((head, tree, refs_sha))
}

/// Captures `(git_head, git_tree, git_refs_sha256)` for snapshot binding.
pub fn capture_git_snapshot_identity(repo: &Path) -> Result<(String, String, String), SjError> {
    capture_git_snapshot_identity_staged(repo, repo, &ProtectionContext::from_env())
}

fn validate_commondir(gitdir: &Path, ctx: &ProtectionContext) -> Result<(), String> {
    let commondir_file = gitdir.join("commondir");
    match std::fs::symlink_metadata(&commondir_file) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("unreadable_commondir_metadata".to_string()),
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err("symlink_commondir_file".to_string());
            }
            if !meta.is_file() {
                return Err("non_regular_commondir_file".to_string());
            }
        }
    }
    let common_raw =
        read_regular_text(&commondir_file).map_err(|_| "unreadable_commondir".to_string())?;
    let common_trimmed = common_raw.trim();
    if common_trimmed.is_empty() {
        return Err("empty_commondir".to_string());
    }
    let common_path = resolve_relative_from_dir(gitdir, Path::new(common_trimmed));
    if is_symlink_path(&common_path).unwrap_or(true) {
        return Err("symlink_or_missing_commondir".to_string());
    }
    let common_verdict = check_path_protection_anchored(&common_path, ctx);
    if common_verdict.protected {
        return Err(format!("protected_commondir:{}", common_verdict.reason));
    }
    Ok(())
}

fn validate_gitdir_pointer(
    logical_worktree: &Path,
    dot_git_file: &Path,
    ctx: &ProtectionContext,
) -> Result<PathBuf, String> {
    let raw =
        read_regular_text(dot_git_file).map_err(|_| "unreadable_dot_git_file".to_string())?;
    let line = raw
        .lines()
        .find(|l| l.trim_start().starts_with("gitdir:"))
        .ok_or_else(|| "invalid_dot_git_file".to_string())?;
    let target_raw = line.trim_start().trim_start_matches("gitdir:").trim();
    if target_raw.is_empty() {
        return Err("empty_gitdir_pointer".to_string());
    }
    let target = resolve_relative_from_dir(logical_worktree, Path::new(target_raw));
    if is_symlink_path(&target).unwrap_or(true) {
        return Err("symlink_or_missing_gitdir".to_string());
    }
    let verdict = check_path_protection_anchored(&target, ctx);
    if verdict.protected {
        return Err(format!("protected_gitdir:{}", verdict.reason));
    }

    validate_commondir(&target, ctx)?;

    Ok(target)
}

fn resolve_staged_alternates(
    actual_repo: &Path,
    logical_repo: &Path,
) -> Result<Option<OsString>, String> {
    if actual_repo == logical_repo {
        return Ok(None);
    }
    let alternates_file = actual_repo
        .join(".git")
        .join("objects")
        .join("info")
        .join("alternates");
    match std::fs::symlink_metadata(&alternates_file) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("unreadable_alternates_metadata".to_string()),
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err("symlink_alternates_file".to_string());
            }
            if !meta.is_file() {
                return Err("invalid_alternates_file".to_string());
            }
        }
    }
    let raw = std::fs::read_to_string(&alternates_file)
        .map_err(|_| "unreadable_alternates".to_string())?;
    let mut resolved_paths: Vec<PathBuf> = Vec::new();
    let logical_objects = logical_repo.join(".git").join("objects");
    let logical_repo_resolved = resolve_relative_from_dir(logical_repo, Path::new("."));
    let canon_logical = std::fs::canonicalize(logical_repo).ok();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let p = Path::new(trimmed);
        if p.is_absolute() {
            resolved_paths.push(p.to_path_buf());
        } else {
            let resolved = resolve_relative_from_dir(&logical_objects, p);
            let rel_inside = match (
                canon_logical.as_ref(),
                std::fs::canonicalize(&resolved).ok(),
            ) {
                (Some(cl), Some(cr)) => cr.strip_prefix(cl).ok().map(Path::to_path_buf),
                _ => resolved
                    .strip_prefix(&logical_repo_resolved)
                    .or_else(|_| resolved.strip_prefix(logical_repo))
                    .ok()
                    .filter(|rel| !rel.components().any(|c| matches!(c, Component::ParentDir)))
                    .map(Path::to_path_buf),
            };
            if let Some(rel_inside) = rel_inside {
                resolved_paths.push(actual_repo.join(rel_inside));
            } else {
                resolved_paths.push(resolved);
            }
        }
    }
    if resolved_paths.is_empty() {
        Ok(None)
    } else {
        std::env::join_paths(&resolved_paths)
            .map(Some)
            .map_err(|_| "invalid_alternates_path".to_string())
    }
}

fn build_git_exec_context(
    actual_repo: &Path,
    logical_repo: &Path,
    ctx: &ProtectionContext,
) -> Result<(GitExecContext, bool), String> {
    let actual_abs = anchor_to_cwd(actual_repo)?;
    let logical_abs = anchor_to_cwd(logical_repo)?;
    let dot_git = actual_abs.join(".git");
    let dot_git_meta =
        std::fs::symlink_metadata(&dot_git).map_err(|_| "missing_dot_git".to_string())?;
    if dot_git_meta.file_type().is_symlink() {
        return Err("symlink_dot_git".to_string());
    }
    if dot_git_meta.is_file() {
        let git_dir = validate_gitdir_pointer(&logical_abs, &dot_git, ctx)?;
        Ok((
            GitExecContext {
                work_tree: actual_abs,
                git_dir,
                alternate_object_dirs: None,
            },
            true,
        ))
    } else if dot_git_meta.is_dir() {
        validate_commondir(&dot_git, ctx)?;
        let alternate_object_dirs = resolve_staged_alternates(&actual_abs, &logical_abs)?;
        Ok((
            GitExecContext {
                work_tree: actual_abs,
                git_dir: dot_git,
                alternate_object_dirs,
            },
            false,
        ))
    } else {
        Err("invalid_dot_git".to_string())
    }
}

fn resolve_relative_local_remote(url: &str, logical_repo: &Path) -> Option<PathBuf> {
    let trimmed = url.trim();
    if trimmed.is_empty()
        || trimmed.contains("://")
        || trimmed.starts_with('/')
        || trimmed.starts_with('\\')
        || trimmed.starts_with('~')
    {
        return None;
    }
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return None;
    }
    let first_sep = trimmed.find(['/', '\\']);
    if let Some(colon) = trimmed.find(':') {
        if first_sep.is_none_or(|sep| colon < sep) {
            return None;
        }
    }
    let resolved = resolve_relative_from_dir(logical_repo, Path::new(trimmed));
    if trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed.starts_with(".\\")
        || trimmed.starts_with("..\\")
        || resolved.exists()
    {
        Some(resolved)
    } else {
        None
    }
}

fn dir_bytes_no_follow(path: &Path) -> u64 {
    let mut total = 0u64;
    for entry_res in WalkDir::new(path).follow_links(false).skip_hidden(false) {
        let Ok(entry) = entry_res else {
            continue;
        };
        if entry.file_type().is_file() {
            if let Ok(meta) = entry.metadata() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}

/// True when the repository has (or may have) submodules: a `.gitmodules`, a `.git/modules` dir,
/// or any gitlink (mode 160000) in the index. Unknown (listing failed) counts as "has".
fn has_submodules(git_ctx: &GitExecContext) -> bool {
    if std::fs::symlink_metadata(git_ctx.work_tree.join(".gitmodules")).is_ok()
        || std::fs::symlink_metadata(git_ctx.git_dir.join("modules")).is_ok()
    {
        return true;
    }
    match run_git_raw_ctx(git_ctx, ["ls-files", "--stage", "-z"]) {
        Ok((true, out)) => out.split('\0').any(|e| e.starts_with("160000 ")),
        _ => true,
    }
}

fn validate_single_repo_at(
    actual_repo: &Path,
    logical_repo: &Path,
    ctx: &ProtectionContext,
) -> Result<OrphanCandidate, Vec<String>> {
    let _home = HomeLease::acquire();
    let mut reasons = Vec::new();
    let proof_start = Instant::now();
    if scan_deadline_passed() {
        return Err(vec!["scan_budget_exceeded".to_string()]);
    }

    // The gate rejects relative paths outright; anchor to the cwd WITHOUT touching `..` components
    // (symlink-then-`..` must still be resolved by the OS, not collapsed lexically).
    let prot = match anchor_to_cwd(logical_repo) {
        Ok(abs) => check_path_protection_anchored(&abs, ctx),
        Err(reason) => ProtectionVerdict::deny(reason),
    };
    if prot.protected {
        reasons.push(format!("protected_path:{}", prot.reason));
        return Err(reasons);
    }

    if is_symlink_path(actual_repo).unwrap_or(true) {
        reasons.push("symlink_worktree".to_string());
        return Err(reasons);
    }

    let (git_ctx, is_worktree) = match build_git_exec_context(actual_repo, logical_repo, ctx) {
        Ok(v) => v,
        Err(reason) => {
            reasons.push(reason);
            return Err(reasons);
        }
    };

    // Block BEFORE any git invocation that could execute repo-controlled config.
    if let Some(risk) = executable_config_risk(&git_ctx) {
        reasons.push(risk);
        return Err(reasons);
    }

    // A `.git` FILE that points straight at a bare repository (the `.bare` layout): this directory
    // hosts the bare main repo, and every linked worktree anywhere on disk depends on it. Deleting
    // it would destroy their git metadata and every branch only they hold. Refuse, by name.
    if is_worktree && linked_common_dir(&git_ctx.git_dir).is_none() && common_dir_is_bare(&git_ctx.git_dir) {
        reasons.push("bare_main_repository".to_string());
        return Err(reasons);
    }

    // Submodules carry their OWN config (.git/modules/*/config) that the gate above cannot vouch
    // for, and `git status` would run its filters. Fail closed: a repository with submodules is
    // never offered, and status never recurses into them.
    if has_submodules(&git_ctx) {
        reasons.push("has_submodules".to_string());
        return Err(reasons);
    }

    let Ok((head_ok, head_before)) = run_git_ctx(&git_ctx, ["rev-parse", "--verify", "HEAD"])
    else {
        reasons.push("git_invocation_failed".to_string());
        return Err(reasons);
    };
    if !head_ok || head_before.is_empty() {
        reasons.push("unborn_head".to_string());
    }

    let (sym_ok, sym_ref) =
        run_git_ctx(&git_ctx, ["symbolic-ref", "-q", "HEAD"]).unwrap_or((false, String::new()));
    let branch = if sym_ok && !sym_ref.is_empty() {
        Some(sym_ref)
    } else {
        reasons.push("detached_head".to_string());
        None
    };

    let (status_ok, status_out) = run_git_raw_ctx(
        &git_ctx,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=traditional",
            "--ignore-submodules=all",
        ],
    )
    .unwrap_or((false, String::new()));
    if !status_ok {
        reasons.push("dirty_or_untracked".to_string());
    } else if !status_out.trim().is_empty() {
        let mut has_dirty = false;
        let mut has_ignored = false;
        for line in status_out.lines() {
            if line.starts_with("!!") {
                has_ignored = true;
            } else if !line.trim().is_empty() {
                has_dirty = true;
            }
        }
        if has_dirty {
            reasons.push("dirty_or_untracked".to_string());
        }
        if has_ignored {
            reasons.push("ignored_files_present".to_string());
        }
    }

    // Index flags (assume-unchanged = lowercase tag, skip-worktree = 'S') keep `git status` clean while
    // the file holds uncommitted edits, so any flagged entry (or a failed listing) blocks the prune.
    let (flags_ok, flags_out) = run_git_raw_ctx(&git_ctx, ["ls-files", "-v", "-z"])
        .unwrap_or((false, String::new()));
    if !flags_ok
        || flags_out.split('\0').any(|e| {
            e.chars()
                .next()
                .map(|c| c.is_ascii_lowercase() || c == 'S')
                .unwrap_or(false)
        })
    {
        reasons.push("index_flags_hide_changes".to_string());
    }

    let (remote_ok, remote_out) =
        run_git_ctx(&git_ctx, ["remote"]).unwrap_or((false, String::new()));
    let remotes: Vec<String> = if remote_ok {
        remote_out
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        Vec::new()
    };
    if !remote_ok || remotes.is_empty() {
        reasons.push("no_remote".to_string());
    }

    match list_worktrees(&git_ctx) {
        Ok(entries) => {
            if is_worktree {
                let me = std::fs::canonicalize(actual_repo).ok();
                let locked = entries.iter().any(|(p, locked)| {
                    *locked && std::fs::canonicalize(p).ok().is_some() && std::fs::canonicalize(p).ok() == me
                });
                if locked {
                    reasons.push("worktree_locked".to_string());
                }
            } else if entries.len() > 1 {
                // deleting the main repo would destroy every linked worktree's git metadata
                reasons.push("has_linked_worktrees".to_string());
            }
        }
        Err(_) => reasons.push("worktree_list_unverified".to_string()),
    }

    let (stash_ok, stash_out) =
        run_git_ctx(&git_ctx, ["stash", "list"]).unwrap_or((false, String::new()));
    if !stash_ok || !stash_out.is_empty() {
        reasons.push("has_stashes".to_string());
    }

    let refs_before = snapshot_local_branches(&git_ctx);
    let extra_commits = collect_extra_local_commits(&git_ctx);
    if let Err(reason) = &extra_commits {
        // cap hit / listing failure: fail closed with the REAL reason
        reasons.push(reason.clone());
    }
    let mut all_branches_verified = false;
    if let Ok(ref local_branches) = refs_before {
        if !remotes.is_empty() && proof_start.elapsed() < active_limits().repo_budget {
            let mut remote_tips: BTreeMap<String, Vec<String>> = BTreeMap::new();
            let mut remote_query_failed = false;
            for remote_name in &remotes {
                if proof_start.elapsed() >= active_limits().repo_budget || scan_deadline_passed() {
                    remote_query_failed = true;
                    break;
                }
                let target_override = if actual_repo != logical_repo {
                    let logical_abs = match anchor_to_cwd(logical_repo) {
                        Ok(p) => p,
                        Err(_) => {
                            remote_query_failed = true;
                            continue;
                        }
                    };
                    let cfg_key = format!("remote.{remote_name}.url");
                    run_git_ctx(&git_ctx, ["config", "--get", &cfg_key])
                        .ok()
                        .filter(|(ok, out)| *ok && !out.is_empty())
                        .and_then(|(_, url)| resolve_relative_local_remote(&url, &logical_abs))
                } else {
                    None
                };
                let ls_target: &OsStr = target_override
                    .as_ref()
                    .map(|p| p.as_os_str())
                    .unwrap_or_else(|| OsStr::new(remote_name));
                // heads and tags only: hosted remotes also expose refs/pull/* by the thousand
                match run_git_raw_ctx(
                    &git_ctx,
                    [
                        OsStr::new("ls-remote"),
                        OsStr::new("--heads"),
                        OsStr::new("--tags"),
                        OsStr::new("--"),
                        ls_target,
                    ],
                ) {
                    Ok((true, ls_out)) => {
                        let tips = ls_out
                            .lines()
                            .filter_map(|l| l.split_whitespace().next())
                            .map(str::to_string)
                            .collect::<Vec<_>>();
                        remote_tips.insert(remote_name.clone(), present_objects(&git_ctx, &tips));
                    }
                    _ => {
                        remote_query_failed = true;
                    }
                }
            }

            if !remote_query_failed {
                let all_tips: Vec<String> = remote_tips
                    .values()
                    .flatten()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();

                // tags and per-worktree refs: contained in some remote head/tag
                let (ref_shas, reflog_shas) = match &extra_commits {
                    Ok(v) => v.clone(),
                    // reported precisely below (never mislabelled as an unpushed commit)
                    Err(_) => (Vec::new(), Vec::new()),
                };
                let refs_ok = ref_shas.is_empty()
                    || count_unreachable(&git_ctx, &ref_shas, &all_tips, &[], &[]) == Ok(0);
                // HEAD reflog: for a linked worktree, commits still held by the SHARED reflogs (branch
                // reflogs live in the common git dir and outlive the worktree) are not lost
                let reflog_ok = if reflog_shas.is_empty() {
                    true
                } else if let Some(shared) = shared_git_ctx(&git_ctx) {
                    count_unreachable(
                        &shared,
                        &reflog_shas,
                        &all_tips,
                        &["--single-worktree"],
                        &["--reflog"],
                    ) == Ok(0)
                } else {
                    count_unreachable(&git_ctx, &reflog_shas, &all_tips, &[], &[]) == Ok(0)
                };
                if !(refs_ok && reflog_ok) {
                    reasons.push("unpushed_tag_worktree_ref_or_reflog_commit".to_string());
                }

                all_branches_verified = local_branches.iter().all(|(refname, local_sha)| {
                    let short_branch = refname.strip_prefix("refs/heads/").unwrap_or(refname);
                    let remote_cfg = run_git_ctx(
                        &git_ctx,
                        ["config", "--get", &format!("branch.{short_branch}.remote")],
                    )
                    .ok()
                    .filter(|(ok, out)| *ok && !out.is_empty())
                    .map(|(_, out)| out);
                    let tips: &[String] = match remote_cfg.as_ref() {
                        Some(rem) => remote_tips.get(rem).map(Vec::as_slice).unwrap_or(&[]),
                        None => &all_tips,
                    };
                    !tips.is_empty()
                        && count_unreachable(&git_ctx, std::slice::from_ref(local_sha), tips, &[], &[])
                            == Ok(0)
                });
            }
        }
    }
    if proof_start.elapsed() >= active_limits().repo_budget {
        reasons.push("proof_time_budget_exceeded".to_string());
    }
    if scan_deadline_passed() {
        reasons.push("scan_budget_exceeded".to_string());
    }
    if !all_branches_verified {
        reasons.push("remote_unverified_or_unpushed".to_string());
    }

    let refs_after = snapshot_local_branches(&git_ctx);
    if let Ok(ref before) = refs_before {
        if refs_after.as_ref() != Ok(before) {
            reasons.push("concurrent_ref_drift".to_string());
        }
    }

    let (head_after_ok, head_after) =
        run_git_ctx(&git_ctx, ["rev-parse", "--verify", "HEAD"]).unwrap_or((false, String::new()));
    if head_ok && (!head_after_ok || head_after != head_before) {
        reasons.push("concurrent_head_drift".to_string());
    }

    if reasons.is_empty() {
        Ok(OrphanCandidate {
            path: logical_repo.to_string_lossy().into_owned(),
            is_worktree,
            branch,
            head: Some(head_before),
            bytes: dir_bytes_no_follow(actual_repo),
        })
    } else {
        Err(reasons)
    }
}

fn validate_single_repo(
    repo: &Path,
    ctx: &ProtectionContext,
) -> Result<OrphanCandidate, Vec<String>> {
    validate_single_repo_at(repo, repo, ctx)
}

pub fn inspect_orphans(
    root: &Path,
    ctx: &ProtectionContext,
    opts: &OrphanOptions,
) -> Result<OrphansReport, SjError> {
    inspect_orphans_with_limits(root, ctx, opts, ProofLimits::default())
}

pub fn inspect_orphans_with_limits(
    root: &Path,
    ctx: &ProtectionContext,
    opts: &OrphanOptions,
    limits: ProofLimits,
) -> Result<OrphansReport, SjError> {
    let _scope = ScanScope::enter(limits);
    if is_symlink_path(root)? {
        return Err(SjError::ProtectedPath(format!(
            "refusing symlink orphan scan root: {}",
            root.display()
        )));
    }

    let mut candidates: BTreeSet<PathBuf> = BTreeSet::new();
    let mut quarantined: BTreeMap<PathBuf, String> = BTreeMap::new();
    let ctx_clone = ctx.clone();
    let walker = WalkDir::new(root)
        .follow_links(false)
        .skip_hidden(false)
        .max_depth(opts.max_depth.saturating_add(1))
        .process_read_dir(move |depth, _path, _state, children| {
            if depth.is_none() {
                return;
            }
            for entry in children.iter_mut().flatten() {
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(is_quarantine_stage_name)
                {
                    entry.read_children_path = None;
                }
            }
            children.retain(|res| {
                let Ok(entry) = res else {
                    return false;
                };
                if entry.file_name() == ".git" {
                    return false;
                }
                if entry.file_type().is_symlink() {
                    return false;
                }
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(is_quarantine_stage_name)
                {
                    return true;
                }
                !check_path_protection_anchored(&entry.path(), &ctx_clone).protected
            });
        });

    for entry_res in walker {
        let Ok(entry) = entry_res else {
            continue;
        };
        if entry.depth > 0 {
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_quarantine_stage_name(&name) {
                quarantined.insert(
                    entry.path(),
                    format!("quarantine_stage_recovery_required:{name}"),
                );
                continue;
            }
        }
        if entry.file_type().is_dir() {
            let p = entry.path();
            if std::fs::symlink_metadata(p.join(".git")).is_ok() {
                candidates.insert(p);
            }
        }
    }

    let candidate_list: Vec<PathBuf> = candidates.into_iter().collect();
    let mut results: Vec<(PathBuf, Result<OrphanCandidate, Vec<String>>)> = candidate_list
        .iter()
        .map(|p| (p.clone(), validate_single_repo(p, ctx)))
        .collect();

    // Propagate nested repo failures to parent repos
    let unsafe_paths: Vec<PathBuf> = results
        .iter()
        .filter_map(|(p, res)| if res.is_err() { Some(p.clone()) } else { None })
        .collect();

    for (p, res) in &mut results {
        if res.is_ok() {
            let p_ref = p.as_path();
            let has_unsafe_nested = unsafe_paths
                .iter()
                .any(|u| u.as_path() != p_ref && u.starts_with(p_ref));
            if has_unsafe_nested {
                *res = Err(vec!["nested_repo_unsafe".to_string()]);
                continue;
            }
            match discover_nested_repos_exhaustive(p_ref, 100_000) {
                Err(reason) => {
                    *res = Err(vec![reason]);
                    continue;
                }
                Ok(nested_repos) => {
                    if nested_repos
                        .iter()
                        .any(|nr| validate_single_repo(nr, ctx).is_err())
                    {
                        *res = Err(vec!["nested_repo_unsafe".to_string()]);
                        continue;
                    }
                }
            }
            let desc = check_dir_descendants_safe_logical(p_ref, p_ref, ctx, 100_000);
            if desc.protected {
                *res = Err(vec![desc.reason]);
            }
        }
    }

    let mut safe_to_prune = Vec::new();
    let mut blocked = Vec::new();

    for (p, res) in results {
        match res {
            Ok(c) => safe_to_prune.push(c),
            Err(reasons) => blocked.push(BlockedOrphan {
                path: p.to_string_lossy().into_owned(),
                reasons,
            }),
        }
    }

    for (p, reason) in quarantined {
        blocked.push(BlockedOrphan {
            path: p.to_string_lossy().into_owned(),
            reasons: vec![reason],
        });
    }

    safe_to_prune.sort_by(|a, b| a.path.cmp(&b.path));
    blocked.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(OrphansReport {
        schema: SCHEMA_ORPHANS_V1.to_string(),
        root: root.to_string_lossy().into_owned(),
        candidates_scanned: safe_to_prune.len() + blocked.len(),
        safe_to_prune,
        blocked,
    })
}

/// Exhaustively discovers nested git repositories (`.git` dirs, files, or symlinks)
/// inside `repo` without a depth cap, bounded by `max_entries` and failing closed on
/// any traversal or `read_children_error`.
pub fn discover_nested_repos_exhaustive(
    repo: &Path,
    max_entries: usize,
) -> Result<Vec<PathBuf>, String> {
    let mut repos = BTreeSet::new();
    let mut seen: usize = 0;

    let walker = WalkDir::new(repo)
        .follow_links(false)
        .skip_hidden(false)
        .process_read_dir(|_depth, _path, _state, children| {
            for entry in children.iter_mut().flatten() {
                if entry.file_name() == ".git" {
                    entry.read_children_path = None;
                }
            }
        });

    for entry_res in walker {
        if scan_deadline_passed() {
            return Err("scan_budget_exceeded".to_string());
        }
        let entry = entry_res.map_err(|e| format!("nested_scan_error:{e}"))?;
        if entry.read_children_error.is_some() {
            return Err(format!("nested_scan_unreadable:{}", entry.path().display()));
        }
        seen += 1;
        if seen > max_entries {
            return Err("nested_scan_budget_exceeded".to_string());
        }
        if entry.depth > 1 && entry.file_name() == ".git" {
            if let Some(parent) = entry.path().parent() {
                if parent != repo {
                    repos.insert(parent.to_path_buf());
                }
            }
        }
    }

    Ok(repos.into_iter().collect())
}

pub(crate) fn verify_orphan_safe_to_remove_staged(
    actual_repo: &Path,
    logical_repo: &Path,
    ctx: &ProtectionContext,
) -> Result<(), SjError> {
    let _home = HomeLease::acquire();
    let prot = match anchor_to_cwd(logical_repo) {
        Ok(abs) => check_path_protection_anchored(&abs, ctx),
        Err(reason) => ProtectionVerdict::deny(reason),
    };
    if prot.protected {
        return Err(SjError::ProtectedPath(prot.reason));
    }
    if let Err(reasons) = validate_single_repo_at(actual_repo, logical_repo, ctx) {
        return Err(SjError::ExecutionGate(format!(
            "orphan validation failed: {}",
            reasons.join(",")
        )));
    }
    let nested_repos =
        discover_nested_repos_exhaustive(actual_repo, 100_000).map_err(SjError::ExecutionGate)?;
    for nested_actual in nested_repos {
        let rel = nested_actual.strip_prefix(actual_repo).map_err(|_| {
            SjError::ExecutionGate(format!(
                "nested repository {} outside {}",
                nested_actual.display(),
                actual_repo.display()
            ))
        })?;
        let nested_logical = logical_repo.join(rel);
        if let Err(reasons) = validate_single_repo_at(&nested_actual, &nested_logical, ctx) {
            return Err(SjError::ExecutionGate(format!(
                "orphan has unsafe nested repository {}: {}",
                nested_logical.display(),
                reasons.join(",")
            )));
        }
    }
    let desc = check_dir_descendants_safe_logical(actual_repo, logical_repo, ctx, 100_000);
    if desc.protected {
        return Err(SjError::ProtectedPath(desc.reason));
    }
    Ok(())
}

/// Fail-closed pre-removal verification for an orphan worktree/repo directory.
pub fn verify_orphan_safe_to_remove(repo: &Path, ctx: &ProtectionContext) -> Result<(), SjError> {
    verify_orphan_safe_to_remove_staged(repo, repo, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_to_cwd_preserves_filesystem_parent_components() {
        let cwd = std::env::current_dir().expect("current_dir should succeed");

        let anchored_dot = anchor_to_cwd(Path::new(".")).expect("anchor '.' should succeed");
        assert!(anchored_dot.is_absolute());
        assert_eq!(anchored_dot, cwd.join("."));

        let anchored_rel = anchor_to_cwd(Path::new("link/../checkout"))
            .expect("anchor relative path should succeed");
        assert!(anchored_rel.is_absolute());
        assert_eq!(anchored_rel, cwd.join("link/../checkout"));

        let abs_in = cwd.join("link").join("..").join("checkout");
        let anchored_abs = anchor_to_cwd(&abs_in).expect("anchor absolute path should succeed");
        assert!(anchored_abs.is_absolute());
        assert_eq!(anchored_abs, abs_in);

        #[cfg(unix)]
        {
            let unix_abs = Path::new("/tmp/link/../checkout");
            let anchored_unix =
                anchor_to_cwd(unix_abs).expect("anchor unix absolute path should succeed");
            assert_eq!(anchored_unix, PathBuf::from("/tmp/link/../checkout"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn resolve_relative_from_dir_handles_existing_and_missing_bases() {
        let tmp = tempfile::tempdir().expect("tempdir should succeed");
        let root = tmp.path();
        let real_dir = root.join("real");
        let sub = real_dir.join("sub");
        let checkout = real_dir.join("checkout");
        let shared = real_dir.join("shared");
        std::fs::create_dir_all(&sub).expect("create sub");
        std::fs::create_dir_all(&checkout).expect("create checkout");
        std::fs::create_dir_all(&shared).expect("create shared");
        std::os::unix::fs::symlink(&sub, root.join("link")).expect("create symlink");

        let canon_shared = std::fs::canonicalize(&shared).expect("canonicalize shared");

        // Existing base dir preserves symlink + '..' for OS resolution without lexical collapse.
        let existing_base = root.join("link").join("..").join("checkout");
        let resolved_existing = resolve_relative_from_dir(&existing_base, Path::new("../shared"));
        assert_eq!(resolved_existing, existing_base.join("../shared"));
        assert_eq!(
            std::fs::canonicalize(&resolved_existing).expect("canonicalize resolved existing"),
            canon_shared
        );

        // Missing/moved base dir canonicalizes deepest existing ancestor first, then normalizes.
        let missing_base = root
            .join("link")
            .join("..")
            .join("moved_checkout")
            .join(".git")
            .join("objects");
        let resolved_missing =
            resolve_relative_from_dir(&missing_base, Path::new("../../../shared"));
        assert_eq!(resolved_missing, canon_shared);

        // Missing/moved base dir consumes '..' only against missing tail segments and preserves
        // remaining components verbatim so symlink + '..' inside rel is resolved by the OS.
        let ws = root.join("ws");
        let remotes_origin = real_dir.join("remotes").join("origin.git");
        std::fs::create_dir_all(&ws).expect("create ws");
        std::fs::create_dir_all(&remotes_origin).expect("create remotes/origin.git");
        std::os::unix::fs::symlink(&sub, ws.join("link")).expect("create ws/link");

        let moved_checkout = ws.join("moved_checkout");
        let resolved_rel_symlink =
            resolve_relative_from_dir(&moved_checkout, Path::new("../link/../remotes/origin.git"));
        assert_eq!(
            resolved_rel_symlink,
            std::fs::canonicalize(&ws)
                .expect("canonicalize ws")
                .join("link")
                .join("..")
                .join("remotes")
                .join("origin.git")
        );
        assert_eq!(
            std::fs::canonicalize(&resolved_rel_symlink)
                .expect("canonicalize resolved symlink remote"),
            std::fs::canonicalize(&remotes_origin).expect("canonicalize origin.git")
        );

        // Absolute rel is returned unchanged.
        let resolved_abs = resolve_relative_from_dir(&existing_base, &shared);
        assert_eq!(resolved_abs, shared);
    }

    // ---- process-tree kill (all platforms; the Windows leg runs on windows-latest CI) ----------

    /// Re-entry point: the timeout test re-executes THIS test binary with SJ_TREE_ROLE set. As the
    /// `parent` it spawns a `grandchild` (a second copy of this binary) and records its pid, then both
    /// sleep. Without the env var it is a no-op, so a normal `cargo test` run is unaffected.
    #[test]
    fn tree_kill_helper_role() {
        let Ok(role) = std::env::var("SJ_TREE_ROLE") else {
            return;
        };
        let pidfile = std::env::var("SJ_TREE_PIDFILE").expect("pidfile");
        if role == "parent" {
            let exe = std::env::current_exe().unwrap();
            // deliberately never waited on: it must outlive this process unless the tree is killed
            #[allow(clippy::zombie_processes)]
            let child = std::process::Command::new(exe)
                .args(["--exact", "orphans::tests::tree_kill_helper_role", "--nocapture"])
                .env("SJ_TREE_ROLE", "grandchild")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn grandchild");
            std::fs::write(&pidfile, child.id().to_string()).unwrap();
        }
        std::thread::sleep(Duration::from_secs(120));
    }

    fn pid_is_alive(pid: u32) -> bool {
        #[cfg(unix)]
        {
            // SAFETY: signal 0 only checks existence.
            unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
        }
        #[cfg(windows)]
        {
            let out = Command::new("tasklist")
                .args(["/NH", "/FI", &format!("PID eq {pid}")])
                .output()
                .expect("tasklist");
            String::from_utf8_lossy(&out.stdout).contains(&pid.to_string())
        }
    }

    #[test]
    fn timeout_kills_the_whole_process_tree_not_just_the_direct_child() {
        let tmp = tempfile::tempdir().unwrap();
        let pidfile = tmp.path().join("grandchild.pid");
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "orphans::tests::tree_kill_helper_role", "--nocapture"])
            .env("SJ_TREE_ROLE", "parent")
            .env("SJ_TREE_PIDFILE", &pidfile);
        let started = Instant::now();
        let res = run_with_timeout(cmd, None, Duration::from_secs(4));
        assert!(
            matches!(&res, Err(SjError::Git(r)) if r == "git_timeout"),
            "expected git_timeout, got {res:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(30), "timeout did not bound the call");
        let pid: u32 = std::fs::read_to_string(&pidfile)
            .expect("the parent never recorded its grandchild; probe is not exercising the tree")
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while pid_is_alive(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        let alive = pid_is_alive(pid);
        if alive {
            #[cfg(unix)]
            // SAFETY: cleanup of the probe's own leaked process.
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
            #[cfg(windows)]
            let _ = Command::new("taskkill").args(["/F", "/PID", &pid.to_string()]).output();
        }
        assert!(!alive, "grandchild {pid} survived the timeout: only the direct child was killed");
    }
}
