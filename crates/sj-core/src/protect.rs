//! The protected-path gate. This is the ONLY implementation: the Node tooling and the desktop app
//! forward every question here (`sj protect`), so there is no second denylist that could drift. Rules
//! are the union of the former JavaScript denylist (main a66538f `packages/core/src/protect.mjs`)
//! and the original Rust rules; `crates/sj-core/tests/fixtures/protect_vectors.json` pins them.
//!
//! Two layers:
//! * [`is_protected_path`] / [`is_protected_path_with`]: pure string rules, no filesystem access, the
//!   same answer on every platform (Windows prefixes, drive letters, `\` and `/`, case-insensitive).
//! * [`check_path_protection`]: what callers use before touching disk. It expands `~` textually,
//!   rejects relative, control-character and (on POSIX) drive-letter inputs, resolves the path the way
//!   the OS does (a symlink is replaced by its target BEFORE a following `..` applies) and judges both
//!   the resolved and the lexical form. Any resolution error fails closed.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Home-relative subtrees that are protected as a whole (credentials, user data, shell profiles).
pub const PROTECTED_HOME_SUBPATHS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".config",
    ".config/gh",
    ".docker",
    ".netrc",
    "Documents",
    "Desktop",
    "Library",
    ".azure",
    ".oci",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".gitconfig",
    ".local/share/keyrings",
    ".password-store",
    ".1password",
    ".mozilla",
    ".terraform.d",
    ".claude",
    ".codex",
    ".zshrc",
    ".bashrc",
    ".bash_profile",
    ".zprofile",
    ".profile",
    "Pictures",
    "Movies",
    "Music",
    "AppData",
    "OneDrive",
];

/// Cache carve-outs inside the blanket-protected `Library` / `AppData` subtrees. Only these exact
/// subtrees (and their children) may be proposed for cleanup.
pub const PROTECTED_HOME_ALLOW_SUBPATHS: &[&str] = &[
    "Library/Caches/Homebrew",
    "Library/Caches/pip",
    "Library/Caches/pnpm",
    "AppData/Local/npm-cache",
    "AppData/Local/pip/Cache",
];

/// System roots: the directory and everything below it is protected.
pub const PROTECTED_SYSTEM_ROOTS: &[&str] = &[
    "/System",
    "/System/Library",
    "/System/Applications",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/etc",
    "/Library",
    "/Applications",
    "/private/etc",
    "/private/var/db",
    "/private/var/root",
    "/var/db",
    "/var/root",
    "/root",
    "/opt",
    "/Windows",
    "/Program Files",
    "/Program Files (x86)",
    "C:/Windows",
    "C:/Program Files",
    "C:/Program Files (x86)",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/run",
    "/snap",
    "/lost+found",
    "/var/lib/dpkg",
    "/var/lib/rpm",
    "/var/lib/systemd",
    "/var/lib/docker",
    "/var/lib/containers",
    "/var/log/journal",
    "/var/cache/apt",
];

/// Protected as the directory itself only (children are governed by the other rules).
pub const PROTECTED_EXACT_ONLY_ROOTS: &[&str] = &[
    "/Users", "/home", "/var", "/private", "/private/var", "/private/tmp", "/Volumes", "/mnt", "/srv", "/tmp", "C:/Users",
];

/// Account roots whose children belong to some other user unless they sit under the current home.
pub const PROTECTED_FOREIGN_HOME_ROOTS: &[&str] = &["/Users", "/home", "C:/Users"];

/// Case-insensitive wildcard patterns (`*` any run, `?` one char) matched against the whole
/// normalized path and against its last segment.
pub const PROTECTED_GLOB_PATTERNS: &[&str] = &[
    "*.private.*",
    "*/.ssh/*",
    "*/.gnupg/*",
    "*.pem",
    "*.p12",
    "*.pfx",
    "*.kdbx",
    "*.key",
    "*/.env",
    "*/.env.*",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "id_dsa*",
    "*.vmdk",
    "*.qcow2",
    "*.vhdx",
    "*.vdi",
    "*.raw",
    "*.img",
    "*/.sj-stage-*",
    "*/.ssh",
    "*/.gnupg",
    "*/.aws",
    "*/.aws/*",
    "*/.kube",
    "*/.kube/*",
    "*/.config/gh",
    "*/.config/gh/*",
];

pub const QUARANTINE_STAGE_PREFIX: &str = ".sj-stage-";

pub fn is_quarantine_stage_name(name: &str) -> bool {
    name.to_ascii_lowercase()
        .starts_with(QUARANTINE_STAGE_PREFIX)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionVerdict {
    pub protected: bool,
    pub reason: String,
}

impl ProtectionVerdict {
    pub(crate) fn safe() -> Self {
        Self {
            protected: false,
            reason: String::new(),
        }
    }

    pub(crate) fn deny(reason: impl Into<String>) -> Self {
        Self {
            protected: true,
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtectionContext {
    pub home_dir: PathBuf,
    /// User-configured protected paths (the path and everything below it).
    pub exact_paths: Vec<PathBuf>,
    /// Paths protected at runtime (for example active worktrees); the home itself and `/` are ignored.
    pub dynamic_paths: Vec<PathBuf>,
    /// Extra wildcard patterns on top of [`PROTECTED_GLOB_PATTERNS`].
    pub glob_patterns: Vec<String>,
    /// Resolved forms of every rule root (computed once per context, on first filesystem-aware
    /// check). Mutate the public rule fields before the first check.
    prepared: std::sync::OnceLock<Prepared>,
}

impl ProtectionContext {
    pub fn new(home_dir: PathBuf, exact_paths: Vec<PathBuf>) -> Self {
        Self {
            home_dir,
            exact_paths,
            dynamic_paths: Vec::new(),
            glob_patterns: Vec::new(),
            prepared: std::sync::OnceLock::new(),
        }
    }

    pub fn with_dynamic_paths(mut self, dynamic_paths: Vec<PathBuf>) -> Self {
        self.dynamic_paths = dynamic_paths;
        self
    }

    pub fn with_glob_patterns(mut self, glob_patterns: Vec<String>) -> Self {
        self.glob_patterns = glob_patterns;
        self
    }

    pub fn from_env() -> Self {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));
        Self::new(home, Vec::new())
    }
}

// ---------------------------------------------------------------------------------------------
// Pure string layer
// ---------------------------------------------------------------------------------------------

fn has_control_char(s: &str) -> bool {
    s.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f)
}

fn is_drive_letter_start(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// `X:/` or `X:\` (a drive-absolute path) as opposed to the drive-relative `X:foo`.
fn is_drive_absolute(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'/' || b[2] == b'\\')
}

fn is_drive_root(norm: &str) -> bool {
    let b = norm.as_bytes();
    (b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
        || (b.len() == 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'/')
}

/// Separator normalisation: `\` becomes `/`, runs collapse, the Win32 extended prefixes
/// (`\\?\C:\x`) are stripped to the drive form. Device paths (`\\.\...`) and UNC shares
/// (`\\server\share`, `\\?\UNC\...`) are returned as `Err(reason)`: another machine's files are never a cleanup target.
fn normalize_separators(raw: &str) -> Result<String, &'static str> {
    let mut s = raw.trim().replace('\\', "/");
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("//?/unc/") || lower == "//?/unc" {
        return Err("protected_unc_path");
    }
    if s.starts_with("//./") {
        return Err("protected_device_path");
    }
    if s.starts_with("//?/") {
        s = s[4..].to_string();
        if !is_drive_absolute(&s) && !is_drive_root(&s) {
            return Err("protected_device_path");
        }
    } else if s.starts_with("//") && !s.starts_with("///") {
        return Err("protected_unc_path");
    }
    while s.contains("//") {
        s = s.replace("//", "/");
    }
    if s.len() > 1 && s.ends_with('/') && !is_drive_root(&s) {
        s.truncate(s.len() - 1);
    }
    Ok(s)
}

/// Lexical `.` / `..` collapse over a separator-normalised absolute string.
fn collapse_dots(norm: &str) -> String {
    let (prefix, rest): (String, &str) = if is_drive_letter_start(norm) {
        (norm[..2].to_string(), norm[2..].trim_start_matches('/'))
    } else {
        (String::new(), norm.trim_start_matches('/'))
    };
    let mut stack: Vec<&str> = Vec::new();
    for seg in rest.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            stack.pop();
        } else {
            stack.push(seg);
        }
    }
    let body = stack.join("/");
    let mut out = if prefix.is_empty() {
        format!("/{body}")
    } else if body.is_empty() {
        format!("{prefix}/")
    } else {
        format!("{prefix}/{body}")
    };
    // macOS APFS Data volume is the same tree as "/": strip the alias.
    loop {
        let low = out.to_ascii_lowercase();
        if low == "/system/volumes/data" {
            out = "/".to_string();
        } else if low.starts_with("/system/volumes/data/") {
            out = out["/system/volumes/data".len()..].to_string();
        } else {
            break;
        }
    }
    if out.len() > 1 && out.ends_with('/') && !is_drive_root(&out) {
        out.truncate(out.len() - 1);
    }
    out
}

fn normalize_lexical(raw: &str) -> Result<String, &'static str> {
    Ok(collapse_dots(&normalize_separators(raw)?))
}

/// `~` and `~/rest` are replaced textually (no `..` collapsing: that must wait until symlinks are
/// resolved). Anything else is returned unchanged; `~user/...` stays relative and is rejected.
fn expand_tilde_textual(raw: &str, home: &str) -> String {
    let home = home.trim().replace('\\', "/");
    let home = home.trim_end_matches('/');
    if raw == "~" {
        return home.to_string();
    }
    if let Some(rest) = raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")) {
        return format!("{home}/{rest}");
    }
    raw.to_string()
}

/// Absolute by TEXT, independent of the host: rooted (`/x`, `\x`) or drive-absolute (`C:/x`).
fn is_absolute_textual(s: &str) -> bool {
    s.starts_with('/') || s.starts_with('\\') || is_drive_absolute(s)
}

fn key(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// `cand` is `root` or below it (case-insensitive). `/` only matches itself.
fn same_or_child(cand: &str, root: &str) -> bool {
    let (c, r) = (key(cand), key(root));
    if r == "/" {
        return c == "/";
    }
    let r = r.trim_end_matches('/');
    c == r || c.starts_with(&format!("{r}/"))
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().replace('\\', "/").chars().collect();
    let t: Vec<char> = text.to_lowercase().replace('\\', "/").chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) && p[pi] != '*' {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn is_protected_filename(name: &str) -> Option<String> {
    let low = name.to_ascii_lowercase();
    if low == ".env" || low.starts_with(".env.") || low.ends_with(".env") {
        return Some("protected_secret_file:.env".to_string());
    }
    if low.contains(".private.") {
        return Some("protected_glob:*.private.*".to_string());
    }
    for prefix in ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"] {
        if low.starts_with(prefix) {
            return Some(format!("protected_key_file:{prefix}"));
        }
    }
    if let Some((_, ext)) = low.rsplit_once('.') {
        if ["pem", "key", "p12", "pfx", "kdbx"].contains(&ext) {
            return Some(format!("protected_key_ext:*.{ext}"));
        }
        if ["vmdk", "qcow2", "vhdx", "vdi", "raw", "img"].contains(&ext) {
            return Some(format!("protected_vm_image:*.{ext}"));
        }
    }
    None
}

/// Every rule root in all the forms a candidate may legitimately take: the textual form and, for the
/// filesystem-aware layer, the form the OS resolves it to (so `/tmp` also protects `/private/tmp`,
/// and a `~/.ssh` that is a symlink also protects its real target). Custom rules are only ever added
/// here, so they can protect more but never allow anything.
#[derive(Debug, Clone)]
struct Prepared {
    homes: Vec<String>,
    system_roots: Vec<(String, Vec<String>)>,
    exact_only: Vec<(String, Vec<String>)>,
    foreign: Vec<(String, Vec<String>)>,
    home_subs: Vec<(String, Vec<String>)>,
    exact: Vec<(String, Vec<String>)>,
    dynamic: Vec<(String, Vec<String>)>,
    /// set when a custom rule could not be anchored: every path is then denied (fail closed)
    rule_error: Option<String>,
}

fn forms_of(textual: &str, resolve: &dyn Fn(&str) -> String) -> Vec<String> {
    let mut out = vec![textual.to_string()];
    let r = resolve(textual);
    if !r.is_empty() && !out.iter().any(|x| key(x) == key(&r)) {
        out.push(r);
    }
    out
}

fn prepare(homes: Vec<String>, ctx: &ProtectionContext, resolve: &dyn Fn(&str) -> String) -> Prepared {
    let norm_roots = |roots: &[&str]| -> Vec<(String, Vec<String>)> {
        roots
            .iter()
            .filter_map(|r| {
                let t = normalize_lexical(r).ok()?;
                // a root that resolves to "/" or a bare drive would swallow everything: keep it textual
                let forms = forms_of(&t, resolve)
                    .into_iter()
                    .filter(|f| f == &t || (f != "/" && !is_drive_root(f)))
                    .collect();
                Some(((*r).to_string(), forms))
            })
            .collect()
    };
    let mut home_subs = Vec::new();
    for sub in PROTECTED_HOME_SUBPATHS {
        let mut forms: Vec<String> = Vec::new();
        for h in &homes {
            let t = format!("{}/{sub}", h.trim_end_matches('/'));
            for f in forms_of(&t, resolve) {
                if !forms.iter().any(|x| key(x) == key(&f)) {
                    forms.push(f);
                }
            }
        }
        home_subs.push(((*sub).to_string(), forms));
    }
    let home0 = homes.first().cloned().unwrap_or_default();
    // Custom rules (exact / dynamic) follow main's `path.resolve` semantics: `~` expands to the home, a
    // relative rule is anchored to the CURRENT WORKING DIRECTORY (not the home), and the OS then resolves
    // it in its own order: components left to right, a symlink replaced by its target BEFORE a following
    // `..` applies. Both the lexical (dots collapsed) and the OS-resolved form protect, so a custom rule
    // can only ever protect more. A rule that cannot be anchored fails closed.
    let mut rule_error: Option<String> = None;
    let mut user_forms = |paths: &[PathBuf]| -> Vec<(String, Vec<String>)> {
        let mut out = Vec::new();
        for p in paths {
            let t = expand_tilde_textual(p.to_string_lossy().trim(), &home0);
            let anchored = if is_absolute_textual(&t) {
                t
            } else {
                match std::env::current_dir() {
                    Ok(cwd) => format!("{}/{t}", cwd.to_string_lossy().trim_end_matches(['/', '\\'])),
                    Err(_) => {
                        rule_error = Some(format!("unresolvable_custom_rule:{}", p.display()));
                        continue;
                    }
                }
            };
            let Ok(sep) = normalize_separators(&anchored) else {
                rule_error = Some(format!("unresolvable_custom_rule:{}", p.display()));
                continue;
            };
            let mut forms = vec![collapse_dots(&sep)];
            let resolved = resolve(&sep); // dots still intact: OS order
            if !resolved.is_empty() && !forms.iter().any(|x| key(x) == key(&resolved)) {
                forms.push(resolved);
            }
            out.push((p.display().to_string(), forms));
        }
        out
    };
    let exact = user_forms(&ctx.exact_paths);
    let dynamic = user_forms(&ctx.dynamic_paths);
    Prepared {
        homes,
        system_roots: norm_roots(PROTECTED_SYSTEM_ROOTS),
        exact_only: norm_roots(PROTECTED_EXACT_ONLY_ROOTS),
        foreign: norm_roots(PROTECTED_FOREIGN_HOME_ROOTS),
        home_subs,
        exact,
        dynamic,
        rule_error,
    }
}

/// Pure rule evaluation over already-normalised candidate forms (`cands`).
fn evaluate(cands: &[String], prep: &Prepared, ctx: &ProtectionContext) -> ProtectionVerdict {
    if let Some(reason) = &prep.rule_error {
        return ProtectionVerdict::deny(reason.clone());
    }
    let homes = &prep.homes;
    let in_any_home = |c: &str| homes.iter().any(|h| same_or_child(c, h));

    for c in cands {
        // Root-level dot entries are filesystem aliases (/.nofollow, /.vol, ...): never a target.
        if c.starts_with("/.") {
            return ProtectionVerdict::deny("protected_alias_root");
        }
        if c == "/"
            || is_drive_root(c)
            || homes.iter().any(|h| key(h) == key(c))
            // every ancestor of the home directory is a home-root candidate
            || homes.iter().any(|h| same_or_child(h, c))
        {
            return ProtectionVerdict::deny("protected_root");
        }
    }

    for (label, forms) in &prep.system_roots {
        if cands.iter().any(|c| forms.iter().any(|f| same_or_child(c, f))) {
            return ProtectionVerdict::deny(format!("protected_system:{label}"));
        }
    }

    for (label, forms) in &prep.exact_only {
        if cands.iter().any(|c| forms.iter().any(|f| key(c) == key(f))) {
            return ProtectionVerdict::deny(format!("protected_system_root:{label}"));
        }
    }

    // Other accounts' homes are never ours to clean.
    for (label, forms) in &prep.foreign {
        for c in cands {
            if forms.iter().any(|f| same_or_child(c, f)) && !in_any_home(c) {
                return ProtectionVerdict::deny(format!("protected_foreign_home:{label}"));
            }
        }
    }

    for (sub, forms) in &prep.home_subs {
        if cands
            .iter()
            .any(|c| forms.iter().any(|f| same_or_child(c, f)))
        {
            // Carve-out only if EVERY form of the candidate sits under an allow-listed subtree.
            // Allow roots are built textually from the home (never by resolving), so a symlink inside
            // an allowed cache cannot launder a sensitive target.
            let allow_roots: Vec<String> = PROTECTED_HOME_ALLOW_SUBPATHS
                .iter()
                .filter(|a| a.starts_with(&format!("{sub}/")))
                .flat_map(|a| {
                    homes
                        .iter()
                        .map(move |hh| format!("{}/{a}", hh.trim_end_matches('/')))
                })
                .collect();
            let allowed = !allow_roots.is_empty()
                && cands
                    .iter()
                    .all(|c| allow_roots.iter().any(|r| same_or_child(c, r)));
            if allowed {
                continue;
            }
            return ProtectionVerdict::deny(format!("protected_credential_store:~/{sub}"));
        }
    }

    // Credential directory segments at any depth and quarantine stage dirs.
    for c in cands {
        let mut prev: Option<String> = None;
        for seg in c.split('/').filter(|s| !s.is_empty()) {
            if is_quarantine_stage_name(seg) {
                return ProtectionVerdict::deny(format!(
                    "quarantine_stage_recovery_required:{seg}"
                ));
            }
            let low = seg.to_ascii_lowercase();
            if matches!(low.as_str(), ".ssh" | ".gnupg" | ".aws" | ".kube") {
                return ProtectionVerdict::deny(format!("protected_credential_dir:{seg}"));
            }
            if prev.as_deref() == Some(".config") && low == "gh" {
                return ProtectionVerdict::deny("protected_credential_dir:.config/gh");
            }
            prev = Some(low);
        }
    }

    for (display, forms) in &prep.exact {
        for ne in forms {
            let root_like = ne == "/" || homes.iter().any(|h| key(h) == key(ne));
            let hit = if root_like {
                cands.iter().any(|c| key(c) == key(ne))
            } else {
                cands.iter().any(|c| same_or_child(c, ne))
            };
            if hit {
                return ProtectionVerdict::deny(format!("protected_exact:{display}"));
            }
        }
    }
    for (display, forms) in &prep.dynamic {
        for nd in forms {
            if nd != "/"
                && !homes.iter().any(|h| key(h) == key(nd))
                && cands.iter().any(|c| same_or_child(c, nd))
            {
                return ProtectionVerdict::deny(format!("protected_dynamic:{display}"));
            }
        }
    }

    for c in cands {
        let base = c.rsplit('/').next().unwrap_or("");
        if let Some(reason) = is_protected_filename(base) {
            return ProtectionVerdict::deny(reason);
        }
        for pat in PROTECTED_GLOB_PATTERNS
            .iter()
            .copied()
            .chain(ctx.glob_patterns.iter().map(String::as_str))
        {
            if glob_match(pat, c) || glob_match(pat, base) {
                return ProtectionVerdict::deny(format!("protected_glob:{pat}"));
            }
        }
    }

    ProtectionVerdict::safe()
}

/// Shared pre-checks for both layers. Returns the textual absolute candidate or a denial.
fn precheck(raw: &str, home: &str) -> Result<String, ProtectionVerdict> {
    let raw = raw.trim();
    if has_control_char(raw) {
        return Err(ProtectionVerdict::deny("control_character_in_path"));
    }
    if raw.is_empty() {
        return Err(ProtectionVerdict::deny("empty_path"));
    }
    let expanded = expand_tilde_textual(raw, home);
    if !is_absolute_textual(&expanded) {
        return Err(ProtectionVerdict::deny("relative_path_rejected"));
    }
    Ok(expanded)
}

/// Pure string evaluation with the context's custom rules; no filesystem access.
pub fn is_protected_path_with(
    candidate: &str,
    home_dir: &str,
    ctx: &ProtectionContext,
) -> ProtectionVerdict {
    let expanded = match precheck(candidate, home_dir) {
        Ok(e) => e,
        Err(v) => return v,
    };
    let cand = match normalize_lexical(&expanded) {
        Ok(c) => c,
        Err(reason) => return ProtectionVerdict::deny(reason),
    };
    let home = match normalize_lexical(home_dir) {
        Ok(h) if !h.is_empty() => h,
        _ => return ProtectionVerdict::deny("unresolvable_home"),
    };
    let prep = prepare(vec![home], ctx, &|_| String::new());
    evaluate(&[cand], &prep, ctx)
}

/// Evaluates whether `candidate` is protected by immutable built-in safety rules or user exact paths.
/// Pure string rules: identical on every platform.
pub fn is_protected_path(
    candidate: &str,
    home_dir: &str,
    exact_paths: &[&str],
) -> ProtectionVerdict {
    let ctx = ProtectionContext::new(
        PathBuf::from(home_dir),
        exact_paths.iter().map(PathBuf::from).collect(),
    );
    is_protected_path_with(candidate, home_dir, &ctx)
}

// ---------------------------------------------------------------------------------------------
// Filesystem-aware layer
// ---------------------------------------------------------------------------------------------

/// Resolve an absolute path the way the OS does: components left to right, a symlink is replaced by
/// its target before a following `..` is applied. A nonexistent tail is appended lexically. Any
/// symlink that cannot be resolved (dangling, looping, unreadable) is an error: fail closed.
#[cfg(unix)]
fn resolve_os_style(abs: &str) -> Result<String, String> {
    let mut cur = PathBuf::from("/");
    let mut exists = true;
    for comp in abs.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp == ".." {
            cur.pop();
            continue;
        }
        let next = cur.join(comp);
        if exists {
            match std::fs::symlink_metadata(&next) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        match std::fs::canonicalize(&next) {
                            Ok(real) => cur = real,
                            Err(_) => {
                                return Err(format!(
                                    "dangling_or_unresolvable_symlink:{}",
                                    next.display()
                                ))
                            }
                        }
                    } else {
                        cur = next;
                    }
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    exists = false;
                    cur = next;
                }
                Err(_) => {
                    return Err(format!("unresolvable_path_metadata:{}", next.display()));
                }
            }
        } else {
            cur = next;
        }
    }
    Ok(cur.to_string_lossy().into_owned())
}

/// On Windows only existing real paths are resolved (junctions and symlinks), and the `\\?\`
/// prefix `canonicalize` adds is stripped by the string layer. A path that does not exist is judged
/// lexically.
#[cfg(not(unix))]
fn resolve_os_style(abs: &str) -> Result<String, String> {
    match std::fs::symlink_metadata(abs) {
        Ok(_) => std::fs::canonicalize(abs)
            .map(|p| p.to_string_lossy().into_owned())
            .map_err(|_| format!("unresolvable_canonical_path:{abs}")),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(abs.to_string()),
        Err(_) => Err(format!("unresolvable_path_metadata:{abs}")),
    }
}

/// Fail-closed path protection check used before anything touches the disk:
/// 1. `~` is expanded textually; control characters, relative paths and (on POSIX hosts) drive-letter
///    strings are rejected; UNC/device paths are rejected.
/// 2. The path is resolved the way the OS does (symlink target first, then `..`), and BOTH the
///    resolved and the lexical form are judged by the full rule set.
/// 3. Any resolution error (dangling or looping symlink, unreadable metadata) denies.
pub fn check_path_protection(candidate: &Path, ctx: &ProtectionContext) -> ProtectionVerdict {
    let home_str = ctx.home_dir.to_string_lossy().into_owned();
    let raw = candidate.to_string_lossy().into_owned();
    let expanded = match precheck(&raw, &home_str) {
        Ok(e) => e,
        Err(v) => return v,
    };
    // A drive-letter path means nothing to a POSIX kernel (it is relative to the cwd), so it cannot be
    // judged lexically there.
    if cfg!(not(windows)) && is_drive_letter_start(expanded.trim()) {
        return ProtectionVerdict::deny("windows_path_on_posix_rejected");
    }
    // `\x` is rooted only on Windows. On a POSIX host it is a relative file name, so judging it as
    // `/x` would approve a different path than the one the OS acts on.
    if cfg!(not(windows)) && !expanded.trim().starts_with('/') {
        return ProtectionVerdict::deny("relative_path_rejected");
    }
    let sep_norm = match normalize_separators(&expanded) {
        Ok(s) => s,
        Err(reason) => return ProtectionVerdict::deny(reason),
    };
    let lexical = collapse_dots(&sep_norm);
    let home_lex = match normalize_lexical(&home_str) {
        Ok(h) if !h.is_empty() => h,
        _ => return ProtectionVerdict::deny("unresolvable_home"),
    };

    let mut cands = vec![lexical.clone()];
    let mut homes = vec![home_lex.clone()];

    // Resolve from the textual form (dots intact) so a `..` after a symlink follows the target.
    match resolve_os_style(&sep_norm) {
        Ok(resolved) => match normalize_lexical(&resolved) {
            Ok(r) => {
                if !cands.contains(&r) {
                    cands.push(r);
                }
            }
            Err(reason) => return ProtectionVerdict::deny(reason),
        },
        Err(reason) => return ProtectionVerdict::deny(reason),
    }
    if let Ok(resolved_home) = resolve_os_style(&home_lex).map_err(|_| ()).and_then(|h| {
        normalize_lexical(&h).map_err(|_| ())
    }) {
        if !homes.contains(&resolved_home) {
            homes.push(resolved_home);
        }
    }

    let prep = ctx
        .prepared
        .get_or_init(|| prepare(homes.clone(), ctx, &|t| resolve_lenient(t)));
    evaluate(&cands, prep, ctx)
}

/// The OS-resolved form of a rule root, or nothing when it cannot be resolved or is not a Unix path.
fn resolve_lenient(textual: &str) -> String {
    if cfg!(unix) && is_drive_letter_start(textual) {
        return String::new();
    }
    match resolve_os_style(textual) {
        Ok(r) => normalize_lexical(&r).unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// Internal callers hold paths that are legitimately relative to the cwd (for example a CLI root of
/// `.` or `link/../checkout`). Anchor them textually (keeping every `..` for the OS-style resolution)
/// and apply the strict gate. The public/CLI entry points stay strict and reject relative input.
pub(crate) fn check_path_protection_anchored(
    candidate: &Path,
    ctx: &ProtectionContext,
) -> ProtectionVerdict {
    let raw = candidate.to_string_lossy();
    let t = raw.trim();
    let needs_anchor = !t.is_empty()
        && !has_control_char(t)
        && !t.starts_with('~')
        && !is_absolute_textual(t)
        && !candidate.is_absolute();
    if !needs_anchor {
        return check_path_protection(candidate, ctx);
    }
    match std::env::current_dir() {
        Ok(cwd) => check_path_protection(&cwd.join(candidate), ctx),
        Err(_) => ProtectionVerdict::deny("unresolvable_current_dir"),
    }
}

/// Returns `Ok(true)` if `path` itself is a symlink, `Ok(false)` if not, or `Err` on metadata failure.
pub fn is_symlink_path(path: &Path) -> Result<bool, std::io::Error> {
    let meta = std::fs::symlink_metadata(path)?;
    Ok(meta.file_type().is_symlink())
}

/// Bounded recursive non-following check ensuring no descendant inside `actual_dir` is protected
/// (evaluated at `logical_dir`), a symlink, or unreadable. Fails closed on any error or when
/// `max_entries` is exceeded.
pub(crate) fn check_dir_descendants_safe_logical(
    actual_dir: &Path,
    logical_dir: &Path,
    ctx: &ProtectionContext,
    max_entries: usize,
) -> ProtectionVerdict {
    let mut seen: usize = 0;
    for entry_res in jwalk::WalkDir::new(actual_dir)
        .follow_links(false)
        .skip_hidden(false)
    {
        let Ok(entry) = entry_res else {
            return ProtectionVerdict::deny("unreadable_descendant");
        };
        if entry.read_children_error.is_some() {
            return ProtectionVerdict::deny(format!(
                "unreadable_directory:{}",
                entry.path().display()
            ));
        }
        if entry.depth == 0 {
            continue;
        }
        seen += 1;
        if seen > max_entries {
            return ProtectionVerdict::deny("descendant_check_limit_exceeded");
        }
        if entry.file_type().is_symlink() {
            return ProtectionVerdict::deny(format!(
                "symlink_descendant:{}",
                entry.path().display()
            ));
        }
        let entry_path = entry.path();
        let Ok(rel) = entry_path.strip_prefix(actual_dir) else {
            return ProtectionVerdict::deny(format!(
                "unresolvable_descendant:{}",
                entry_path.display()
            ));
        };
        let v = check_path_protection_anchored(&logical_dir.join(rel), ctx);
        if v.protected {
            return ProtectionVerdict::deny(format!("protected_descendant:{}", v.reason));
        }
    }
    ProtectionVerdict::safe()
}

/// Bounded recursive non-following check ensuring no descendant inside `dir` is protected,
/// a symlink, or unreadable. Fails closed on any error or when `max_entries` is exceeded.
pub fn check_dir_descendants_safe(
    dir: &Path,
    ctx: &ProtectionContext,
    max_entries: usize,
) -> ProtectionVerdict {
    check_dir_descendants_safe_logical(dir, dir, ctx, max_entries)
}
