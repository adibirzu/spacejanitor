use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

pub const PROTECTED_HOME_SUBPATHS: &[&str] =
    &[".ssh", ".gnupg", ".aws", ".kube", ".claude", ".config/gh"];

pub const PROTECTED_SYSTEM_ROOTS: &[&str] = &[
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/etc",
    "/Library",
    "/private/etc",
    "/private/var/db",
    "/Windows",
    "C:/Windows",
];

const PROTECTED_VM_EXTENSIONS: &[&str] = &["vmdk", "qcow2", "vhdx", "vdi", "raw", "img"];
const PROTECTED_KEY_EXTENSIONS: &[&str] = &["pem", "key", "p12", "pfx"];
const PROTECTED_KEY_PREFIXES: &[&str] = &["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"];

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
    fn safe() -> Self {
        Self {
            protected: false,
            reason: String::new(),
        }
    }

    fn deny(reason: impl Into<String>) -> Self {
        Self {
            protected: true,
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtectionContext {
    pub home_dir: PathBuf,
    pub exact_paths: Vec<PathBuf>,
}

impl ProtectionContext {
    pub fn new(home_dir: PathBuf, exact_paths: Vec<PathBuf>) -> Self {
        Self {
            home_dir,
            exact_paths,
        }
    }

    pub fn from_env() -> Self {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));
        Self {
            home_dir: home,
            exact_paths: Vec::new(),
        }
    }
}

fn normalize_separators(raw: &str) -> String {
    let trimmed = raw.trim().replace('\\', "/");
    if trimmed.len() > 1 {
        trimmed.trim_end_matches('/').to_string()
    } else {
        trimmed
    }
}

fn normalize_lexical(raw: &str) -> String {
    let norm = normalize_separators(raw);
    if norm.is_empty() {
        return String::new();
    }

    let bytes = norm.as_bytes();
    let has_drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    let (prefix, is_abs, rest) = if has_drive {
        let drive = &norm[..2];
        let after = &norm[2..];
        let abs = after.starts_with('/');
        (Some(drive), abs, after.trim_start_matches('/'))
    } else if let Some(after) = norm.strip_prefix('/') {
        (None, true, after)
    } else {
        (None, false, norm.as_str())
    };

    let mut stack: Vec<&str> = Vec::new();
    for seg in rest.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            if let Some(&last) = stack.last() {
                if last != ".." {
                    stack.pop();
                    continue;
                }
            }
            if !is_abs {
                stack.push("..");
            }
        } else {
            stack.push(seg);
        }
    }

    match (prefix, is_abs) {
        (Some(d), true) => {
            if stack.is_empty() {
                format!("{d}/")
            } else {
                format!("{d}/{}", stack.join("/"))
            }
        }
        (Some(d), false) => {
            if stack.is_empty() {
                d.to_string()
            } else {
                format!("{d}/{}", stack.join("/"))
            }
        }
        (None, true) => format!("/{}", stack.join("/")),
        (None, false) => stack.join("/"),
    }
}

fn expand_home(raw: &str, home_dir: &str) -> String {
    let home = normalize_lexical(home_dir);
    let norm = normalize_separators(raw);
    if norm == "~" {
        return home;
    }
    if let Some(rest) = norm.strip_prefix("~/") {
        return normalize_lexical(&format!("{home}/{rest}"));
    }
    normalize_lexical(&norm)
}

fn is_protected_filename(name: &str) -> Option<String> {
    let low = name.to_ascii_lowercase();
    if low == ".env" || low.starts_with(".env.") || low.ends_with(".env") {
        return Some("protected_secret_file:.env".to_string());
    }
    if low.contains(".private.") {
        return Some("protected_glob:*.private.*".to_string());
    }
    for prefix in PROTECTED_KEY_PREFIXES {
        if low == *prefix || low.starts_with(&format!("{prefix}.")) {
            return Some(format!("protected_key_file:{prefix}"));
        }
    }
    if let Some((_, ext)) = low.rsplit_once('.') {
        if PROTECTED_KEY_EXTENSIONS.contains(&ext) {
            return Some(format!("protected_key_ext:*.{ext}"));
        }
        if PROTECTED_VM_EXTENSIONS.contains(&ext) {
            return Some(format!("protected_vm_image:*.{ext}"));
        }
    }
    None
}

/// Evaluates whether `candidate` is protected by immutable built-in safety rules or user exact paths.
pub fn is_protected_path(
    candidate: &str,
    home_dir: &str,
    exact_paths: &[&str],
) -> ProtectionVerdict {
    let home_norm = normalize_lexical(home_dir);
    let mut cand = expand_home(candidate, &home_norm);
    if cand.is_empty() {
        return ProtectionVerdict::deny("empty_path");
    }

    // macOS APFS Data volume mounts under /System/Volumes/Data/...; strip prefix and
    // re-evaluate remainder against system roots and all other protection rules.
    loop {
        let low = cand.to_ascii_lowercase();
        if low == "/system/volumes/data" {
            cand = "/".to_string();
        } else if low.starts_with("/system/volumes/data/") {
            cand = cand["/system/volumes/data".len()..].to_string();
        } else {
            break;
        }
    }

    if cand == "/" || (!home_norm.is_empty() && cand == home_norm) {
        return ProtectionVerdict::deny("protected_root");
    }

    let cand_low = cand.to_ascii_lowercase();

    for sys_root in PROTECTED_SYSTEM_ROOTS {
        let root_norm = normalize_lexical(sys_root);
        let root_low = root_norm.to_ascii_lowercase();
        if cand_low == root_low || cand_low.starts_with(&format!("{root_low}/")) {
            return ProtectionVerdict::deny(format!("protected_system:{sys_root}"));
        }
    }

    if !home_norm.is_empty() && home_norm != "/" {
        let home_low = home_norm.to_ascii_lowercase();
        for sub in PROTECTED_HOME_SUBPATHS {
            let full_low = format!("{home_low}/{sub}").to_ascii_lowercase();
            if cand_low == full_low || cand_low.starts_with(&format!("{full_low}/")) {
                return ProtectionVerdict::deny(format!("protected_credential_store:~/{sub}"));
            }
        }
    }

    // Also protect any path segment matching credential store directories (case-insensitive)
    // or SpaceJanitor quarantine staging directories.
    let mut prev_seg_low: Option<String> = None;
    for component in Path::new(&cand).components() {
        if let Component::Normal(os_str) = component {
            if let Some(seg) = os_str.to_str() {
                if is_quarantine_stage_name(seg) {
                    return ProtectionVerdict::deny(format!(
                        "quarantine_stage_recovery_required:{seg}"
                    ));
                }
                let seg_low = seg.to_ascii_lowercase();
                if matches!(
                    seg_low.as_str(),
                    ".ssh" | ".gnupg" | ".aws" | ".kube" | ".claude"
                ) {
                    return ProtectionVerdict::deny(format!("protected_credential_dir:{seg}"));
                }
                if prev_seg_low.as_deref() == Some(".config") && seg_low == "gh" {
                    return ProtectionVerdict::deny("protected_credential_dir:.config/gh");
                }
                prev_seg_low = Some(seg_low);
            } else {
                prev_seg_low = None;
            }
        }
    }

    for exact in exact_paths {
        let exact_norm = expand_home(exact, &home_norm);
        if exact_norm == "/" || exact_norm == home_norm {
            if cand == exact_norm {
                return ProtectionVerdict::deny(format!("protected_exact:{exact}"));
            }
        } else if cand == exact_norm || cand.starts_with(&format!("{exact_norm}/")) {
            return ProtectionVerdict::deny(format!("protected_exact:{exact}"));
        }
    }

    if let Some(name) = Path::new(&cand).file_name().and_then(|s| s.to_str()) {
        if let Some(reason) = is_protected_filename(name) {
            return ProtectionVerdict::deny(reason);
        }
    }

    ProtectionVerdict::safe()
}

/// Fail-closed path protection check:
/// 1. Checks lexical rules on `candidate`.
/// 2. Walks ancestors with `symlink_metadata` + `canonicalize`, failing closed on dangling/unresolvable symlinks
///    or symlinks resolving into protected locations.
pub fn check_path_protection(candidate: &Path, ctx: &ProtectionContext) -> ProtectionVerdict {
    let home_str = ctx.home_dir.to_string_lossy();
    let exact_strs: Vec<String> = ctx
        .exact_paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let exact_refs: Vec<&str> = exact_strs.iter().map(String::as_str).collect();

    let raw_str = candidate.to_string_lossy();
    let trimmed = raw_str.trim();
    let bytes = trimmed.as_bytes();
    let is_windows_drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    let resolved_candidate =
        if trimmed == "~" || trimmed.starts_with("~/") || trimmed.starts_with("~\\") {
            PathBuf::from(expand_home(trimmed, &home_str))
        } else if is_windows_drive {
            candidate.to_path_buf()
        } else if candidate.is_relative() {
            match std::env::current_dir() {
                Ok(cwd) => cwd.join(candidate),
                Err(_) => return ProtectionVerdict::deny("unresolvable_current_dir"),
            }
        } else {
            candidate.to_path_buf()
        };

    let cand_str = resolved_candidate.to_string_lossy();
    let lexical = is_protected_path(&cand_str, &home_str, &exact_refs);
    if lexical.protected {
        return lexical;
    }

    // Walk ancestors from resolved_candidate up to root
    let mut deepest_existing: Option<(PathBuf, Vec<std::ffi::OsString>)> = None;
    let mut trailing: Vec<std::ffi::OsString> = Vec::new();

    for anc in resolved_candidate.ancestors() {
        if anc.as_os_str().is_empty() {
            continue;
        }
        match std::fs::symlink_metadata(anc) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    match std::fs::canonicalize(anc) {
                        Ok(resolved) => {
                            let v = is_protected_path(
                                &resolved.to_string_lossy(),
                                &home_str,
                                &exact_refs,
                            );
                            if v.protected {
                                return ProtectionVerdict::deny(format!(
                                    "symlink_to_protected:{}",
                                    v.reason
                                ));
                            }
                        }
                        Err(_) => {
                            return ProtectionVerdict::deny(format!(
                                "dangling_or_unresolvable_symlink:{}",
                                anc.display()
                            ));
                        }
                    }
                }
                if deepest_existing.is_none() {
                    deepest_existing = Some((anc.to_path_buf(), trailing.clone()));
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if let Some(name) = anc.file_name() {
                    trailing.push(name.to_os_string());
                }
            }
            Err(_) => {
                return ProtectionVerdict::deny(format!(
                    "unresolvable_path_metadata:{}",
                    anc.display()
                ));
            }
        }
    }

    if let Some((existing, mut rest)) = deepest_existing {
        match std::fs::canonicalize(&existing) {
            Ok(mut resolved) => {
                while let Some(seg) = rest.pop() {
                    resolved.push(seg);
                }
                let v = is_protected_path(&resolved.to_string_lossy(), &home_str, &exact_refs);
                if v.protected {
                    return v;
                }
            }
            Err(_) => {
                return ProtectionVerdict::deny(format!(
                    "unresolvable_canonical_path:{}",
                    existing.display()
                ));
            }
        }
    }

    ProtectionVerdict::safe()
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
        let v = check_path_protection(&logical_dir.join(rel), ctx);
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
