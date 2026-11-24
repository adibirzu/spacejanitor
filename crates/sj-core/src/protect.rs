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
    "/Windows",
    "C:/Windows",
];

const PROTECTED_VM_EXTENSIONS: &[&str] = &["vmdk", "qcow2", "vhdx", "vdi", "raw", "img"];
const PROTECTED_KEY_EXTENSIONS: &[&str] = &["pem", "key", "p12", "pfx"];
const PROTECTED_KEY_PREFIXES: &[&str] = &["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"];

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

fn expand_home(raw: &str, home_dir: &str) -> String {
    let home = normalize_separators(home_dir);
    let norm = normalize_separators(raw);
    if norm == "~" {
        return home;
    }
    if let Some(rest) = norm.strip_prefix("~/") {
        return format!("{home}/{rest}");
    }
    norm
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
    let home_norm = normalize_separators(home_dir);
    let cand = expand_home(candidate, &home_norm);
    if cand.is_empty() {
        return ProtectionVerdict::deny("empty_path");
    }

    if cand == "/" || (!home_norm.is_empty() && cand == home_norm) {
        return ProtectionVerdict::deny("protected_root");
    }

    for sys_root in PROTECTED_SYSTEM_ROOTS {
        let root_norm = normalize_separators(sys_root);
        let root_low = root_norm.to_ascii_lowercase();
        let cand_low = cand.to_ascii_lowercase();
        if cand_low == root_low || cand_low.starts_with(&format!("{root_low}/")) {
            // macOS APFS Data volume mounts user data under /System/Volumes/Data/...
            if root_low == "/system" && cand_low.starts_with("/system/volumes/data/") {
                continue;
            }
            return ProtectionVerdict::deny(format!("protected_system:{sys_root}"));
        }
    }

    if !home_norm.is_empty() && home_norm != "/" {
        for sub in PROTECTED_HOME_SUBPATHS {
            let full = format!("{home_norm}/{sub}");
            if cand == full || cand.starts_with(&format!("{full}/")) {
                return ProtectionVerdict::deny(format!("protected_credential_store:~/{sub}"));
            }
        }
    }

    // Also protect any path segment matching credential store directories (e.g. inside a scanned root)
    for component in Path::new(&cand).components() {
        if let Component::Normal(os_str) = component {
            if let Some(seg) = os_str.to_str() {
                if matches!(seg, ".ssh" | ".gnupg" | ".aws" | ".kube" | ".claude") {
                    return ProtectionVerdict::deny(format!("protected_credential_dir:{seg}"));
                }
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

    let cand_str = candidate.to_string_lossy();
    let lexical = is_protected_path(&cand_str, &home_str, &exact_refs);
    if lexical.protected {
        return lexical;
    }

    // Walk ancestors from candidate up to root
    let mut deepest_existing: Option<(PathBuf, Vec<std::ffi::OsString>)> = None;
    let mut trailing: Vec<std::ffi::OsString> = Vec::new();

    for anc in candidate.ancestors() {
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
