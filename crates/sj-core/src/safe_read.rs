//! Race-resistant reads of config files for the audit surfaces.
//!
//! A path check followed by a separate `fs::read_to_string(path)` leaves a window in which
//! the file can be swapped for a symlink (or a FIFO) after it was validated. Here the file is
//! opened once without following the final link. Unix checks the opened file's identity against
//! the checked canonical path. Windows checks the final path obtained from the opened handle.
//! Both read content only from the validated handle.

use crate::protect::{check_path_protection, ProtectionContext};
use std::fs;
use std::io::Read;
use std::path::Path;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    GetFileType, GetFinalPathNameByHandleW, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, VOLUME_NAME_DOS,
};

/// Config files above this size are not read (they are not MCP configs).
const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReadRefusal {
    /// The file (or the opened handle's path) is a symlink or changed while being opened.
    Symlink,
    /// The canonical path is outside the canonical home (only enforced when requested).
    OutsideHome,
    /// The canonical path is inside a protected root.
    Protected,
    /// Not a regular file (FIFO, socket, device, directory).
    NotRegular,
    TooLarge,
    Unreadable,
}

impl ReadRefusal {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Symlink => "symlinked_file",
            Self::OutsideHome => "outside_home",
            Self::Protected => "protected_target",
            Self::NotRegular => "not_regular_file",
            Self::TooLarge => "too_large",
            Self::Unreadable => "unreadable",
        }
    }
}

pub(crate) struct ReadPolicy<'a> {
    pub ctx: &'a ProtectionContext,
    pub canon_home: &'a Path,
    /// Default discovery must stay inside the home; an explicit `--config-dir` may point
    /// elsewhere but is still never a symlink and never a protected root.
    pub require_in_home: bool,
}

#[cfg(unix)]
fn same_inode(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

fn open_nofollow(path: &Path) -> std::io::Result<fs::File> {
    let mut o = fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open directory reparse points as objects too, so the handle check can reject them.
        // Exclude delete sharing to keep the opened file from being renamed during validation.
        o.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    o.open(path)
}

#[cfg(windows)]
fn final_path(file: &fs::File) -> Result<std::path::PathBuf, ReadRefusal> {
    use std::os::windows::{ffi::OsStringExt, io::AsRawHandle};

    let handle = file.as_raw_handle();
    // SAFETY: `file` owns this valid handle and remains borrowed throughout the queries.
    if unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
        return Err(ReadRefusal::NotRegular);
    }
    let query = |buf: &mut [u16]| {
        // SAFETY: Win32 receives a live file handle and a writable UTF-16 buffer of this size.
        unsafe {
            GetFinalPathNameByHandleW(
                handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            ) as usize
        }
    };
    let mut buf = vec![0; 260];
    let mut len = query(&mut buf);
    if len > buf.len() {
        buf.resize(len, 0);
        len = query(&mut buf);
    }
    if len == 0 || len >= buf.len() {
        return Err(ReadRefusal::Unreadable);
    }
    Ok(std::ffi::OsString::from_wide(&buf[..len]).into())
}

/// Opens `path` without following a final symlink, validates the *opened handle*, and reads
/// the content from it.
pub(crate) fn read_config_file(
    path: &Path,
    policy: &ReadPolicy<'_>,
) -> Result<String, ReadRefusal> {
    read_config_file_inner(path, policy, false)
}

/// Home-relative subtrees that the sj gate protects wholesale as *cleanup* targets (credentials
/// and user data live there) but under which the audits' fixed client-config tables sit
/// (`~/.codex/config.toml`, `~/.config/opencode/opencode.json`, VS Code's `mcp.json`).
const TRUSTED_CLIENT_HOMES: &[&str] = &[".codex", ".config", "Library", "AppData"];

/// Like [`read_config_file`] for a path taken from one of the audits' FIXED client-config
/// tables. The file may sit inside a subtree the gate protects for cleanup, because reading it is
/// what the audit is for, but only when ALL of these hold: the verdict is exactly one of
/// [`TRUSTED_CLIENT_HOMES`] (never `.ssh`, `.claude`, system roots, key material, ...), the
/// canonical path equals the lexical in-home path (no symlink anywhere on the way), and the
/// handle checks of [`read_config_file`] pass. Output still goes through the closed vocabulary.
pub(crate) fn read_trusted_client_config(
    path: &Path,
    policy: &ReadPolicy<'_>,
) -> Result<String, ReadRefusal> {
    read_config_file_inner(path, policy, true)
}

/// True when `path` (lexical, under the home) is protected ONLY because it sits in a trusted
/// client home and no symlink is involved. Used to skip the caller's pre-check for table files.
pub(crate) fn trusted_client_config_ok(path: &Path, policy: &ReadPolicy<'_>) -> bool {
    let Ok(canon) = fs::canonicalize(path) else {
        return false;
    };
    trusted_client_canonical_ok(path, &canon, policy)
}

fn trusted_client_canonical_ok(path: &Path, canon: &Path, policy: &ReadPolicy<'_>) -> bool {
    let Ok(rel) = path.strip_prefix(&policy.ctx.home_dir) else {
        return false;
    };
    if canon != policy.canon_home.join(rel) {
        return false;
    }
    let v = check_path_protection(canon, policy.ctx);
    !v.protected
        || TRUSTED_CLIENT_HOMES
            .iter()
            .any(|h| v.reason == format!("protected_credential_store:~/{h}"))
}

fn read_config_file_inner(
    path: &Path,
    policy: &ReadPolicy<'_>,
    trusted_client: bool,
) -> Result<String, ReadRefusal> {
    let lm = fs::symlink_metadata(path).map_err(|_| ReadRefusal::Unreadable)?;
    if lm.file_type().is_symlink() {
        return Err(ReadRefusal::Symlink);
    }
    let file = open_nofollow(path).map_err(|e| {
        // ELOOP: the leaf became a symlink between the check and the open
        if e.raw_os_error() == Some(libc_eloop()) {
            ReadRefusal::Symlink
        } else {
            ReadRefusal::Unreadable
        }
    })?;
    let meta = file.metadata().map_err(|_| ReadRefusal::Unreadable)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ReadRefusal::Symlink);
        }
    }
    if !meta.is_file() {
        return Err(ReadRefusal::NotRegular);
    }
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(ReadRefusal::TooLarge);
    }
    #[cfg(windows)]
    let canon = final_path(&file)?;
    #[cfg(not(windows))]
    let canon = fs::canonicalize(path).map_err(|_| ReadRefusal::Unreadable)?;
    if policy.require_in_home && !canon.starts_with(policy.canon_home) {
        return Err(ReadRefusal::OutsideHome);
    }
    let protected = if trusted_client {
        !trusted_client_canonical_ok(path, &canon, policy)
    } else {
        check_path_protection(&canon, policy.ctx).protected
    };
    if protected {
        return Err(ReadRefusal::Protected);
    }
    #[cfg(unix)]
    {
        // The handle we hold must be the file at the canonical path we just validated.
        let cm = fs::metadata(&canon).map_err(|_| ReadRefusal::Unreadable)?;
        if !same_inode(&meta, &cm) {
            return Err(ReadRefusal::Symlink);
        }
    }
    let mut raw = String::new();
    file.take(MAX_CONFIG_BYTES)
        .read_to_string(&mut raw)
        .map_err(|_| ReadRefusal::Unreadable)?;
    Ok(raw)
}

/// Kind of a directory entry, never following symlinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryKind {
    Dir,
    File,
    Symlink,
    Other,
}

/// A directory enumerated through a no-follow handle.
///
/// `fs::read_dir(path)` opens by path and follows a swapped-in symlink, so a path check
/// before or after it cannot prove which directory was listed. Here the canonical path is
/// opened component by component with `O_NOFOLLOW | O_DIRECTORY` (the helpers in
/// `safe_remove`), the handle is bound to that path by `(st_dev, st_ino)`, and the listing and
/// every child open go through the handle only.
///
/// Windows has no equivalent here and keeps the path-based listing (documented limitation).
pub(crate) struct SafeDir {
    #[cfg(unix)]
    inner: crate::safe_remove::unix_impl::NofollowDir,
    #[cfg(not(unix))]
    canon: std::path::PathBuf,
}

impl SafeDir {
    /// Opens `path` for listing. The canonical path must be inside the canonical home (when
    /// the policy requires it) and outside every protected root, unless it equals
    /// `protected_ok_exact` (a names-only listing of one specific protected directory).
    pub(crate) fn open(
        path: &Path,
        policy: &ReadPolicy<'_>,
        protected_ok_exact: Option<&Path>,
    ) -> Result<Self, ReadRefusal> {
        let canon = fs::canonicalize(path).map_err(|_| ReadRefusal::Unreadable)?;
        if policy.require_in_home && !canon.starts_with(policy.canon_home) {
            return Err(ReadRefusal::OutsideHome);
        }
        let exact = protected_ok_exact.is_some_and(|e| e == canon.as_path());
        if !exact && check_path_protection(&canon, policy.ctx).protected {
            return Err(ReadRefusal::Protected);
        }
        Self::open_canonical(&canon)
    }

    #[cfg(unix)]
    fn open_canonical(canon: &Path) -> Result<Self, ReadRefusal> {
        let inner = crate::safe_remove::unix_impl::NofollowDir::open_canonical(canon).map_err(
            |e| match e {
                crate::SjError::Io(ref io) if io.raw_os_error() == Some(libc::ELOOP) => {
                    ReadRefusal::Symlink
                }
                _ => ReadRefusal::Unreadable,
            },
        )?;
        // the handle we hold must be the directory at the canonical path we validated
        if !inner.matches_canonical_path() {
            return Err(ReadRefusal::Symlink);
        }
        Ok(Self { inner })
    }

    #[cfg(not(unix))]
    fn open_canonical(canon: &Path) -> Result<Self, ReadRefusal> {
        Ok(Self {
            canon: canon.to_path_buf(),
        })
    }

    /// Canonical path of the directory this handle was opened for.
    pub(crate) fn canonical_path(&self) -> &Path {
        #[cfg(unix)]
        {
            self.inner.canonical_path()
        }
        #[cfg(not(unix))]
        {
            &self.canon
        }
    }

    /// Entries (`.`/`..` excluded, non-UTF-8 names skipped), classified without following
    /// symlinks.
    pub(crate) fn entries(&self) -> Result<Vec<(String, EntryKind)>, ReadRefusal> {
        #[cfg(unix)]
        {
            use crate::safe_remove::unix_impl::HandleEntryKind as K;
            let v = self.inner.entries().map_err(|_| ReadRefusal::Unreadable)?;
            Ok(v.into_iter()
                .map(|(n, k)| {
                    let k = match k {
                        K::Dir => EntryKind::Dir,
                        K::File => EntryKind::File,
                        K::Symlink => EntryKind::Symlink,
                        K::Other => EntryKind::Other,
                    };
                    (n, k)
                })
                .collect())
        }
        #[cfg(not(unix))]
        {
            let rd = fs::read_dir(&self.canon).map_err(|_| ReadRefusal::Unreadable)?;
            Ok(rd
                .flatten()
                .filter_map(|e| {
                    let name = e.file_name().into_string().ok()?;
                    let t = e.file_type().ok()?;
                    let k = if t.is_symlink() {
                        EntryKind::Symlink
                    } else if t.is_dir() {
                        EntryKind::Dir
                    } else if t.is_file() {
                        EntryKind::File
                    } else {
                        EntryKind::Other
                    };
                    Some((name, k))
                })
                .collect())
        }
    }

    /// Opens a child directory relative to this handle without following a symlink.
    pub(crate) fn open_child(&self, name: &str) -> Result<Self, ReadRefusal> {
        #[cfg(unix)]
        {
            let inner = self.inner.open_child(name).map_err(|e| match e {
                crate::SjError::Io(ref io) if io.raw_os_error() == Some(libc::ELOOP) => {
                    ReadRefusal::Symlink
                }
                _ => ReadRefusal::Unreadable,
            })?;
            Ok(Self { inner })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                canon: self.canon.join(name),
            })
        }
    }
}

#[cfg(unix)]
fn libc_eloop() -> i32 {
    libc::ELOOP
}

#[cfg(not(unix))]
fn libc_eloop() -> i32 {
    -1
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::os::windows::fs::MetadataExt;
    use std::process::Command;

    #[test]
    fn nofollow_open_returns_the_junction_object() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("fixture");
        let junction = temp.path().join("junction");
        fs::create_dir(&target).unwrap();
        make_junction(&junction, &target);

        let opened = open_nofollow(&junction).unwrap();
        let attributes = opened.metadata().unwrap().file_attributes();
        assert_ne!(attributes & FILE_ATTRIBUTE_REPARSE_POINT, 0);
        let canon_home = fs::canonicalize(temp.path()).unwrap();
        let ctx = ProtectionContext::new(temp.path().into(), Vec::new());
        let policy = ReadPolicy {
            ctx: &ctx,
            canon_home: &canon_home,
            require_in_home: true,
        };
        assert_eq!(
            read_config_file(&junction, &policy),
            Err(ReadRefusal::Symlink)
        );
    }

    fn make_junction(junction: &Path, target: &Path) {
        let created = Command::new("cmd")
            .args(["/d", "/c", "mklink", "/j"])
            .arg(junction)
            .arg(target)
            .output()
            .unwrap();
        assert!(created.status.success(), "junction fixture: {created:?}");
    }

    #[test]
    fn policy_checks_the_opened_files_final_path() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let other = temp.path().join("other");
        fs::create_dir(&home).unwrap();
        fs::create_dir(&other).unwrap();
        fs::write(home.join("config.json"), "{}").unwrap();
        fs::write(other.join("config.json"), "{\"fixture\":true}").unwrap();
        make_junction(&home.join("junction"), &other);

        let canon_home = fs::canonicalize(&home).unwrap();
        let ctx = ProtectionContext::new(home.clone(), Vec::new());
        let policy = ReadPolicy {
            ctx: &ctx,
            canon_home: &canon_home,
            require_in_home: true,
        };
        assert_eq!(
            read_config_file(&home.join("config.json"), &policy),
            Ok("{}".into())
        );
        let via_junction = home.join("junction/config.json");
        let file = open_nofollow(&via_junction).unwrap();
        assert_eq!(
            final_path(&file),
            Ok(fs::canonicalize(other.join("config.json")).unwrap())
        );
        assert_eq!(
            read_config_file(&via_junction, &policy),
            Err(ReadRefusal::OutsideHome)
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{Duration, Instant};
    use tempfile::tempdir;

    fn policy<'a>(ctx: &'a ProtectionContext, home: &'a Path, in_home: bool) -> ReadPolicy<'a> {
        ReadPolicy {
            ctx,
            canon_home: home,
            require_in_home: in_home,
        }
    }

    #[test]
    fn regular_file_is_read_symlink_and_fifo_are_refused() {
        let tmp = tempdir().unwrap();
        let h = tmp.path().canonicalize().unwrap();
        let ctx = ProtectionContext::new(h.clone(), Vec::new());
        let p = policy(&ctx, &h, true);
        fs::write(h.join("ok.json"), "{}").unwrap();
        assert_eq!(read_config_file(&h.join("ok.json"), &p).unwrap(), "{}");

        symlink(h.join("ok.json"), h.join("link.json")).unwrap();
        assert_eq!(
            read_config_file(&h.join("link.json"), &p),
            Err(ReadRefusal::Symlink)
        );

        let fifo = h.join("pipe.json");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let t = Instant::now();
        assert_eq!(read_config_file(&fifo, &p), Err(ReadRefusal::NotRegular));
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "must not block on a FIFO"
        );
    }

    #[test]
    fn symlinked_ancestor_and_outside_home_are_refused() {
        let tmp = tempdir().unwrap();
        let h = tmp.path().canonicalize().unwrap();
        let ext = tempdir().unwrap();
        let ext_c = ext.path().canonicalize().unwrap();
        fs::write(ext_c.join("c.json"), "{}").unwrap();
        symlink(&ext_c, h.join("dirlink")).unwrap();
        let ctx = ProtectionContext::new(h.clone(), Vec::new());
        // ancestor symlink resolving outside the home
        assert_eq!(
            read_config_file(&h.join("dirlink/c.json"), &policy(&ctx, &h, true)),
            Err(ReadRefusal::OutsideHome)
        );
        // an explicit config dir may be outside the home, but never a protected root
        assert!(read_config_file(&ext_c.join("c.json"), &policy(&ctx, &h, false)).is_ok());
    }

    #[test]
    fn safe_dir_lists_real_children_and_refuses_protected_and_symlink_leaf() {
        let tmp = tempdir().unwrap();
        let h = tmp.path().canonicalize().unwrap();
        fs::create_dir_all(h.join("plain/real")).unwrap();
        fs::write(h.join("plain/a.json"), "{}").unwrap();
        symlink(h.join("plain/real"), h.join("plain/link")).unwrap();
        fs::create_dir_all(h.join(".ssh/inner")).unwrap();
        let ctx = ProtectionContext::new(h.clone(), Vec::new());
        let p = policy(&ctx, &h, true);

        let d = SafeDir::open(&h.join("plain"), &p, None).unwrap();
        let mut e = d.entries().unwrap();
        e.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            e.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            ["a.json", "link", "real"]
        );
        assert!(e.contains(&("link".to_string(), EntryKind::Symlink)));
        assert!(e.contains(&("real".to_string(), EntryKind::Dir)));
        assert!(d.open_child("real").is_ok());
        assert!(
            d.open_child("link").is_err(),
            "child symlink is never followed"
        );

        assert!(matches!(
            SafeDir::open(&h.join(".ssh"), &p, None),
            Err(ReadRefusal::Protected)
        ));
        // a symlinked leaf resolves to its target; the protected target is refused
        symlink(h.join(".ssh"), h.join("plain/to_ssh")).unwrap();
        assert!(matches!(
            SafeDir::open(&h.join("plain/to_ssh"), &p, None),
            Err(ReadRefusal::Protected)
        ));
        // names-only exception applies to exactly one directory
        assert!(SafeDir::open(&h.join(".ssh"), &p, Some(&h.join(".ssh"))).is_ok());
        assert!(SafeDir::open(&h.join(".ssh"), &p, Some(&h.join("other"))).is_err());
    }

    #[test]
    fn trusted_client_config_reads_protected_client_homes_but_nothing_else() {
        let tmp = tempdir().unwrap();
        let h = tmp.path().canonicalize().unwrap();
        let ctx = ProtectionContext::new(h.clone(), vec![]);
        let p = policy(&ctx, &h, true);
        for (rel, ok) in [
            (".codex/config.toml", true),
            (".config/opencode/opencode.json", true),
            // credential stores and Claude state are never readable through the trusted path
            (".ssh/config", false),
            (".aws/credentials", false),
            (".claude/settings.json", false),
            (".gnupg/gpg.conf", false),
        ] {
            let f = h.join(rel);
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(&f, "x = 1\n").unwrap();
            assert_eq!(read_trusted_client_config(&f, &p).is_ok(), ok, "{rel}");
        }
        // the plain reader still refuses every protected root (explicit --config-dir path)
        assert!(matches!(
            read_config_file(&h.join(".codex/config.toml"), &p),
            Err(ReadRefusal::Protected)
        ));
    }

    #[test]
    fn trusted_client_config_refuses_a_symlinked_client_home() {
        let tmp = tempdir().unwrap();
        let h = tmp.path().canonicalize().unwrap().join("home");
        let elsewhere = tmp.path().canonicalize().unwrap().join("elsewhere");
        fs::create_dir_all(&h).unwrap();
        fs::create_dir_all(&elsewhere).unwrap();
        fs::write(elsewhere.join("config.toml"), "x = 1\n").unwrap();
        symlink(&elsewhere, h.join(".codex")).unwrap();
        let ctx = ProtectionContext::new(h.clone(), vec![]);
        let p = policy(&ctx, &h, true);
        assert!(read_trusted_client_config(&h.join(".codex/config.toml"), &p).is_err());
    }
}
