//! Race-resistant reads of config files for the audit surfaces.
//!
//! A path check followed by a separate `fs::read_to_string(path)` leaves a window in which
//! the file can be swapped for a symlink (or a FIFO) after it was validated. Here the file is
//! opened once with `O_NOFOLLOW | O_NONBLOCK`, `fstat`-ed on the opened handle, and the
//! handle is bound to the checked canonical path by `(st_dev, st_ino)` before any byte is read.
//! Content is only ever read from that handle.

use crate::protect::{check_path_protection, ProtectionContext};
use std::fs;
use std::io::Read;
use std::path::Path;

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

#[cfg(not(unix))]
fn same_inode(_a: &fs::Metadata, _b: &fs::Metadata) -> bool {
    true
}

fn open_nofollow(path: &Path) -> std::io::Result<fs::File> {
    let mut o = fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    o.open(path)
}

/// Opens `path` without following a final symlink, validates the *opened handle*, and reads
/// the content from it.
pub(crate) fn read_config_file(
    path: &Path,
    policy: &ReadPolicy<'_>,
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
    if !meta.is_file() {
        return Err(ReadRefusal::NotRegular);
    }
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(ReadRefusal::TooLarge);
    }
    let canon = fs::canonicalize(path).map_err(|_| ReadRefusal::Unreadable)?;
    if policy.require_in_home && !canon.starts_with(policy.canon_home) {
        return Err(ReadRefusal::OutsideHome);
    }
    if check_path_protection(&canon, policy.ctx).protected {
        return Err(ReadRefusal::Protected);
    }
    // The handle we hold must be the file at the canonical path we just validated.
    let cm = fs::metadata(&canon).map_err(|_| ReadRefusal::Unreadable)?;
    if !same_inode(&meta, &cm) {
        return Err(ReadRefusal::Symlink);
    }
    let mut raw = String::new();
    file.take(MAX_CONFIG_BYTES)
        .read_to_string(&mut raw)
        .map_err(|_| ReadRefusal::Unreadable)?;
    Ok(raw)
}

#[cfg(unix)]
fn libc_eloop() -> i32 {
    libc::ELOOP
}

#[cfg(not(unix))]
fn libc_eloop() -> i32 {
    -1
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
}
