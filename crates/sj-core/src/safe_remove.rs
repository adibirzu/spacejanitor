use crate::orphans::{capture_git_snapshot_identity, verify_orphan_safe_to_remove};
use crate::plan::{PlanItem, TargetSnapshot};
use crate::protect::{check_path_protection, is_symlink_path, ProtectionContext};
use crate::SjError;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[cfg(unix)]
const MAX_DIR_DEPTH: usize = 256;
const MAX_DIR_ENTRIES: usize = 100_000;

fn sha256_to_hex(digest: impl AsRef<[u8]>) -> String {
    let bytes = digest.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

pub(crate) fn hash_file_reader<R: Read + Seek>(reader: &mut R) -> Result<(String, u64), SjError> {
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total_bytes: u64 = 0;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total_bytes = total_bytes.saturating_add(n as u64);
    }
    Ok((sha256_to_hex(hasher.finalize()), total_bytes))
}

pub(crate) type DirTreeRecord = (
    String,
    String,
    Option<u64>,
    Option<u64>,
    u64,
    Option<i64>,
    Option<u32>,
    String,
);

pub(crate) fn hash_dir_tree_records(records: &[DirTreeRecord]) -> String {
    let mut hasher = Sha256::new();
    for (rel_path, entry_type, dev, ino, size, mtime_secs, mtime_nanos, content_sha256) in records {
        hasher.update((rel_path.len() as u64).to_le_bytes());
        hasher.update(rel_path.as_bytes());
        hasher.update(entry_type.as_bytes());
        hasher.update(dev.unwrap_or(0).to_le_bytes());
        hasher.update(ino.unwrap_or(0).to_le_bytes());
        hasher.update(size.to_le_bytes());
        hasher.update(mtime_secs.unwrap_or(0).to_le_bytes());
        hasher.update(mtime_nanos.unwrap_or(0).to_le_bytes());
        hasher.update((content_sha256.len() as u64).to_le_bytes());
        hasher.update(content_sha256.as_bytes());
    }
    sha256_to_hex(hasher.finalize())
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
mod unix_impl {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::Component;

    struct DirGuard(*mut libc::DIR);

    impl Drop for DirGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
    }

    fn last_os_err() -> SjError {
        SjError::Io(std::io::Error::last_os_error())
    }

    fn set_errno(val: i32) {
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = val;
        }
        #[cfg(target_os = "linux")]
        unsafe {
            *libc::__errno_location() = val;
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let _ = val;
    }

    fn get_errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn to_cstring(s: &str) -> Result<CString, SjError> {
        CString::new(s).map_err(|_| {
            SjError::ExecutionGate("path component contains interior NUL byte".to_string())
        })
    }

    fn openat_nofollow(
        dir_fd: libc::c_int,
        name: &CStr,
        flags: libc::c_int,
    ) -> Result<OwnedFd, SjError> {
        loop {
            let fd = unsafe { libc::openat(dir_fd, name.as_ptr(), flags) };
            if fd >= 0 {
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(SjError::Io(err));
        }
    }

    fn fstat_fd(fd: &OwnedFd) -> Result<libc::stat, SjError> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstat(fd.as_raw_fd(), &mut st) };
        if rc != 0 {
            return Err(last_os_err());
        }
        Ok(st)
    }

    fn fstatat_nofollow(dir_fd: &OwnedFd, name: &CStr) -> Result<libc::stat, SjError> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                dir_fd.as_raw_fd(),
                name.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return Err(last_os_err());
        }
        Ok(st)
    }

    fn lstat_path(path: &Path) -> Result<libc::stat, SjError> {
        let c_path = to_cstring(&path.to_string_lossy())?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::lstat(c_path.as_ptr(), &mut st) };
        if rc != 0 {
            return Err(last_os_err());
        }
        Ok(st)
    }

    fn stat_matches_dev_ino(a: &libc::stat, b: &libc::stat) -> bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino
    }

    fn stat_matches_reg_identity(a: &libc::stat, b: &libc::stat) -> bool {
        a.st_dev == b.st_dev
            && a.st_ino == b.st_ino
            && a.st_size == b.st_size
            && a.st_mtime == b.st_mtime
            && a.st_mtime_nsec == b.st_mtime_nsec
    }

    pub(super) fn hash_fd_stable(
        file_fd: &OwnedFd,
        st_before: &libc::stat,
    ) -> Result<String, SjError> {
        if (st_before.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(SjError::ExecutionGate(
                "cannot hash non-regular file descriptor".to_string(),
            ));
        }
        let dup_fd = unsafe { libc::fcntl(file_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if dup_fd < 0 {
            return Err(last_os_err());
        }
        let owned_dup = unsafe { OwnedFd::from_raw_fd(dup_fd) };
        let mut file = File::from(owned_dup);
        let (digest, bytes_read) = hash_file_reader(&mut file)?;
        drop(file);

        let st_after = fstat_fd(file_fd)?;
        if bytes_read != st_before.st_size as u64
            || !stat_matches_reg_identity(&st_after, st_before)
        {
            return Err(SjError::ExecutionGate(
                "file changed while hashing; aborting".to_string(),
            ));
        }
        Ok(digest)
    }

    fn snapshot_matches_stat(snap: &TargetSnapshot, st: &libc::stat) -> bool {
        snap.dev == Some(st.st_dev as u64) && snap.ino == Some(st.st_ino as u64)
    }

    fn stat_mtime(st: &libc::stat) -> (Option<i64>, Option<u32>) {
        (Some(st.st_mtime as i64), Some(st.st_mtime_nsec as u32))
    }

    fn fd_to_dir(fd: &OwnedFd) -> Result<DirGuard, SjError> {
        let dup_fd = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if dup_fd < 0 {
            return Err(last_os_err());
        }
        let dir = unsafe { libc::fdopendir(dup_fd) };
        if dir.is_null() {
            let err = last_os_err();
            unsafe {
                libc::close(dup_fd);
            }
            return Err(err);
        }
        unsafe {
            libc::rewinddir(dir);
        }
        Ok(DirGuard(dir))
    }

    fn open_dir_nofollow_from_root(canon_dir: &Path) -> Result<OwnedFd, SjError> {
        if !canon_dir.is_absolute() {
            return Err(SjError::ExecutionGate(format!(
                "expected absolute canonical path: {}",
                canon_dir.display()
            )));
        }
        let root_c = to_cstring("/")?;
        let mut cur = openat_nofollow(
            libc::AT_FDCWD,
            &root_c,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;
        for comp in canon_dir.components() {
            match comp {
                Component::RootDir => {}
                Component::Normal(seg) => {
                    let seg_str = seg.to_str().ok_or_else(|| {
                        SjError::ExecutionGate("non-UTF-8 path component".to_string())
                    })?;
                    let c_seg = to_cstring(seg_str)?;
                    cur = openat_nofollow(
                        cur.as_raw_fd(),
                        &c_seg,
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )?;
                }
                _ => {
                    return Err(SjError::ExecutionGate(format!(
                        "unexpected path component in canonical path: {}",
                        canon_dir.display()
                    )));
                }
            }
        }
        Ok(cur)
    }

    fn open_rel_dir_nofollow(base_fd: OwnedFd, rel: &Path) -> Result<OwnedFd, SjError> {
        let mut cur = base_fd;
        for comp in rel.components() {
            match comp {
                Component::CurDir => {}
                Component::Normal(seg) => {
                    let seg_str = seg.to_str().ok_or_else(|| {
                        SjError::ExecutionGate("non-UTF-8 path component".to_string())
                    })?;
                    let c_seg = to_cstring(seg_str)?;
                    cur = openat_nofollow(
                        cur.as_raw_fd(),
                        &c_seg,
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )?;
                }
                _ => {
                    return Err(SjError::ExecutionGate(format!(
                        "unexpected relative path component: {}",
                        rel.display()
                    )));
                }
            }
        }
        Ok(cur)
    }

    pub(super) struct ManifestFile {
        pub(super) name_c: CString,
        pub(super) name_str: String,
        pub(super) dev: u64,
        pub(super) ino: u64,
        pub(super) size: u64,
        pub(super) mtime_secs: i64,
        pub(super) mtime_nsec: i64,
    }

    pub(super) struct ManifestDir {
        pub(super) name_c: CString,
        pub(super) name_str: String,
        pub(super) dev: u64,
        pub(super) ino: u64,
        pub(super) dirs: Vec<ManifestDir>,
        pub(super) files: Vec<ManifestFile>,
    }

    struct InspectState<'a> {
        root_dev: u64,
        seen: usize,
        skip_dot_git: bool,
        ctx: &'a ProtectionContext,
        records: Vec<DirTreeRecord>,
    }

    fn inspect_dir_fd_recursive(
        dir_fd: &OwnedFd,
        dir_path: &Path,
        rel_prefix: &str,
        depth: usize,
        state: &mut InspectState<'_>,
        manifest: &mut ManifestDir,
    ) -> Result<(), SjError> {
        if depth > MAX_DIR_DEPTH {
            return Err(SjError::ExecutionGate(
                "directory depth limit exceeded during safe inspection".to_string(),
            ));
        }
        let guard = fd_to_dir(dir_fd)?;
        let mut children: Vec<(String, CString)> = Vec::new();
        loop {
            set_errno(0);
            let dent = unsafe { libc::readdir(guard.0) };
            if dent.is_null() {
                let err = get_errno();
                if err != 0 {
                    return Err(SjError::Io(std::io::Error::from_raw_os_error(err)));
                }
                break;
            }
            let name_c = unsafe { CStr::from_ptr((*dent).d_name.as_ptr()) };
            let name_str = name_c.to_str().map_err(|_| {
                SjError::ExecutionGate("non-UTF-8 directory entry name".to_string())
            })?;
            if name_str == "." || name_str == ".." {
                continue;
            }
            children.push((name_str.to_string(), name_c.to_owned()));
        }
        drop(guard);

        for (name_str, name_c) in children {
            state.seen += 1;
            if state.seen > MAX_DIR_ENTRIES {
                return Err(SjError::ExecutionGate(
                    "directory entry limit exceeded during safe inspection".to_string(),
                ));
            }
            let child_st = fstatat_nofollow(dir_fd, &name_c)?;
            if (child_st.st_dev as u64) != state.root_dev {
                return Err(SjError::ProtectedPath(format!(
                    "refusing cross-device mountpoint descendant: {}",
                    dir_path.join(&name_str).display()
                )));
            }
            let mode = child_st.st_mode & libc::S_IFMT;
            if mode == libc::S_IFLNK {
                return Err(SjError::ProtectedPath(format!(
                    "symlink_descendant:{}",
                    dir_path.join(&name_str).display()
                )));
            }
            let child_full_path = dir_path.join(&name_str);
            let prot = check_path_protection(&child_full_path, state.ctx);
            if prot.protected {
                return Err(SjError::ProtectedPath(format!(
                    "protected_descendant:{}",
                    prot.reason
                )));
            }

            let rel_path = if rel_prefix.is_empty() {
                name_str.clone()
            } else {
                format!("{rel_prefix}/{name_str}")
            };

            let in_dot_git =
                state.skip_dot_git && (rel_path == ".git" || rel_path.starts_with(".git/"));

            if mode == libc::S_IFDIR {
                if !in_dot_git {
                    let (ms, mn) = stat_mtime(&child_st);
                    state.records.push((
                        rel_path.clone(),
                        "dir".to_string(),
                        Some(child_st.st_dev as u64),
                        Some(child_st.st_ino as u64),
                        child_st.st_size as u64,
                        ms,
                        mn,
                        String::new(),
                    ));
                }
                let sub_fd = openat_nofollow(
                    dir_fd.as_raw_fd(),
                    &name_c,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )?;
                let sub_st = fstat_fd(&sub_fd)?;
                if (sub_st.st_mode & libc::S_IFMT) != libc::S_IFDIR
                    || (sub_st.st_dev as u64) != state.root_dev
                    || !stat_matches_dev_ino(&sub_st, &child_st)
                {
                    return Err(SjError::ExecutionGate(format!(
                        "subdirectory fd identity mismatch: {}",
                        child_full_path.display()
                    )));
                }
                let mut sub_manifest = ManifestDir {
                    name_c: name_c.clone(),
                    name_str: name_str.clone(),
                    dev: sub_st.st_dev as u64,
                    ino: sub_st.st_ino as u64,
                    dirs: Vec::new(),
                    files: Vec::new(),
                };
                inspect_dir_fd_recursive(
                    &sub_fd,
                    &child_full_path,
                    &rel_path,
                    depth + 1,
                    state,
                    &mut sub_manifest,
                )?;
                manifest.dirs.push(sub_manifest);
            } else if mode == libc::S_IFREG {
                if !in_dot_git {
                    let file_fd = openat_nofollow(
                        dir_fd.as_raw_fd(),
                        &name_c,
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )?;
                    let file_st = fstat_fd(&file_fd)?;
                    if (file_st.st_mode & libc::S_IFMT) != libc::S_IFREG
                        || !stat_matches_reg_identity(&file_st, &child_st)
                    {
                        return Err(SjError::ExecutionGate(format!(
                            "file fd identity mismatch: {}",
                            child_full_path.display()
                        )));
                    }
                    let content_sha256 = hash_fd_stable(&file_fd, &child_st)?;
                    let (ms, mn) = stat_mtime(&child_st);
                    state.records.push((
                        rel_path,
                        "file".to_string(),
                        Some(child_st.st_dev as u64),
                        Some(child_st.st_ino as u64),
                        child_st.st_size as u64,
                        ms,
                        mn,
                        content_sha256,
                    ));
                }
                manifest.files.push(ManifestFile {
                    name_c,
                    name_str,
                    dev: child_st.st_dev as u64,
                    ino: child_st.st_ino as u64,
                    size: child_st.st_size as u64,
                    mtime_secs: child_st.st_mtime as i64,
                    mtime_nsec: child_st.st_mtime_nsec as i64,
                });
            } else {
                return Err(SjError::ProtectedPath(format!(
                    "refusing special file descendant: {}",
                    child_full_path.display()
                )));
            }
        }
        Ok(())
    }

    pub(super) fn delete_dir_from_manifest(
        dir_fd: &OwnedFd,
        dir_path: &Path,
        manifest: &ManifestDir,
        root_dev: u64,
        ctx: &ProtectionContext,
        depth: usize,
    ) -> Result<(), SjError> {
        use std::collections::HashSet;

        if depth > MAX_DIR_DEPTH {
            return Err(SjError::ExecutionGate(
                "directory depth limit exceeded during safe deletion".to_string(),
            ));
        }
        let guard = fd_to_dir(dir_fd)?;
        let mut live_names: Vec<String> = Vec::new();
        loop {
            set_errno(0);
            let dent = unsafe { libc::readdir(guard.0) };
            if dent.is_null() {
                let err = get_errno();
                if err != 0 {
                    return Err(SjError::Io(std::io::Error::from_raw_os_error(err)));
                }
                break;
            }
            let name_c = unsafe { CStr::from_ptr((*dent).d_name.as_ptr()) };
            let name_str = name_c.to_str().map_err(|_| {
                SjError::ExecutionGate("non-UTF-8 directory entry name".to_string())
            })?;
            if name_str == "." || name_str == ".." {
                continue;
            }
            live_names.push(name_str.to_string());
        }
        drop(guard);

        let expected_names: HashSet<&str> = manifest
            .dirs
            .iter()
            .map(|d| d.name_str.as_str())
            .chain(manifest.files.iter().map(|f| f.name_str.as_str()))
            .collect();
        let live_set: HashSet<&str> = live_names.iter().map(String::as_str).collect();
        if live_names.len() != expected_names.len()
            || live_set.len() != expected_names.len()
            || !live_set.iter().all(|n| expected_names.contains(n))
        {
            return Err(SjError::ExecutionGate(
                "directory contents drifted from reviewed manifest; aborting deletion".to_string(),
            ));
        }

        for sub in &manifest.dirs {
            let sub_path = dir_path.join(&sub.name_str);
            let prot = check_path_protection(&sub_path, ctx);
            if prot.protected {
                return Err(SjError::ProtectedPath(format!(
                    "protected_descendant:{}",
                    prot.reason
                )));
            }
            let child_st = fstatat_nofollow(dir_fd, &sub.name_c)?;
            if (child_st.st_mode & libc::S_IFMT) != libc::S_IFDIR
                || (child_st.st_dev as u64) != root_dev
                || (child_st.st_dev as u64) != sub.dev
                || (child_st.st_ino as u64) != sub.ino
            {
                return Err(SjError::ExecutionGate(
                    "subdirectory identity drifted from reviewed manifest; aborting deletion"
                        .to_string(),
                ));
            }
            let sub_fd = openat_nofollow(
                dir_fd.as_raw_fd(),
                &sub.name_c,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?;
            let sub_st = fstat_fd(&sub_fd)?;
            if (sub_st.st_mode & libc::S_IFMT) != libc::S_IFDIR
                || (sub_st.st_dev as u64) != sub.dev
                || (sub_st.st_ino as u64) != sub.ino
            {
                return Err(SjError::ExecutionGate(
                    "subdirectory fd identity mismatch during manifest deletion".to_string(),
                ));
            }
            delete_dir_from_manifest(&sub_fd, &sub_path, sub, root_dev, ctx, depth + 1)?;
            drop(sub_fd);

            let recheck_st = fstatat_nofollow(dir_fd, &sub.name_c)?;
            if (recheck_st.st_mode & libc::S_IFMT) != libc::S_IFDIR
                || (recheck_st.st_dev as u64) != sub.dev
                || (recheck_st.st_ino as u64) != sub.ino
            {
                return Err(SjError::ExecutionGate(
                    "subdirectory identity changed before unlinkat; aborting deletion".to_string(),
                ));
            }
            let rc = unsafe {
                libc::unlinkat(dir_fd.as_raw_fd(), sub.name_c.as_ptr(), libc::AT_REMOVEDIR)
            };
            if rc != 0 {
                return Err(last_os_err());
            }
        }

        for file in &manifest.files {
            let file_path = dir_path.join(&file.name_str);
            let prot = check_path_protection(&file_path, ctx);
            if prot.protected {
                return Err(SjError::ProtectedPath(format!(
                    "protected_descendant:{}",
                    prot.reason
                )));
            }
            let child_st = fstatat_nofollow(dir_fd, &file.name_c)?;
            if (child_st.st_mode & libc::S_IFMT) != libc::S_IFREG
                || (child_st.st_dev as u64) != file.dev
                || (child_st.st_ino as u64) != file.ino
                || (child_st.st_size as u64) != file.size
                || (child_st.st_mtime as i64) != file.mtime_secs
                || (child_st.st_mtime_nsec as i64) != file.mtime_nsec
            {
                return Err(SjError::ExecutionGate(
                    "file identity drifted from reviewed manifest; aborting deletion".to_string(),
                ));
            }
            let file_fd = openat_nofollow(
                dir_fd.as_raw_fd(),
                &file.name_c,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?;
            let f_st = fstat_fd(&file_fd)?;
            if (f_st.st_mode & libc::S_IFMT) != libc::S_IFREG
                || (f_st.st_dev as u64) != file.dev
                || (f_st.st_ino as u64) != file.ino
                || (f_st.st_size as u64) != file.size
                || (f_st.st_mtime as i64) != file.mtime_secs
                || (f_st.st_mtime_nsec as i64) != file.mtime_nsec
            {
                return Err(SjError::ExecutionGate(
                    "file fd identity mismatch during manifest deletion".to_string(),
                ));
            }
            drop(file_fd);

            let recheck_st = fstatat_nofollow(dir_fd, &file.name_c)?;
            if (recheck_st.st_mode & libc::S_IFMT) != libc::S_IFREG
                || (recheck_st.st_dev as u64) != file.dev
                || (recheck_st.st_ino as u64) != file.ino
                || (recheck_st.st_size as u64) != file.size
                || (recheck_st.st_mtime as i64) != file.mtime_secs
                || (recheck_st.st_mtime_nsec as i64) != file.mtime_nsec
            {
                return Err(SjError::ExecutionGate(
                    "file identity changed before unlinkat; aborting deletion".to_string(),
                ));
            }
            let rc = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), file.name_c.as_ptr(), 0) };
            if rc != 0 {
                return Err(last_os_err());
            }
        }
        Ok(())
    }

    pub(super) fn capture_snapshot_unix(
        target: &Path,
        is_orphan: bool,
        ctx: &ProtectionContext,
    ) -> Result<TargetSnapshot, SjError> {
        if is_symlink_path(target)? {
            return Err(SjError::ProtectedPath(format!(
                "refusing symlink target: {}",
                target.display()
            )));
        }
        let canon_target = std::fs::canonicalize(target)?;
        let canon_parent = canon_target.parent().ok_or_else(|| {
            SjError::ExecutionGate(format!("target has no parent: {}", canon_target.display()))
        })?;
        let leaf = canon_target
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                SjError::ExecutionGate(format!(
                    "target has invalid filename: {}",
                    canon_target.display()
                ))
            })?;
        let parent_fd = open_dir_nofollow_from_root(canon_parent)?;
        let leaf_c = to_cstring(leaf)?;
        let st_leaf = fstatat_nofollow(&parent_fd, &leaf_c)?;
        let mode = st_leaf.st_mode & libc::S_IFMT;

        if mode == libc::S_IFREG {
            let file_fd = openat_nofollow(
                parent_fd.as_raw_fd(),
                &leaf_c,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?;
            let st = fstat_fd(&file_fd)?;
            let size = st.st_size as u64;
            let (ms, mn) = stat_mtime(&st);
            let content_hash = hash_fd_stable(&file_fd, &st)?;
            Ok(TargetSnapshot {
                entry_type: "file".to_string(),
                dev: Some(st.st_dev as u64),
                ino: Some(st.st_ino as u64),
                size,
                mtime_secs: ms,
                mtime_nanos: mn,
                content_or_tree_sha256: content_hash,
                git_head: None,
                git_tree: None,
                git_refs_sha256: None,
            })
        } else if mode == libc::S_IFDIR {
            let dir_fd = openat_nofollow(
                parent_fd.as_raw_fd(),
                &leaf_c,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?;
            let st = fstat_fd(&dir_fd)?;
            let mut state = InspectState {
                root_dev: st.st_dev as u64,
                seen: 0,
                skip_dot_git: is_orphan,
                ctx,
                records: Vec::new(),
            };
            let mut root_manifest = ManifestDir {
                name_c: leaf_c,
                name_str: leaf.to_string(),
                dev: st.st_dev as u64,
                ino: st.st_ino as u64,
                dirs: Vec::new(),
                files: Vec::new(),
            };
            inspect_dir_fd_recursive(
                &dir_fd,
                &canon_target,
                "",
                1,
                &mut state,
                &mut root_manifest,
            )?;
            state.records.sort();
            let tree_hash = hash_dir_tree_records(&state.records);
            let (ms, mn) = stat_mtime(&st);
            let (git_head, git_tree, git_refs_sha256) = if is_orphan {
                let (h, t, r) = capture_git_snapshot_identity(&canon_target)?;
                (Some(h), Some(t), Some(r))
            } else {
                (None, None, None)
            };
            Ok(TargetSnapshot {
                entry_type: "dir".to_string(),
                dev: Some(st.st_dev as u64),
                ino: Some(st.st_ino as u64),
                size: st.st_size as u64,
                mtime_secs: ms,
                mtime_nanos: mn,
                content_or_tree_sha256: tree_hash,
                git_head,
                git_tree,
                git_refs_sha256,
            })
        } else {
            Err(SjError::ProtectedPath(format!(
                "refusing non-file/non-dir target: {}",
                target.display()
            )))
        }
    }

    pub(super) fn safe_remove_plan_item_unix(
        item: &PlanItem,
        ctx: &ProtectionContext,
        allowed_trash_roots: &[PathBuf],
    ) -> Result<(), SjError> {
        let target = Path::new(&item.path);
        let prot = check_path_protection(target, ctx);
        if prot.protected {
            return Err(SjError::ProtectedPath(prot.reason));
        }
        if is_symlink_path(target)? {
            return Err(SjError::ProtectedPath(format!(
                "refusing symlink target: {}",
                target.display()
            )));
        }

        let (parent_fd, leaf_c, canon_target, is_orphan) = match item.kind.as_str() {
            "trash_item" => {
                let canon_target = std::fs::canonicalize(target)?;
                let mut matched_root: Option<PathBuf> = None;
                for root in allowed_trash_roots {
                    if !root.exists() || is_symlink_path(root).unwrap_or(true) {
                        continue;
                    }
                    if let Ok(canon_root) = std::fs::canonicalize(root) {
                        if canon_target.starts_with(&canon_root) && canon_target != canon_root {
                            matched_root = Some(canon_root);
                            break;
                        }
                    }
                }
                let Some(canon_root) = matched_root else {
                    return Err(SjError::ExecutionGate(format!(
                        "refusing trash_item outside verified OS Trash roots: {}",
                        target.display()
                    )));
                };
                let prot_canon = check_path_protection(&canon_target, ctx);
                if prot_canon.protected {
                    return Err(SjError::ProtectedPath(prot_canon.reason));
                }
                let rel = canon_target.strip_prefix(&canon_root).map_err(|_| {
                    SjError::ExecutionGate("failed to strip canonical trash root".to_string())
                })?;
                let rel_parent = rel.parent().unwrap_or_else(|| Path::new(""));
                let leaf = rel
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| SjError::ExecutionGate("invalid trash item leaf".to_string()))?;
                let root_fd = open_dir_nofollow_from_root(&canon_root)?;
                let parent_fd = open_rel_dir_nofollow(root_fd, rel_parent)?;
                (parent_fd, to_cstring(leaf)?, canon_target, false)
            }
            "orphan_worktree" => {
                let canon_target = std::fs::canonicalize(target)?;
                let prot_canon = check_path_protection(&canon_target, ctx);
                if prot_canon.protected {
                    return Err(SjError::ProtectedPath(prot_canon.reason));
                }
                if is_symlink_path(&canon_target)? {
                    return Err(SjError::ProtectedPath(format!(
                        "refusing symlink target: {}",
                        canon_target.display()
                    )));
                }
                let canon_parent = canon_target.parent().ok_or_else(|| {
                    SjError::ExecutionGate("orphan target has no parent".to_string())
                })?;
                let leaf = canon_target
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| SjError::ExecutionGate("invalid orphan leaf".to_string()))?;
                let parent_fd = open_dir_nofollow_from_root(canon_parent)?;
                (parent_fd, to_cstring(leaf)?, canon_target, true)
            }
            other => {
                return Err(SjError::ExecutionGate(format!(
                    "unsupported plan item kind: {other}"
                )));
            }
        };

        let st_leaf = fstatat_nofollow(&parent_fd, &leaf_c)?;
        let mode = st_leaf.st_mode & libc::S_IFMT;

        if mode == libc::S_IFLNK {
            return Err(SjError::ProtectedPath(format!(
                "refusing symlink target: {}",
                target.display()
            )));
        }

        if !is_orphan && mode == libc::S_IFREG {
            if item.snapshot.entry_type != "file" {
                return Err(SjError::ExecutionGate(
                    "snapshot entry_type mismatch (expected dir, found file)".to_string(),
                ));
            }
            let file_fd = openat_nofollow(
                parent_fd.as_raw_fd(),
                &leaf_c,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?;
            let st = fstat_fd(&file_fd)?;
            if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
                return Err(SjError::ExecutionGate(
                    "opened fd is not a regular file".to_string(),
                ));
            }
            if !snapshot_matches_stat(&item.snapshot, &st) {
                return Err(SjError::ExecutionGate(
                    "target dev/ino changed since plan; regenerate plan".to_string(),
                ));
            }
            let size = st.st_size as u64;
            let (ms, mn) = stat_mtime(&st);
            let content_hash = hash_fd_stable(&file_fd, &st)?;
            drop(file_fd);
            let live_snapshot = TargetSnapshot {
                entry_type: "file".to_string(),
                dev: Some(st.st_dev as u64),
                ino: Some(st.st_ino as u64),
                size,
                mtime_secs: ms,
                mtime_nanos: mn,
                content_or_tree_sha256: content_hash,
                git_head: None,
                git_tree: None,
                git_refs_sha256: None,
            };
            if live_snapshot != item.snapshot {
                return Err(SjError::ExecutionGate(
                    "target snapshot mismatch; regenerate plan".to_string(),
                ));
            }
            let st_recheck = fstatat_nofollow(&parent_fd, &leaf_c)?;
            if !stat_matches_dev_ino(&st_recheck, &st) {
                return Err(SjError::ExecutionGate(
                    "target changed before unlinkat; aborting".to_string(),
                ));
            }
            let rc = unsafe { libc::unlinkat(parent_fd.as_raw_fd(), leaf_c.as_ptr(), 0) };
            if rc != 0 {
                return Err(last_os_err());
            }
            return Ok(());
        }

        if mode != libc::S_IFDIR {
            return Err(SjError::ExecutionGate(format!(
                "target is not a directory: {}",
                target.display()
            )));
        }
        if item.snapshot.entry_type != "dir" {
            return Err(SjError::ExecutionGate(
                "snapshot entry_type mismatch (expected file, found dir)".to_string(),
            ));
        }

        let target_dir_fd = openat_nofollow(
            parent_fd.as_raw_fd(),
            &leaf_c,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;
        let st_root = fstat_fd(&target_dir_fd)?;
        if (st_root.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            return Err(SjError::ExecutionGate(
                "opened fd is not a directory".to_string(),
            ));
        }
        if !snapshot_matches_stat(&item.snapshot, &st_root) {
            return Err(SjError::ExecutionGate(
                "target directory dev/ino changed since plan; regenerate plan".to_string(),
            ));
        }

        let root_dev = st_root.st_dev as u64;
        let (git_head, git_tree, git_refs_sha256) = if is_orphan {
            let st_lstat_before = lstat_path(&canon_target)?;
            let st_at_before = fstatat_nofollow(&parent_fd, &leaf_c)?;
            if !stat_matches_dev_ino(&st_root, &st_lstat_before)
                || !stat_matches_dev_ino(&st_root, &st_at_before)
            {
                return Err(SjError::ExecutionGate(
                    "orphan directory identity mismatch before git checks".to_string(),
                ));
            }

            verify_orphan_safe_to_remove(&canon_target, ctx)?;
            let (h, t, r) = capture_git_snapshot_identity(&canon_target)?;

            let st_lstat_after = lstat_path(&canon_target)?;
            let st_at_after = fstatat_nofollow(&parent_fd, &leaf_c)?;
            if !stat_matches_dev_ino(&st_root, &st_lstat_after)
                || !stat_matches_dev_ino(&st_root, &st_at_after)
            {
                return Err(SjError::ExecutionGate(
                    "orphan directory identity changed during git checks".to_string(),
                ));
            }
            let prot_after = check_path_protection(&canon_target, ctx);
            if prot_after.protected {
                return Err(SjError::ProtectedPath(prot_after.reason));
            }
            if is_symlink_path(&canon_target)? {
                return Err(SjError::ProtectedPath(format!(
                    "refusing symlink target: {}",
                    canon_target.display()
                )));
            }
            (Some(h), Some(t), Some(r))
        } else {
            (None, None, None)
        };

        let mut state = InspectState {
            root_dev,
            seen: 0,
            skip_dot_git: is_orphan,
            ctx,
            records: Vec::new(),
        };
        let mut root_manifest = ManifestDir {
            name_c: leaf_c.clone(),
            name_str: leaf_c.to_string_lossy().into_owned(),
            dev: st_root.st_dev as u64,
            ino: st_root.st_ino as u64,
            dirs: Vec::new(),
            files: Vec::new(),
        };
        inspect_dir_fd_recursive(
            &target_dir_fd,
            &canon_target,
            "",
            1,
            &mut state,
            &mut root_manifest,
        )?;
        state.records.sort();
        let tree_hash = hash_dir_tree_records(&state.records);

        let (ms, mn) = stat_mtime(&st_root);
        let live_snapshot = TargetSnapshot {
            entry_type: "dir".to_string(),
            dev: Some(st_root.st_dev as u64),
            ino: Some(st_root.st_ino as u64),
            size: st_root.st_size as u64,
            mtime_secs: ms,
            mtime_nanos: mn,
            content_or_tree_sha256: tree_hash,
            git_head,
            git_tree,
            git_refs_sha256,
        };
        if live_snapshot != item.snapshot {
            return Err(SjError::ExecutionGate(
                "target directory snapshot mismatch; regenerate plan".to_string(),
            ));
        }

        delete_dir_from_manifest(
            &target_dir_fd,
            &canon_target,
            &root_manifest,
            root_dev,
            ctx,
            1,
        )?;
        drop(target_dir_fd);

        let st_recheck = fstatat_nofollow(&parent_fd, &leaf_c)?;
        if !stat_matches_dev_ino(&st_recheck, &st_root) {
            return Err(SjError::ExecutionGate(
                "target directory changed before final unlinkat; aborting".to_string(),
            ));
        }
        let rc =
            unsafe { libc::unlinkat(parent_fd.as_raw_fd(), leaf_c.as_ptr(), libc::AT_REMOVEDIR) };
        if rc != 0 {
            return Err(last_os_err());
        }

        Ok(())
    }
}

#[cfg_attr(unix, allow(dead_code))]
fn metadata_mtime(meta: &std::fs::Metadata) -> (Option<i64>, Option<u32>) {
    match meta.modified() {
        Ok(st) => match st.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => (Some(d.as_secs() as i64), Some(d.subsec_nanos())),
            Err(e) => {
                let d = e.duration();
                let secs = d.as_secs() as i64;
                let nanos = d.subsec_nanos();
                if nanos == 0 {
                    (Some(-secs), Some(0))
                } else {
                    (Some(-secs - 1), Some(1_000_000_000 - nanos))
                }
            }
        },
        Err(_) => (None, None),
    }
}

#[cfg_attr(unix, allow(dead_code))]
fn hash_file_stable_portable(
    path: &Path,
    meta_before: &std::fs::Metadata,
) -> Result<String, SjError> {
    if !meta_before.is_file() {
        return Err(SjError::ExecutionGate(format!(
            "cannot hash non-regular file: {}",
            path.display()
        )));
    }
    let mut file = std::fs::File::open(path)?;
    let open_before = file.metadata()?;
    if !open_before.is_file()
        || open_before.len() != meta_before.len()
        || metadata_mtime(&open_before) != metadata_mtime(meta_before)
    {
        return Err(SjError::ExecutionGate(format!(
            "file metadata changed on open: {}",
            path.display()
        )));
    }
    let (digest, bytes_read) = hash_file_reader(&mut file)?;
    let open_after = file.metadata()?;
    if bytes_read != meta_before.len()
        || open_after.len() != meta_before.len()
        || metadata_mtime(&open_after) != metadata_mtime(meta_before)
    {
        return Err(SjError::ExecutionGate(format!(
            "file changed while hashing: {}",
            path.display()
        )));
    }
    Ok(digest)
}

#[cfg_attr(unix, allow(dead_code))]
pub(crate) fn capture_snapshot_portable(
    target: &Path,
    is_orphan: bool,
    ctx: &ProtectionContext,
) -> Result<TargetSnapshot, SjError> {
    if is_symlink_path(target)? {
        return Err(SjError::ProtectedPath(format!(
            "refusing symlink target: {}",
            target.display()
        )));
    }
    let prot = check_path_protection(target, ctx);
    if prot.protected {
        return Err(SjError::ProtectedPath(prot.reason));
    }

    let meta = std::fs::symlink_metadata(target)?;
    if meta.file_type().is_symlink() {
        return Err(SjError::ProtectedPath(format!(
            "refusing symlink target: {}",
            target.display()
        )));
    }
    let (mtime_secs, mtime_nanos) = metadata_mtime(&meta);

    if meta.is_file() {
        let size = meta.len();
        let content_hash = hash_file_stable_portable(target, &meta)?;
        Ok(TargetSnapshot {
            entry_type: "file".to_string(),
            dev: None,
            ino: None,
            size,
            mtime_secs,
            mtime_nanos,
            content_or_tree_sha256: content_hash,
            git_head: None,
            git_tree: None,
            git_refs_sha256: None,
        })
    } else if meta.is_dir() {
        let mut seen: usize = 0;
        let mut records: Vec<DirTreeRecord> = Vec::new();
        let walker = jwalk::WalkDir::new(target)
            .follow_links(false)
            .skip_hidden(false);

        for entry_res in walker {
            let entry = entry_res.map_err(|e| {
                SjError::ExecutionGate(format!("portable snapshot walk failed: {e}"))
            })?;
            if entry.read_children_error.is_some() {
                return Err(SjError::ExecutionGate(format!(
                    "unreadable directory during snapshot: {}",
                    entry.path().display()
                )));
            }
            if entry.depth == 0 {
                continue;
            }
            seen += 1;
            if seen > MAX_DIR_ENTRIES {
                return Err(SjError::ExecutionGate(format!(
                    "directory entry limit ({MAX_DIR_ENTRIES}) exceeded"
                )));
            }
            let entry_path = entry.path();
            if entry.file_type.is_symlink() || is_symlink_path(&entry_path)? {
                return Err(SjError::ProtectedPath(format!(
                    "symlink_descendant:{}",
                    entry_path.display()
                )));
            }
            let prot = check_path_protection(&entry_path, ctx);
            if prot.protected {
                return Err(SjError::ProtectedPath(format!(
                    "protected_descendant:{}",
                    prot.reason
                )));
            }
            let rel = entry_path.strip_prefix(target).map_err(|_| {
                SjError::ExecutionGate(format!(
                    "entry {} outside target {}",
                    entry_path.display(),
                    target.display()
                ))
            })?;
            let rel_path = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let in_dot_git = is_orphan && (rel_path == ".git" || rel_path.starts_with(".git/"));
            if in_dot_git {
                continue;
            }

            let child_meta = std::fs::symlink_metadata(&entry_path)?;
            if child_meta.file_type().is_symlink() {
                return Err(SjError::ProtectedPath(format!(
                    "symlink_descendant:{}",
                    entry_path.display()
                )));
            }
            let (entry_type, content_sha256) = if child_meta.is_dir() {
                ("dir", String::new())
            } else if child_meta.is_file() {
                ("file", hash_file_stable_portable(&entry_path, &child_meta)?)
            } else {
                return Err(SjError::ProtectedPath(format!(
                    "refusing special file descendant: {}",
                    entry_path.display()
                )));
            };
            let (ms, mn) = metadata_mtime(&child_meta);
            records.push((
                rel_path,
                entry_type.to_string(),
                None,
                None,
                child_meta.len(),
                ms,
                mn,
                content_sha256,
            ));
        }
        records.sort();
        let tree_hash = hash_dir_tree_records(&records);
        let (git_head, git_tree, git_refs_sha256) = if is_orphan {
            let (h, t, r) = capture_git_snapshot_identity(target)?;
            (Some(h), Some(t), Some(r))
        } else {
            (None, None, None)
        };
        Ok(TargetSnapshot {
            entry_type: "dir".to_string(),
            dev: None,
            ino: None,
            size: meta.len(),
            mtime_secs,
            mtime_nanos,
            content_or_tree_sha256: tree_hash,
            git_head,
            git_tree,
            git_refs_sha256,
        })
    } else {
        Err(SjError::ProtectedPath(format!(
            "refusing non-file/non-dir target: {}",
            target.display()
        )))
    }
}

pub(crate) fn capture_target_snapshot(
    target: &Path,
    is_orphan: bool,
    ctx: &ProtectionContext,
) -> Result<TargetSnapshot, SjError> {
    #[cfg(unix)]
    {
        unix_impl::capture_snapshot_unix(target, is_orphan, ctx)
    }
    #[cfg(not(unix))]
    {
        capture_snapshot_portable(target, is_orphan, ctx)
    }
}

pub(crate) fn safe_remove_plan_item(
    item: &PlanItem,
    ctx: &ProtectionContext,
    allowed_trash_roots: &[PathBuf],
) -> Result<(), SjError> {
    #[cfg(unix)]
    {
        unix_impl::safe_remove_plan_item_unix(item, ctx, allowed_trash_roots)
    }
    #[cfg(not(unix))]
    {
        let _ = (item, ctx, allowed_trash_roots);
        Err(SjError::ExecutionGate(
            "safe handle-anchored execution is not supported on this platform; dry-run planning only"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Cursor;
    use std::process::Command;
    use tempfile::tempdir;

    fn run_git(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .current_dir(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "Test User")
            .env("GIT_AUTHOR_EMAIL", "test@example.com")
            .env("GIT_COMMITTER_NAME", "Test User")
            .env("GIT_COMMITTER_EMAIL", "test@example.com")
            .output()
            .expect("git command should run");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn hash_file_reader_streams_full_65mib_without_sampling() {
        let size = 65 * 1024 * 1024;
        let data1 = vec![0u8; size];
        let mut data2 = vec![0u8; size];
        data2[32 * 1024 * 1024] = 1;

        let mut c1 = Cursor::new(data1);
        let mut c2 = Cursor::new(data2);

        let (h1, len1) = hash_file_reader(&mut c1).unwrap();
        let (h2, len2) = hash_file_reader(&mut c2).unwrap();

        assert_eq!(len1, size as u64);
        assert_eq!(len2, size as u64);
        assert_ne!(
            h1, h2,
            "1-byte flip at offset 32 MiB inside 65 MiB stream must change digest"
        );
    }

    #[test]
    fn capture_snapshot_portable_covers_regular_file_and_clean_orphan_deterministically() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);

        let file_path = root.join("sample.txt");
        fs::write(&file_path, b"hello portable\n").unwrap();

        let snap1 = capture_snapshot_portable(&file_path, false, &ctx).unwrap();
        let snap2 = capture_snapshot_portable(&file_path, false, &ctx).unwrap();
        assert_eq!(snap1, snap2);
        assert_eq!(snap1.entry_type, "file");
        assert_eq!(snap1.dev, None);
        assert_eq!(snap1.ino, None);
        assert_eq!(snap1.size, 15);
        assert!(!snap1.content_or_tree_sha256.is_empty());
        assert_eq!(snap1.git_head, None);
        assert_eq!(snap1.git_tree, None);
        assert_eq!(snap1.git_refs_sha256, None);

        let remote_dir = root.join("remote.git");
        fs::create_dir_all(&remote_dir).unwrap();
        run_git(&remote_dir, &["init", "--bare"]);

        let orphan_dir = root.join("orphan_repo");
        fs::create_dir_all(&orphan_dir).unwrap();
        run_git(&orphan_dir, &["init"]);
        fs::write(orphan_dir.join("README.md"), "portable snapshot\n").unwrap();
        run_git(&orphan_dir, &["add", "README.md"]);
        run_git(&orphan_dir, &["commit", "-m", "init"]);
        run_git(
            &orphan_dir,
            &["remote", "add", "origin", remote_dir.to_str().unwrap()],
        );
        run_git(&orphan_dir, &["push", "-u", "origin", "HEAD"]);

        let dir_snap1 = capture_snapshot_portable(&orphan_dir, true, &ctx).unwrap();
        let dir_snap2 = capture_snapshot_portable(&orphan_dir, true, &ctx).unwrap();
        assert_eq!(dir_snap1, dir_snap2);
        assert_eq!(dir_snap1.entry_type, "dir");
        assert_eq!(dir_snap1.dev, None);
        assert_eq!(dir_snap1.ino, None);
        assert!(!dir_snap1.content_or_tree_sha256.is_empty());
        assert!(dir_snap1.git_head.as_deref().is_some_and(|s| !s.is_empty()));
        assert!(dir_snap1.git_tree.as_deref().is_some_and(|s| !s.is_empty()));
        assert!(dir_snap1
            .git_refs_sha256
            .as_deref()
            .is_some_and(|s| !s.is_empty()));
    }

    #[cfg(unix)]
    mod unix_manifest_tests {
        use super::*;
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::fs::MetadataExt;
        use unix_impl::{delete_dir_from_manifest, ManifestDir, ManifestFile};

        fn open_dir_fd(path: &Path) -> OwnedFd {
            let c = CString::new(path.to_str().unwrap()).unwrap();
            let fd = unsafe {
                libc::open(
                    c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            assert!(fd >= 0, "open dir failed: {}", path.display());
            unsafe { OwnedFd::from_raw_fd(fd) }
        }

        fn build_manifest_file(path: &Path, name: &str) -> ManifestFile {
            let meta = fs::symlink_metadata(path.join(name)).unwrap();
            ManifestFile {
                name_c: CString::new(name).unwrap(),
                name_str: name.to_string(),
                dev: meta.dev(),
                ino: meta.ino(),
                size: meta.size(),
                mtime_secs: meta.mtime(),
                mtime_nsec: meta.mtime_nsec(),
            }
        }

        #[test]
        fn delete_dir_from_manifest_rejects_unexpected_unreviewed_file_and_preserves_all() {
            let tmp = tempdir().unwrap();
            let target = tmp.path().join("target_dir");
            fs::create_dir_all(&target).unwrap();
            let file_a = target.join("a.txt");
            let file_b = target.join("b.txt");
            fs::write(&file_a, b"alpha").unwrap();
            fs::write(&file_b, b"beta").unwrap();

            let dir_meta = fs::symlink_metadata(&target).unwrap();
            let manifest = ManifestDir {
                name_c: CString::new("target_dir").unwrap(),
                name_str: "target_dir".to_string(),
                dev: dir_meta.dev(),
                ino: dir_meta.ino(),
                dirs: Vec::new(),
                files: vec![
                    build_manifest_file(&target, "a.txt"),
                    build_manifest_file(&target, "b.txt"),
                ],
            };

            let dir_fd = open_dir_fd(&target);
            // Inject an unreviewed file into the open directory before deletion
            let injected = target.join("unexpected.txt");
            fs::write(&injected, b"do not delete").unwrap();

            let ctx = ProtectionContext::new(tmp.path().to_path_buf(), vec![]);
            let res =
                delete_dir_from_manifest(&dir_fd, &target, &manifest, dir_meta.dev(), &ctx, 1);
            assert!(
                matches!(res, Err(SjError::ExecutionGate(_))),
                "unexpected file must fail closed: {res:?}"
            );
            assert!(file_a.exists(), "existing file a.txt must be preserved");
            assert!(file_b.exists(), "existing file b.txt must be preserved");
            assert!(injected.exists(), "injected file must be preserved");
            let _ = dir_fd.as_raw_fd();
        }

        #[test]
        fn delete_dir_from_manifest_rejects_mutated_file_and_preserves_it() {
            let tmp = tempdir().unwrap();
            let target = tmp.path().join("target_dir");
            fs::create_dir_all(&target).unwrap();
            let file_a = target.join("a.txt");
            fs::write(&file_a, b"initial").unwrap();

            let dir_meta = fs::symlink_metadata(&target).unwrap();
            let manifest = ManifestDir {
                name_c: CString::new("target_dir").unwrap(),
                name_str: "target_dir".to_string(),
                dev: dir_meta.dev(),
                ino: dir_meta.ino(),
                dirs: Vec::new(),
                files: vec![build_manifest_file(&target, "a.txt")],
            };

            let dir_fd = open_dir_fd(&target);
            // Replace a.txt with a new file (different inode/size)
            fs::remove_file(&file_a).unwrap();
            fs::write(&file_a, b"mutated content").unwrap();

            let ctx = ProtectionContext::new(tmp.path().to_path_buf(), vec![]);
            let res =
                delete_dir_from_manifest(&dir_fd, &target, &manifest, dir_meta.dev(), &ctx, 1);
            assert!(
                matches!(res, Err(SjError::ExecutionGate(_))),
                "mutated/replaced file must fail closed: {res:?}"
            );
            assert!(file_a.exists(), "mutated file must be preserved");
        }
    }
}
