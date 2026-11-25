use crate::orphans::capture_git_snapshot_identity_staged;
use crate::plan::{PlanItem, TargetSnapshot};
use crate::protect::{check_path_protection_anchored, is_symlink_path, ProtectionContext};
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
    use crate::orphans::{verify_orphan_safe_to_remove, verify_orphan_safe_to_remove_staged};
    use crate::protect::QUARANTINE_STAGE_PREFIX;
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
        pub(super) content_sha256: String,
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
            let prot = check_path_protection_anchored(&child_full_path, state.ctx);
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
                if !in_dot_git {
                    let (ms, mn) = stat_mtime(&child_st);
                    state.records.push((
                        rel_path,
                        "file".to_string(),
                        Some(child_st.st_dev as u64),
                        Some(child_st.st_ino as u64),
                        child_st.st_size as u64,
                        ms,
                        mn,
                        content_sha256.clone(),
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
                    content_sha256,
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

    fn verify_dir_against_manifest(
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
            let prot = check_path_protection_anchored(&sub_path, ctx);
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
                || (sub_st.st_dev as u64) != root_dev
                || (sub_st.st_dev as u64) != sub.dev
                || (sub_st.st_ino as u64) != sub.ino
            {
                return Err(SjError::ExecutionGate(
                    "subdirectory fd identity mismatch during manifest verification".to_string(),
                ));
            }
            verify_dir_against_manifest(&sub_fd, &sub_path, sub, root_dev, ctx, depth + 1)?;
        }

        for file in &manifest.files {
            let file_path = dir_path.join(&file.name_str);
            let prot = check_path_protection_anchored(&file_path, ctx);
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
                    "file fd identity mismatch during manifest verification".to_string(),
                ));
            }
            let live_sha = hash_fd_stable(&file_fd, &f_st)?;
            if live_sha != file.content_sha256 {
                return Err(SjError::ExecutionGate(
                    "file content digest drifted from reviewed manifest; aborting deletion"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    fn unlink_dir_from_manifest(
        dir_fd: &OwnedFd,
        dir_path: &Path,
        manifest: &ManifestDir,
        root_dev: u64,
        ctx: &ProtectionContext,
        depth: usize,
        any_unlinked: &mut bool,
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
            let prot = check_path_protection_anchored(&sub_path, ctx);
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
                || (sub_st.st_dev as u64) != root_dev
                || (sub_st.st_dev as u64) != sub.dev
                || (sub_st.st_ino as u64) != sub.ino
            {
                return Err(SjError::ExecutionGate(
                    "subdirectory fd identity mismatch during manifest deletion".to_string(),
                ));
            }
            unlink_dir_from_manifest(
                &sub_fd,
                &sub_path,
                sub,
                root_dev,
                ctx,
                depth + 1,
                any_unlinked,
            )?;
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
            *any_unlinked = true;
        }

        for file in &manifest.files {
            let file_path = dir_path.join(&file.name_str);
            let prot = check_path_protection_anchored(&file_path, ctx);
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
            let live_sha = hash_fd_stable(&file_fd, &f_st)?;
            if live_sha != file.content_sha256 {
                return Err(SjError::ExecutionGate(
                    "file content digest drifted from reviewed manifest; aborting deletion"
                        .to_string(),
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
            *any_unlinked = true;
        }
        Ok(())
    }

    pub(super) fn delete_dir_from_manifest_tracked(
        dir_fd: &OwnedFd,
        dir_path: &Path,
        manifest: &ManifestDir,
        root_dev: u64,
        ctx: &ProtectionContext,
        depth: usize,
        any_unlinked: &mut bool,
    ) -> Result<(), SjError> {
        if depth == 1 {
            verify_dir_against_manifest(dir_fd, dir_path, manifest, root_dev, ctx, depth)?;
        }
        unlink_dir_from_manifest(
            dir_fd,
            dir_path,
            manifest,
            root_dev,
            ctx,
            depth,
            any_unlinked,
        )
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn delete_dir_from_manifest(
        dir_fd: &OwnedFd,
        dir_path: &Path,
        manifest: &ManifestDir,
        root_dev: u64,
        ctx: &ProtectionContext,
        depth: usize,
    ) -> Result<(), SjError> {
        let mut any_unlinked = false;
        delete_dir_from_manifest_tracked(
            dir_fd,
            dir_path,
            manifest,
            root_dev,
            ctx,
            depth,
            &mut any_unlinked,
        )
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
                let (h, t, r) =
                    capture_git_snapshot_identity_staged(&canon_target, &canon_target, ctx)?;
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

    static STAGE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    pub(super) fn create_private_stage_dir(
        parent_fd: &OwnedFd,
        root_dev: u64,
    ) -> Result<(OwnedFd, CString, String), SjError> {
        use std::sync::atomic::Ordering;
        use std::time::{SystemTime, UNIX_EPOCH};

        let pid = std::process::id();
        for _ in 0..32 {
            let seq = STAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let mut urandom_buf = [0u8; 16];
            if let Ok(mut f) = File::open("/dev/urandom") {
                let _ = f.read_exact(&mut urandom_buf);
            }

            let mut hasher = Sha256::new();
            hasher.update(pid.to_le_bytes());
            hasher.update(seq.to_le_bytes());
            hasher.update(nanos.to_le_bytes());
            hasher.update(urandom_buf);
            let hex = sha256_to_hex(hasher.finalize());
            let stage_name = format!("{QUARANTINE_STAGE_PREFIX}{pid}-{}", &hex[..16]);
            let stage_c = to_cstring(&stage_name)?;

            let rc = unsafe { libc::mkdirat(parent_fd.as_raw_fd(), stage_c.as_ptr(), 0o700) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EEXIST) {
                    continue;
                }
                return Err(SjError::Io(err));
            }

            let stage_fd = openat_nofollow(
                parent_fd.as_raw_fd(),
                &stage_c,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?;
            let mut st = fstat_fd(&stage_fd)?;
            if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
                return Err(SjError::ExecutionGate(
                    "staging path is not a directory".to_string(),
                ));
            }
            let euid = unsafe { libc::geteuid() };
            if st.st_uid != euid {
                return Err(SjError::ExecutionGate(
                    "staging directory owner mismatch".to_string(),
                ));
            }
            if (st.st_dev as u64) != root_dev {
                return Err(SjError::ExecutionGate(
                    "staging directory device mismatch".to_string(),
                ));
            }
            if (st.st_mode & 0o777) != 0o700 {
                let chmod_rc = unsafe { libc::fchmod(stage_fd.as_raw_fd(), 0o700) };
                if chmod_rc != 0 {
                    return Err(last_os_err());
                }
                st = fstat_fd(&stage_fd)?;
                if (st.st_mode & 0o777) != 0o700 {
                    return Err(SjError::ExecutionGate(
                        "failed to enforce 0700 mode on staging directory".to_string(),
                    ));
                }
            }

            let guard = fd_to_dir(&stage_fd)?;
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
                let name_bytes = name_c.to_bytes();
                if name_bytes != b"." && name_bytes != b".." {
                    return Err(SjError::ExecutionGate(
                        "newly created staging directory is not empty".to_string(),
                    ));
                }
            }
            drop(guard);

            return Ok((stage_fd, stage_c, stage_name));
        }

        Err(SjError::ExecutionGate(
            "exhausted attempts creating unique private staging directory".to_string(),
        ))
    }

    pub(super) fn renameat_no_replace(
        from_dir: &OwnedFd,
        from_name: &CStr,
        to_dir: &OwnedFd,
        to_name: &CStr,
    ) -> Result<(), std::io::Error> {
        #[cfg(target_os = "macos")]
        {
            let rc = unsafe {
                libc::renameatx_np(
                    from_dir.as_raw_fd(),
                    from_name.as_ptr(),
                    to_dir.as_raw_fd(),
                    to_name.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            if rc == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
        #[cfg(target_os = "linux")]
        {
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    from_dir.as_raw_fd(),
                    from_name.as_ptr(),
                    to_dir.as_raw_fd(),
                    to_name.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            if rc == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            if fstatat_nofollow(to_dir, to_name).is_ok() {
                return Err(std::io::Error::from_raw_os_error(libc::EEXIST));
            }
            let rc = unsafe {
                libc::renameat(
                    from_dir.as_raw_fd(),
                    from_name.as_ptr(),
                    to_dir.as_raw_fd(),
                    to_name.as_ptr(),
                )
            };
            if rc == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
    }

    pub(super) fn restore_staged_or_preserve(
        parent_fd: &OwnedFd,
        leaf_c: &CStr,
        canon_target: &Path,
        stage_fd: &OwnedFd,
        stage_name_c: &CStr,
        stage_dir_path: &Path,
    ) -> Result<(), String> {
        let target_c = c"target";
        match renameat_no_replace(stage_fd, target_c, parent_fd, leaf_c) {
            Ok(()) => {
                let rc = unsafe {
                    libc::unlinkat(
                        parent_fd.as_raw_fd(),
                        stage_name_c.as_ptr(),
                        libc::AT_REMOVEDIR,
                    )
                };
                if rc != 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(format!(
                        "restored target to {} but failed to remove empty staging directory {}: {err}",
                        canon_target.display(),
                        stage_dir_path.display()
                    ));
                }
                Ok(())
            }
            Err(e) => Err(format!(
                "could not restore {} without overwrite ({e}); staged target preserved in quarantine at {} for manual recovery",
                canon_target.display(),
                stage_dir_path.join("target").display()
            )),
        }
    }

    pub(super) fn safe_remove_plan_item_unix(
        item: &PlanItem,
        ctx: &ProtectionContext,
        allowed_trash_roots: &[PathBuf],
    ) -> Result<(), SjError> {
        let target = Path::new(&item.path);
        let prot = check_path_protection_anchored(target, ctx);
        if prot.protected {
            return Err(SjError::ProtectedPath(prot.reason));
        }
        if is_symlink_path(target)? {
            return Err(SjError::ProtectedPath(format!(
                "refusing symlink target: {}",
                target.display()
            )));
        }

        let (parent_fd, leaf_c, canon_target, canon_parent, is_orphan) = match item.kind.as_str() {
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
                let prot_canon = check_path_protection_anchored(&canon_target, ctx);
                if prot_canon.protected {
                    return Err(SjError::ProtectedPath(prot_canon.reason));
                }
                let canon_parent = canon_target
                    .parent()
                    .ok_or_else(|| {
                        SjError::ExecutionGate("trash target has no parent".to_string())
                    })?
                    .to_path_buf();
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
                (
                    parent_fd,
                    to_cstring(leaf)?,
                    canon_target,
                    canon_parent,
                    false,
                )
            }
            "orphan_worktree" => {
                let canon_target = std::fs::canonicalize(target)?;
                let prot_canon = check_path_protection_anchored(&canon_target, ctx);
                if prot_canon.protected {
                    return Err(SjError::ProtectedPath(prot_canon.reason));
                }
                if is_symlink_path(&canon_target)? {
                    return Err(SjError::ProtectedPath(format!(
                        "refusing symlink target: {}",
                        canon_target.display()
                    )));
                }
                let canon_parent = canon_target
                    .parent()
                    .ok_or_else(|| {
                        SjError::ExecutionGate("orphan target has no parent".to_string())
                    })?
                    .to_path_buf();
                let leaf = canon_target
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| SjError::ExecutionGate("invalid orphan leaf".to_string()))?;
                let parent_fd = open_dir_nofollow_from_root(&canon_parent)?;
                (
                    parent_fd,
                    to_cstring(leaf)?,
                    canon_target,
                    canon_parent,
                    true,
                )
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

        let target_c = c"target";
        let st_parent = fstat_fd(&parent_fd)?;

        if !is_orphan && mode == libc::S_IFREG {
            if item.snapshot.entry_type != "file" {
                return Err(SjError::ExecutionGate(
                    "snapshot entry_type mismatch (expected dir, found file)".to_string(),
                ));
            }
            if !snapshot_matches_stat(&item.snapshot, &st_leaf) {
                return Err(SjError::ExecutionGate(
                    "target dev/ino changed since plan; regenerate plan".to_string(),
                ));
            }

            let (stage_fd, stage_name_c, stage_name_str) =
                create_private_stage_dir(&parent_fd, st_parent.st_dev as u64)?;
            let stage_dir_path = canon_parent.join(&stage_name_str);
            if let Err(e) = renameat_no_replace(&parent_fd, &leaf_c, &stage_fd, target_c) {
                drop(stage_fd);
                let _ = unsafe {
                    libc::unlinkat(
                        parent_fd.as_raw_fd(),
                        stage_name_c.as_ptr(),
                        libc::AT_REMOVEDIR,
                    )
                };
                return Err(SjError::Io(e));
            }

            let verify_staged_file = || -> Result<(), SjError> {
                let staged_file_fd = openat_nofollow(
                    stage_fd.as_raw_fd(),
                    target_c,
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )?;
                let st = fstat_fd(&staged_file_fd)?;
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
                let content_hash = hash_fd_stable(&staged_file_fd, &st)?;
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
                let st_recheck = fstatat_nofollow(&stage_fd, target_c)?;
                if !stat_matches_reg_identity(&st_recheck, &st) {
                    return Err(SjError::ExecutionGate(
                        "staged target changed before unlinkat; aborting".to_string(),
                    ));
                }
                Ok(())
            };

            if let Err(err) = verify_staged_file() {
                return match restore_staged_or_preserve(
                    &parent_fd,
                    &leaf_c,
                    &canon_target,
                    &stage_fd,
                    &stage_name_c,
                    &stage_dir_path,
                ) {
                    Ok(()) => Err(err),
                    Err(rollback_note) => {
                        Err(SjError::ExecutionGate(format!("{err}; {rollback_note}")))
                    }
                };
            }

            let rc = unsafe { libc::unlinkat(stage_fd.as_raw_fd(), target_c.as_ptr(), 0) };
            if rc != 0 {
                let err = last_os_err();
                return match restore_staged_or_preserve(
                    &parent_fd,
                    &leaf_c,
                    &canon_target,
                    &stage_fd,
                    &stage_name_c,
                    &stage_dir_path,
                ) {
                    Ok(()) => Err(err),
                    Err(rollback_note) => {
                        Err(SjError::ExecutionGate(format!("{err}; {rollback_note}")))
                    }
                };
            }
            drop(stage_fd);
            let rc = unsafe {
                libc::unlinkat(
                    parent_fd.as_raw_fd(),
                    stage_name_c.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            };
            if rc != 0 {
                let err = last_os_err();
                return Err(SjError::ExecutionGate(format!(
                    "deleted target but failed to remove empty staging directory {}: {err}",
                    stage_dir_path.display()
                )));
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
        if !snapshot_matches_stat(&item.snapshot, &st_leaf) {
            return Err(SjError::ExecutionGate(
                "target directory dev/ino changed since plan; regenerate plan".to_string(),
            ));
        }

        if is_orphan {
            verify_orphan_safe_to_remove(&canon_target, ctx)?;
        }

        let (stage_fd, stage_name_c, stage_name_str) =
            create_private_stage_dir(&parent_fd, st_parent.st_dev as u64)?;
        let stage_dir_path = canon_parent.join(&stage_name_str);
        let quarantined_target_path = stage_dir_path.join("target");
        if let Err(e) = renameat_no_replace(&parent_fd, &leaf_c, &stage_fd, target_c) {
            drop(stage_fd);
            let _ = unsafe {
                libc::unlinkat(
                    parent_fd.as_raw_fd(),
                    stage_name_c.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            };
            return Err(SjError::Io(e));
        }

        let verify_staged_dir = || -> Result<(OwnedFd, libc::stat, ManifestDir, u64), SjError> {
            let staged_dir_fd = openat_nofollow(
                stage_fd.as_raw_fd(),
                target_c,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?;
            let st_root = fstat_fd(&staged_dir_fd)?;
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
                let st_lstat_before = lstat_path(&quarantined_target_path)?;
                let st_at_before = fstatat_nofollow(&stage_fd, target_c)?;
                if !stat_matches_dev_ino(&st_root, &st_lstat_before)
                    || !stat_matches_dev_ino(&st_root, &st_at_before)
                {
                    return Err(SjError::ExecutionGate(
                        "orphan directory identity mismatch before git checks".to_string(),
                    ));
                }

                verify_orphan_safe_to_remove_staged(&quarantined_target_path, &canon_target, ctx)?;
                let (h, t, r) = capture_git_snapshot_identity_staged(
                    &quarantined_target_path,
                    &canon_target,
                    ctx,
                )?;

                let st_lstat_after = lstat_path(&quarantined_target_path)?;
                let st_at_after = fstatat_nofollow(&stage_fd, target_c)?;
                if !stat_matches_dev_ino(&st_root, &st_lstat_after)
                    || !stat_matches_dev_ino(&st_root, &st_at_after)
                {
                    return Err(SjError::ExecutionGate(
                        "orphan directory identity changed during git checks".to_string(),
                    ));
                }
                let prot_after = check_path_protection_anchored(&canon_target, ctx);
                if prot_after.protected {
                    return Err(SjError::ProtectedPath(prot_after.reason));
                }
                if is_symlink_path(&quarantined_target_path)? {
                    return Err(SjError::ProtectedPath(format!(
                        "refusing symlink target: {}",
                        quarantined_target_path.display()
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
                &staged_dir_fd,
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

            Ok((staged_dir_fd, st_root, root_manifest, root_dev))
        };

        let (staged_dir_fd, st_root, root_manifest, root_dev) = match verify_staged_dir() {
            Ok(v) => v,
            Err(err) => {
                return match restore_staged_or_preserve(
                    &parent_fd,
                    &leaf_c,
                    &canon_target,
                    &stage_fd,
                    &stage_name_c,
                    &stage_dir_path,
                ) {
                    Ok(()) => Err(err),
                    Err(rollback_note) => {
                        Err(SjError::ExecutionGate(format!("{err}; {rollback_note}")))
                    }
                };
            }
        };

        let mut any_unlinked = false;
        let del_and_unlink_res: Result<(), SjError> = (|| {
            let del_res = delete_dir_from_manifest_tracked(
                &staged_dir_fd,
                &canon_target,
                &root_manifest,
                root_dev,
                ctx,
                1,
                &mut any_unlinked,
            );
            drop(staged_dir_fd);
            del_res?;

            let st_recheck = fstatat_nofollow(&stage_fd, target_c)?;
            if !stat_matches_dev_ino(&st_recheck, &st_root) {
                return Err(SjError::ExecutionGate(
                    "target directory changed before final unlinkat; aborting".to_string(),
                ));
            }
            let rc = unsafe {
                libc::unlinkat(stage_fd.as_raw_fd(), target_c.as_ptr(), libc::AT_REMOVEDIR)
            };
            if rc != 0 {
                return Err(last_os_err());
            }
            Ok(())
        })();

        if let Err(err) = del_and_unlink_res {
            if !any_unlinked {
                return match restore_staged_or_preserve(
                    &parent_fd,
                    &leaf_c,
                    &canon_target,
                    &stage_fd,
                    &stage_name_c,
                    &stage_dir_path,
                ) {
                    Ok(()) => Err(err),
                    Err(rollback_note) => {
                        Err(SjError::ExecutionGate(format!("{err}; {rollback_note}")))
                    }
                };
            }
            return Err(SjError::ExecutionGate(format!(
                "{err}; partial deletion aborted — remaining target preserved in quarantine at {} for manual recovery",
                quarantined_target_path.display()
            )));
        }

        drop(stage_fd);
        let rc = unsafe {
            libc::unlinkat(
                parent_fd.as_raw_fd(),
                stage_name_c.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        };
        if rc != 0 {
            let err = last_os_err();
            return Err(SjError::ExecutionGate(format!(
                "deleted target but failed to remove empty staging directory {}: {err}",
                stage_dir_path.display()
            )));
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
    let prot = check_path_protection_anchored(target, ctx);
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
            let prot = check_path_protection_anchored(&entry_path, ctx);
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
            let (h, t, r) = capture_git_snapshot_identity_staged(target, target, ctx)?;
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
    let prot = check_path_protection_anchored(Path::new(&item.path), ctx);
    if prot.protected {
        return Err(SjError::ProtectedPath(prot.reason));
    }

    #[cfg(unix)]
    {
        unix_impl::safe_remove_plan_item_unix(item, ctx, allowed_trash_roots)
    }
    #[cfg(not(unix))]
    {
        let _ = allowed_trash_roots;
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

    #[test]
    fn safe_remove_plan_item_refuses_quarantine_stage_targets_cross_platform() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let trash_dir = root.join("Trash");
        let stage_dir = trash_dir.join(".sj-stage-999-deadbeef01234567");
        let nested_target = stage_dir.join("target");
        fs::create_dir_all(&nested_target).unwrap();
        let leftover = nested_target.join("leftover.txt");
        fs::write(&leftover, b"recover me").unwrap();

        let unprotected = root.join("normal.txt");
        fs::write(&unprotected, b"outside trash").unwrap();

        let ctx = ProtectionContext::new(root.to_path_buf(), vec![]);
        let allowed_trash_roots = vec![trash_dir];

        let dir_snapshot = TargetSnapshot {
            entry_type: "dir".to_string(),
            dev: None,
            ino: None,
            size: 0,
            mtime_secs: None,
            mtime_nanos: None,
            content_or_tree_sha256: String::new(),
            git_head: None,
            git_tree: None,
            git_refs_sha256: None,
        };

        let trash_stage_item = PlanItem {
            id: "item_stage_dir".to_string(),
            kind: "trash_item".to_string(),
            path: stage_dir.to_string_lossy().into_owned(),
            bytes: 0,
            tier: "safe".to_string(),
            safety_reasons: Vec::new(),
            snapshot: dir_snapshot.clone(),
        };
        let res1 = safe_remove_plan_item(&trash_stage_item, &ctx, &allowed_trash_roots);
        assert!(
            matches!(res1, Err(SjError::ProtectedPath(ref r)) if r.starts_with("quarantine_stage_recovery_required:")),
            "expected ProtectedPath for stage_dir, got: {res1:?}"
        );

        let orphan_nested_item = PlanItem {
            id: "item_nested_target".to_string(),
            kind: "orphan_worktree".to_string(),
            path: nested_target.to_string_lossy().into_owned(),
            bytes: 0,
            tier: "safe".to_string(),
            safety_reasons: Vec::new(),
            snapshot: dir_snapshot,
        };
        let res2 = safe_remove_plan_item(&orphan_nested_item, &ctx, &allowed_trash_roots);
        assert!(
            matches!(res2, Err(SjError::ProtectedPath(ref r)) if r.starts_with("quarantine_stage_recovery_required:")),
            "expected ProtectedPath for nested_target, got: {res2:?}"
        );
        assert!(
            leftover.exists(),
            "quarantined leftover.txt must remain intact"
        );

        let file_snapshot = TargetSnapshot {
            entry_type: "file".to_string(),
            dev: None,
            ino: None,
            size: 13,
            mtime_secs: None,
            mtime_nanos: None,
            content_or_tree_sha256: String::new(),
            git_head: None,
            git_tree: None,
            git_refs_sha256: None,
        };
        let unprotected_item = PlanItem {
            id: "item_unprotected".to_string(),
            kind: "trash_item".to_string(),
            path: unprotected.to_string_lossy().into_owned(),
            bytes: 13,
            tier: "safe".to_string(),
            safety_reasons: Vec::new(),
            snapshot: file_snapshot,
        };
        let res3 = safe_remove_plan_item(&unprotected_item, &ctx, &allowed_trash_roots);
        assert!(
            matches!(res3, Err(SjError::ExecutionGate(_))),
            "expected ExecutionGate for unprotected path outside trash roots, got: {res3:?}"
        );
        assert!(unprotected.exists(), "unprotected file must remain intact");
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
            let full = path.join(name);
            let meta = fs::symlink_metadata(&full).unwrap();
            let mut f = fs::File::open(&full).unwrap();
            let (content_sha256, _) = hash_file_reader(&mut f).unwrap();
            ManifestFile {
                name_c: CString::new(name).unwrap(),
                name_str: name.to_string(),
                dev: meta.dev(),
                ino: meta.ino(),
                size: meta.size(),
                mtime_secs: meta.mtime(),
                mtime_nsec: meta.mtime_nsec(),
                content_sha256,
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

        #[test]
        fn delete_dir_from_manifest_rejects_same_size_and_mtime_content_drift() {
            use std::io::Write;

            let tmp = tempdir().unwrap();
            let target = tmp.path().join("target_dir");
            fs::create_dir_all(&target).unwrap();
            let file_a = target.join("a.txt");
            fs::write(&file_a, b"initial").unwrap();
            let orig_mtime = fs::metadata(&file_a).unwrap().modified().unwrap();

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
            {
                let mut f = fs::OpenOptions::new()
                    .write(true)
                    .truncate(false)
                    .open(&file_a)
                    .unwrap();
                f.write_all(b"DRIFTED").unwrap();
                f.flush().unwrap();
                f.set_modified(orig_mtime).unwrap();
            }

            let ctx = ProtectionContext::new(tmp.path().to_path_buf(), vec![]);
            let res =
                delete_dir_from_manifest(&dir_fd, &target, &manifest, dir_meta.dev(), &ctx, 1);
            assert!(
                matches!(res, Err(SjError::ExecutionGate(_))),
                "same-size/same-mtime content drift must fail closed: {res:?}"
            );
            assert_eq!(
                fs::read(&file_a).unwrap(),
                b"DRIFTED",
                "drifted file must be preserved intact on disk"
            );
        }

        #[test]
        fn restore_staged_or_preserve_non_clobbering_on_eexist() {
            let tmp = tempdir().unwrap();
            let parent = tmp.path();
            let leaf_path = parent.join("victim.txt");
            fs::write(&leaf_path, b"staged payload").unwrap();

            let parent_fd = open_dir_fd(parent);
            let parent_meta = fs::symlink_metadata(parent).unwrap();
            let (stage_fd, stage_name_c, stage_name_str) =
                unix_impl::create_private_stage_dir(&parent_fd, parent_meta.dev()).unwrap();

            let leaf_c = CString::new("victim.txt").unwrap();
            let target_c = c"target";
            unix_impl::renameat_no_replace(&parent_fd, &leaf_c, &stage_fd, target_c).unwrap();

            // Simulate concurrent creation of a new file at the original path
            fs::write(&leaf_path, b"new concurrent file").unwrap();

            let stage_dir_path = parent.join(&stage_name_str);
            let res = unix_impl::restore_staged_or_preserve(
                &parent_fd,
                &leaf_c,
                &leaf_path,
                &stage_fd,
                &stage_name_c,
                &stage_dir_path,
            );
            assert!(
                res.is_err(),
                "restore_staged_or_preserve must fail when destination already exists"
            );
            let quarantined_target = parent.join(&stage_name_str).join("target");
            let err_msg = res.unwrap_err();
            assert!(
                err_msg.contains(&quarantined_target.display().to_string()),
                "restore_staged_or_preserve error must include exact quarantined target path {}: {err_msg}",
                quarantined_target.display()
            );
            assert_eq!(
                fs::read(&leaf_path).unwrap(),
                b"new concurrent file",
                "new file at leaf_c must not be clobbered"
            );
            assert_eq!(
                fs::read(&quarantined_target).unwrap(),
                b"staged payload",
                "staged target must remain preserved in quarantine"
            );
        }

        #[test]
        fn delete_dir_from_manifest_two_phase_prevents_partial_deletion_on_later_drift() {
            use std::io::Write;

            let tmp = tempdir().unwrap();
            let target = tmp.path().join("target_dir");
            let sub_a = target.join("sub_a");
            let sub_b = target.join("sub_b");
            fs::create_dir_all(&sub_a).unwrap();
            fs::create_dir_all(&sub_b).unwrap();

            let keep_file = sub_a.join("keep.txt");
            let drifted_file = sub_b.join("drifted.txt");
            fs::write(&keep_file, b"keep-intact").unwrap();
            fs::write(&drifted_file, b"original").unwrap();
            let orig_mtime = fs::metadata(&drifted_file).unwrap().modified().unwrap();

            let dir_meta = fs::symlink_metadata(&target).unwrap();
            let sub_a_meta = fs::symlink_metadata(&sub_a).unwrap();
            let sub_b_meta = fs::symlink_metadata(&sub_b).unwrap();

            let sub_a_manifest = ManifestDir {
                name_c: CString::new("sub_a").unwrap(),
                name_str: "sub_a".to_string(),
                dev: sub_a_meta.dev(),
                ino: sub_a_meta.ino(),
                dirs: Vec::new(),
                files: vec![build_manifest_file(&sub_a, "keep.txt")],
            };
            let sub_b_manifest = ManifestDir {
                name_c: CString::new("sub_b").unwrap(),
                name_str: "sub_b".to_string(),
                dev: sub_b_meta.dev(),
                ino: sub_b_meta.ino(),
                dirs: Vec::new(),
                files: vec![build_manifest_file(&sub_b, "drifted.txt")],
            };
            let manifest = ManifestDir {
                name_c: CString::new("target_dir").unwrap(),
                name_str: "target_dir".to_string(),
                dev: dir_meta.dev(),
                ino: dir_meta.ino(),
                dirs: vec![sub_a_manifest, sub_b_manifest],
                files: Vec::new(),
            };

            let dir_fd = open_dir_fd(&target);
            {
                let mut f = fs::OpenOptions::new()
                    .write(true)
                    .truncate(false)
                    .open(&drifted_file)
                    .unwrap();
                f.write_all(b"MUTATED!").unwrap();
                f.flush().unwrap();
                f.set_modified(orig_mtime).unwrap();
            }

            let ctx = ProtectionContext::new(tmp.path().to_path_buf(), vec![]);
            let res =
                delete_dir_from_manifest(&dir_fd, &target, &manifest, dir_meta.dev(), &ctx, 1);
            assert!(
                matches!(res, Err(SjError::ExecutionGate(_))),
                "later subdir drift must fail closed: {res:?}"
            );
            assert_eq!(
                fs::read(&keep_file).unwrap(),
                b"keep-intact",
                "Phase 1 must prevent partial deletion of earlier sibling sub_a/keep.txt"
            );
            assert_eq!(
                fs::read(&drifted_file).unwrap(),
                b"MUTATED!",
                "drifted file sub_b/drifted.txt must also remain preserved intact"
            );
        }
    }
}
