use crate::orphans::{capture_git_snapshot_identity, verify_orphan_safe_to_remove};
use crate::plan::{PlanItem, TargetSnapshot};
use crate::protect::{check_path_protection, is_symlink_path, ProtectionContext};
use crate::SjError;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const LARGE_FILE_THRESHOLD: u64 = 64 * 1024 * 1024;
const LARGE_FILE_CHUNK: usize = 1024 * 1024;
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

pub fn hash_file_reader<R: Read + Seek>(reader: &mut R, size: u64) -> Result<String, SjError> {
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    if size <= LARGE_FILE_THRESHOLD {
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
    } else {
        hasher.update(b"large:");
        hasher.update(size.to_le_bytes());

        let mut head_buf = vec![0u8; LARGE_FILE_CHUNK];
        reader.read_exact(&mut head_buf)?;
        hasher.update(&head_buf);

        reader.seek(SeekFrom::Start(size - LARGE_FILE_CHUNK as u64))?;
        let mut tail_buf = vec![0u8; LARGE_FILE_CHUNK];
        reader.read_exact(&mut tail_buf)?;
        hasher.update(&tail_buf);
    }
    Ok(sha256_to_hex(hasher.finalize()))
}

pub type DirTreeRecord = (
    String,
    String,
    Option<u64>,
    Option<u64>,
    u64,
    Option<i64>,
    Option<u32>,
);

pub fn hash_dir_tree_records(records: &[DirTreeRecord]) -> String {
    let mut hasher = Sha256::new();
    for (rel_path, entry_type, dev, ino, size, mtime_secs, mtime_nanos) in records {
        hasher.update((rel_path.len() as u64).to_le_bytes());
        hasher.update(rel_path.as_bytes());
        hasher.update(entry_type.as_bytes());
        hasher.update(dev.unwrap_or(0).to_le_bytes());
        hasher.update(ino.unwrap_or(0).to_le_bytes());
        hasher.update(size.to_le_bytes());
        hasher.update(mtime_secs.unwrap_or(0).to_le_bytes());
        hasher.update(mtime_nanos.unwrap_or(0).to_le_bytes());
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
                inspect_dir_fd_recursive(&sub_fd, &child_full_path, &rel_path, depth + 1, state)?;
            } else if mode == libc::S_IFREG {
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
                    ));
                }
            } else {
                return Err(SjError::ProtectedPath(format!(
                    "refusing special file descendant: {}",
                    child_full_path.display()
                )));
            }
        }
        Ok(())
    }

    fn delete_dir_fd_post_order(
        dir_fd: &OwnedFd,
        root_dev: u64,
        depth: usize,
    ) -> Result<(), SjError> {
        if depth > MAX_DIR_DEPTH {
            return Err(SjError::ExecutionGate(
                "directory depth limit exceeded during safe deletion".to_string(),
            ));
        }
        let guard = fd_to_dir(dir_fd)?;
        let mut children: Vec<CString> = Vec::new();
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
            children.push(name_c.to_owned());
        }
        drop(guard);

        for name_c in children {
            let child_st = fstatat_nofollow(dir_fd, &name_c)?;
            if (child_st.st_dev as u64) != root_dev {
                return Err(SjError::ProtectedPath(
                    "refusing cross-device mountpoint during deletion".to_string(),
                ));
            }
            let mode = child_st.st_mode & libc::S_IFMT;
            if mode == libc::S_IFLNK {
                return Err(SjError::ProtectedPath(
                    "refusing symlink encountered during deletion".to_string(),
                ));
            }
            if mode == libc::S_IFDIR {
                let sub_fd = openat_nofollow(
                    dir_fd.as_raw_fd(),
                    &name_c,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )?;
                let sub_st = fstat_fd(&sub_fd)?;
                if (sub_st.st_mode & libc::S_IFMT) != libc::S_IFDIR
                    || (sub_st.st_dev as u64) != root_dev
                    || !stat_matches_dev_ino(&sub_st, &child_st)
                {
                    return Err(SjError::ExecutionGate(
                        "subdirectory fd identity mismatch during deletion".to_string(),
                    ));
                }
                delete_dir_fd_post_order(&sub_fd, root_dev, depth + 1)?;
                drop(sub_fd);
                let rc = unsafe {
                    libc::unlinkat(dir_fd.as_raw_fd(), name_c.as_ptr(), libc::AT_REMOVEDIR)
                };
                if rc != 0 {
                    return Err(last_os_err());
                }
            } else if mode == libc::S_IFREG {
                let rc = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), name_c.as_ptr(), 0) };
                if rc != 0 {
                    return Err(last_os_err());
                }
            } else {
                return Err(SjError::ProtectedPath(
                    "refusing special file encountered during deletion".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn capture_snapshot_unix(
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
            let mut file = File::from(file_fd);
            let content_hash = hash_file_reader(&mut file, size)?;
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
            inspect_dir_fd_recursive(&dir_fd, &canon_target, "", 1, &mut state)?;
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

    pub fn safe_remove_plan_item_unix(
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
            let mut file = File::from(file_fd);
            let content_hash = hash_file_reader(&mut file, size)?;
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
        inspect_dir_fd_recursive(&target_dir_fd, &canon_target, "", 1, &mut state)?;
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

        delete_dir_fd_post_order(&target_dir_fd, root_dev, 1)?;
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

pub fn capture_snapshot_portable(
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
        let mut file = std::fs::File::open(target)?;
        let size = meta.len();
        let content_hash = hash_file_reader(&mut file, size)?;
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
            let entry_type = if child_meta.is_dir() {
                "dir"
            } else if child_meta.is_file() {
                "file"
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

pub fn capture_target_snapshot(
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

pub fn safe_remove_plan_item(
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
