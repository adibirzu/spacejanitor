use crate::protect::{
    check_dir_descendants_safe_logical, check_path_protection, is_quarantine_stage_name,
    is_symlink_path, ProtectionContext,
};
use crate::{SjError, SCHEMA_ORPHANS_V1};
use jwalk::WalkDir;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

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

fn run_git_raw_ctx<I, S>(git_ctx: &GitExecContext, args: I) -> Result<(bool, String), SjError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new("git");
    cmd.current_dir(&git_ctx.work_tree)
        .arg("--git-dir")
        .arg(&git_ctx.git_dir)
        .arg("--work-tree")
        .arg(&git_ctx.work_tree)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0");
    if let Some(ref alt) = git_ctx.alternate_object_dirs {
        cmd.env("GIT_ALTERNATE_OBJECT_DIRECTORIES", alt);
    }
    let out = cmd.output()?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    Ok((out.status.success(), stdout))
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
        }
    }
    let common_raw =
        std::fs::read_to_string(&commondir_file).map_err(|_| "unreadable_commondir".to_string())?;
    let common_trimmed = common_raw.trim();
    if common_trimmed.is_empty() {
        return Err("empty_commondir".to_string());
    }
    let common_path = resolve_relative_from_dir(gitdir, Path::new(common_trimmed));
    if is_symlink_path(&common_path).unwrap_or(true) {
        return Err("symlink_or_missing_commondir".to_string());
    }
    let common_verdict = check_path_protection(&common_path, ctx);
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
        std::fs::read_to_string(dot_git_file).map_err(|_| "unreadable_dot_git_file".to_string())?;
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
    let verdict = check_path_protection(&target, ctx);
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

fn validate_single_repo_at(
    actual_repo: &Path,
    logical_repo: &Path,
    ctx: &ProtectionContext,
) -> Result<OrphanCandidate, Vec<String>> {
    let mut reasons = Vec::new();

    let prot = check_path_protection(logical_repo, ctx);
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
            "--ignore-submodules=none",
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

    let (stash_ok, stash_out) =
        run_git_ctx(&git_ctx, ["stash", "list"]).unwrap_or((false, String::new()));
    if !stash_ok || !stash_out.is_empty() {
        reasons.push("has_stashes".to_string());
    }

    let refs_before = snapshot_local_branches(&git_ctx);
    let mut all_branches_verified = false;
    if let Ok(ref local_branches) = refs_before {
        if !remotes.is_empty() {
            let mut remote_heads: BTreeMap<String, Vec<String>> = BTreeMap::new();
            let mut remote_query_failed = false;
            for remote_name in &remotes {
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
                match run_git_raw_ctx(
                    &git_ctx,
                    [
                        OsStr::new("ls-remote"),
                        OsStr::new("--heads"),
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
                        remote_heads.insert(remote_name.clone(), tips);
                    }
                    _ => {
                        remote_query_failed = true;
                    }
                }
            }

            if !remote_query_failed {
                let is_pushed_to_tips = |local_sha: &str, tips: &[String]| -> bool {
                    tips.iter().any(|rsha| {
                        rsha == local_sha
                            || run_git_ctx(
                                &git_ctx,
                                ["merge-base", "--is-ancestor", local_sha, rsha],
                            )
                            .map(|(ok, _)| ok)
                            .unwrap_or(false)
                    })
                };

                all_branches_verified = local_branches.iter().all(|(refname, local_sha)| {
                    let short_branch = refname.strip_prefix("refs/heads/").unwrap_or(refname);
                    let remote_cfg = run_git_ctx(
                        &git_ctx,
                        ["config", "--get", &format!("branch.{short_branch}.remote")],
                    )
                    .ok()
                    .filter(|(ok, out)| *ok && !out.is_empty())
                    .map(|(_, out)| out);

                    if let Some(rem) = remote_cfg {
                        remote_heads
                            .get(&rem)
                            .is_some_and(|tips| is_pushed_to_tips(local_sha, tips))
                    } else {
                        remote_heads
                            .values()
                            .any(|tips| is_pushed_to_tips(local_sha, tips))
                    }
                });
            }
        }
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
                !check_path_protection(&entry.path(), &ctx_clone).protected
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
    let prot = check_path_protection(logical_repo, ctx);
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
}
