use crate::protect::{check_path_protection, is_symlink_path, ProtectionContext};
use crate::{SjError, SCHEMA_ORPHANS_V1};
use jwalk::WalkDir;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
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

fn run_git(repo: &Path, args: &[&str]) -> Result<(bool, String), SjError> {
    let out = Command::new("git")
        .current_dir(repo)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok((out.status.success(), stdout))
}

fn validate_gitdir_pointer(
    worktree: &Path,
    dot_git_file: &Path,
    ctx: &ProtectionContext,
) -> Result<(), String> {
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
    let target = {
        let p = PathBuf::from(target_raw);
        if p.is_absolute() {
            p
        } else {
            worktree.join(p)
        }
    };
    if is_symlink_path(&target).unwrap_or(true) {
        return Err("symlink_or_missing_gitdir".to_string());
    }
    let verdict = check_path_protection(&target, ctx);
    if verdict.protected {
        return Err(format!("protected_gitdir:{}", verdict.reason));
    }

    let commondir_file = target.join("commondir");
    if commondir_file.exists() {
        if is_symlink_path(&commondir_file).unwrap_or(true) {
            return Err("symlink_commondir_file".to_string());
        }
        let common_raw = std::fs::read_to_string(&commondir_file)
            .map_err(|_| "unreadable_commondir".to_string())?;
        let common_trimmed = common_raw.trim();
        let common_path = {
            let p = PathBuf::from(common_trimmed);
            if p.is_absolute() {
                p
            } else {
                target.join(p)
            }
        };
        if is_symlink_path(&common_path).unwrap_or(true) {
            return Err("symlink_or_missing_commondir".to_string());
        }
        let common_verdict = check_path_protection(&common_path, ctx);
        if common_verdict.protected {
            return Err(format!("protected_commondir:{}", common_verdict.reason));
        }
    }

    Ok(())
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

fn validate_single_repo(
    repo: &Path,
    ctx: &ProtectionContext,
) -> Result<OrphanCandidate, Vec<String>> {
    let mut reasons = Vec::new();

    let prot = check_path_protection(repo, ctx);
    if prot.protected {
        reasons.push(format!("protected_path:{}", prot.reason));
        return Err(reasons);
    }

    if is_symlink_path(repo).unwrap_or(true) {
        reasons.push("symlink_worktree".to_string());
        return Err(reasons);
    }

    let dot_git = repo.join(".git");
    let Ok(dot_git_meta) = std::fs::symlink_metadata(&dot_git) else {
        reasons.push("missing_dot_git".to_string());
        return Err(reasons);
    };
    if dot_git_meta.file_type().is_symlink() {
        reasons.push("symlink_dot_git".to_string());
        return Err(reasons);
    }

    let is_worktree = dot_git_meta.is_file();
    if is_worktree {
        if let Err(reason) = validate_gitdir_pointer(repo, &dot_git, ctx) {
            reasons.push(reason);
            return Err(reasons);
        }
    }

    let Ok((head_ok, head_before)) = run_git(repo, &["rev-parse", "--verify", "HEAD"]) else {
        reasons.push("git_invocation_failed".to_string());
        return Err(reasons);
    };
    if !head_ok || head_before.is_empty() {
        reasons.push("unborn_head".to_string());
    }

    let (sym_ok, sym_ref) =
        run_git(repo, &["symbolic-ref", "-q", "HEAD"]).unwrap_or((false, String::new()));
    let branch = if sym_ok && !sym_ref.is_empty() {
        Some(sym_ref)
    } else {
        reasons.push("detached_head".to_string());
        None
    };

    let (status_ok, status_out) = run_git(
        repo,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    )
    .unwrap_or((false, String::new()));
    if !status_ok || !status_out.is_empty() {
        reasons.push("dirty_or_untracked".to_string());
    }

    let (remote_ok, remote_out) = run_git(repo, &["remote"]).unwrap_or((false, String::new()));
    if !remote_ok || remote_out.is_empty() {
        reasons.push("no_remote".to_string());
    }

    let (stash_ok, stash_out) = run_git(repo, &["stash", "list"]).unwrap_or((false, String::new()));
    if !stash_ok || !stash_out.is_empty() {
        reasons.push("has_stashes".to_string());
    }

    let (unpushed_ok, unpushed_out) = run_git(
        repo,
        &["rev-list", "--branches", "--not", "--remotes", "--count"],
    )
    .unwrap_or((false, String::new()));
    if !unpushed_ok || unpushed_out != "0" {
        reasons.push("unpushed_commits".to_string());
    }

    let (head_after_ok, head_after) =
        run_git(repo, &["rev-parse", "--verify", "HEAD"]).unwrap_or((false, String::new()));
    if head_ok && (!head_after_ok || head_after != head_before) {
        reasons.push("concurrent_head_drift".to_string());
    }

    if reasons.is_empty() {
        Ok(OrphanCandidate {
            path: repo.to_string_lossy().into_owned(),
            is_worktree,
            branch,
            head: Some(head_before),
            bytes: dir_bytes_no_follow(repo),
        })
    } else {
        Err(reasons)
    }
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
    let walker = WalkDir::new(root)
        .follow_links(false)
        .skip_hidden(false)
        .max_depth(opts.max_depth.saturating_add(1))
        .process_read_dir(|_depth, _path, _state, children| {
            children.retain(|res| {
                let Ok(entry) = res else {
                    return false;
                };
                if entry.file_name() == ".git" {
                    return false;
                }
                !entry.file_type().is_symlink()
            });
        });

    for entry_res in walker {
        let Ok(entry) = entry_res else {
            continue;
        };
        if entry.file_type().is_dir() {
            let p = entry.path();
            if p.join(".git").exists() {
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
