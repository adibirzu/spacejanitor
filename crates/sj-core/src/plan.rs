use crate::orphans::{inspect_orphans, verify_orphan_safe_to_remove, OrphanOptions};
use crate::protect::{
    check_dir_descendants_safe, check_path_protection, is_symlink_path, ProtectionContext,
};
use crate::trash::{default_trash_paths, discover_trash_at};
use crate::{SjError, SCHEMA_PROPOSAL_V1};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct PlanOptions {
    pub include_trash: bool,
    pub include_orphans: bool,
    pub trash_path_override: Option<PathBuf>,
    pub orphan_max_depth: usize,
}

impl Default for PlanOptions {
    fn default() -> Self {
        Self {
            include_trash: true,
            include_orphans: true,
            trash_path_override: None,
            orphan_max_depth: 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanItem {
    pub id: String,
    pub kind: String,
    pub path: String,
    pub bytes: u64,
    pub tier: String,
    pub safety_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExcludedItem {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemediationPlan {
    pub schema: String,
    pub mode: String,
    pub mutated: bool,
    pub plan_sha256: String,
    pub total_reclaimable_bytes: u64,
    pub items: Vec<PlanItem>,
    pub protected_exclusions: Vec<ExcludedItem>,
}

#[derive(Debug, Clone)]
pub struct ExecutionGate {
    pub execute: bool,
    pub confirm: bool,
    pub plan_sha256: String,
    pub item_id: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn deterministic_item_id(kind: &str, path: &str) -> String {
    let full = sha256_hex(format!("{kind}:{path}").as_bytes());
    format!("item_{}", &full[..12])
}

pub fn compute_plan_sha256(items: &[PlanItem]) -> Result<String, SjError> {
    let canonical = serde_json::to_vec(items)?;
    Ok(sha256_hex(&canonical))
}

pub fn build_remediation_plan(
    root: &Path,
    ctx: &ProtectionContext,
    opts: &PlanOptions,
) -> Result<RemediationPlan, SjError> {
    let mut items = Vec::new();
    let mut protected_exclusions = Vec::new();

    if opts.include_trash {
        let trash_paths = match &opts.trash_path_override {
            Some(p) => vec![p.clone()],
            None => default_trash_paths(&ctx.home_dir),
        };
        for tp in trash_paths {
            let report = discover_trash_at(&tp, ctx)?;
            for item in report.items {
                items.push(PlanItem {
                    id: deterministic_item_id("trash_item", &item.path),
                    kind: "trash_item".to_string(),
                    path: item.path,
                    bytes: item.bytes,
                    tier: "tier1".to_string(),
                    safety_reasons: vec!["os_trash_item".to_string(), "not_protected".to_string()],
                });
            }
            for prot in report.protected_items {
                protected_exclusions.push(ExcludedItem {
                    path: prot.path,
                    reason: prot.reason.unwrap_or_else(|| "protected".to_string()),
                });
            }
        }
    }

    if opts.include_orphans {
        let report = inspect_orphans(
            root,
            ctx,
            &OrphanOptions {
                max_depth: opts.orphan_max_depth,
            },
        )?;
        for cand in report.safe_to_prune {
            items.push(PlanItem {
                id: deterministic_item_id("orphan_worktree", &cand.path),
                kind: "orphan_worktree".to_string(),
                path: cand.path,
                bytes: cand.bytes,
                tier: "tier2".to_string(),
                safety_reasons: vec![
                    "clean_working_tree".to_string(),
                    "all_branches_pushed".to_string(),
                    "not_protected".to_string(),
                ],
            });
        }
        for blk in report.blocked {
            protected_exclusions.push(ExcludedItem {
                path: blk.path,
                reason: blk.reasons.join(","),
            });
        }
    }

    items.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.id.cmp(&b.id))
    });
    protected_exclusions.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.reason.cmp(&b.reason)));

    let total_reclaimable_bytes = items
        .iter()
        .fold(0u64, |acc, i| acc.saturating_add(i.bytes));
    let plan_sha256 = compute_plan_sha256(&items)?;

    Ok(RemediationPlan {
        schema: SCHEMA_PROPOSAL_V1.to_string(),
        mode: "dry-run".to_string(),
        mutated: false,
        plan_sha256,
        total_reclaimable_bytes,
        items,
        protected_exclusions,
    })
}

pub fn execute_plan_item(
    plan: &RemediationPlan,
    gate: &ExecutionGate,
    ctx: &ProtectionContext,
) -> Result<PlanItem, SjError> {
    let allowed = default_trash_paths(&ctx.home_dir);
    execute_plan_item_with_roots(plan, gate, ctx, &allowed)
}

pub fn execute_plan_item_with_roots(
    plan: &RemediationPlan,
    gate: &ExecutionGate,
    ctx: &ProtectionContext,
    allowed_trash_roots: &[PathBuf],
) -> Result<PlanItem, SjError> {
    if !gate.execute {
        return Err(SjError::ExecutionGate(
            "missing --execute flag (dry-run is default)".to_string(),
        ));
    }
    if !gate.confirm {
        return Err(SjError::ExecutionGate("missing --confirm flag".to_string()));
    }
    if gate.plan_sha256.is_empty() || gate.item_id.is_empty() {
        return Err(SjError::ExecutionGate(
            "both --plan-sha256 and --item <id> are required".to_string(),
        ));
    }

    let expected_sha = compute_plan_sha256(&plan.items)?;
    if gate.plan_sha256 != expected_sha || gate.plan_sha256 != plan.plan_sha256 {
        return Err(SjError::ExecutionGate(
            "plan_sha256 mismatch; regenerate plan and retry".to_string(),
        ));
    }

    let item = plan
        .items
        .iter()
        .find(|i| i.id == gate.item_id)
        .cloned()
        .ok_or_else(|| {
            SjError::ExecutionGate(format!(
                "item id '{}' not in allowlisted plan",
                gate.item_id
            ))
        })?;

    let target = Path::new(&item.path);
    let prot = check_path_protection(target, ctx);
    if prot.protected {
        return Err(SjError::ProtectedPath(prot.reason));
    }

    let meta = std::fs::symlink_metadata(target)?;
    if meta.file_type().is_symlink() || is_symlink_path(target)? {
        return Err(SjError::ProtectedPath(format!(
            "refusing symlink target: {}",
            target.display()
        )));
    }

    match item.kind.as_str() {
        "trash_item" => {
            let canon_target = std::fs::canonicalize(target)?;
            let in_allowed_root = allowed_trash_roots.iter().any(|root| {
                if !root.exists() || is_symlink_path(root).unwrap_or(true) {
                    return false;
                }
                std::fs::canonicalize(root)
                    .map(|canon_root| {
                        canon_target.starts_with(&canon_root) && canon_target != canon_root
                    })
                    .unwrap_or(false)
            });
            if !in_allowed_root {
                return Err(SjError::ExecutionGate(format!(
                    "refusing trash_item outside verified OS Trash roots: {}",
                    target.display()
                )));
            }
            if meta.is_dir() {
                let desc = check_dir_descendants_safe(target, ctx, 100_000);
                if desc.protected {
                    return Err(SjError::ProtectedPath(desc.reason));
                }
            }
        }
        "orphan_worktree" => {
            if !meta.is_dir() {
                return Err(SjError::ExecutionGate(format!(
                    "orphan_worktree target is not a directory: {}",
                    target.display()
                )));
            }
            verify_orphan_safe_to_remove(target, ctx)?;
        }
        other => {
            return Err(SjError::ExecutionGate(format!(
                "unsupported plan item kind: {other}"
            )));
        }
    }

    if meta.is_dir() {
        std::fs::remove_dir_all(target)?;
    } else {
        std::fs::remove_file(target)?;
    }

    Ok(item)
}
