use crate::linux::{
    allowed_tmp_roots, discover_linux_audit, execute_linux_command_item, LinuxAuditReport,
};
use crate::orphans::{inspect_orphans, OrphanOptions};
use crate::protect::{check_path_protection_anchored, ProtectionContext};
use crate::safe_remove::{
    capture_target_snapshot, safe_remove_plan_item, safe_remove_plan_item_with_roots,
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
            // off by default: orphan scanning runs git inside repositories found on disk (experimental)
            include_orphans: false,
            trash_path_override: None,
            orphan_max_depth: 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetSnapshot {
    pub entry_type: String,
    pub dev: Option<u64>,
    pub ino: Option<u64>,
    pub size: u64,
    pub mtime_secs: Option<i64>,
    pub mtime_nanos: Option<u32>,
    pub content_or_tree_sha256: String,
    pub git_head: Option<String>,
    pub git_tree: Option<String>,
    pub git_refs_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanItem {
    pub id: String,
    pub kind: String,
    pub path: String,
    pub bytes: u64,
    pub tier: String,
    pub safety_reasons: Vec<String>,
    pub snapshot: TargetSnapshot,
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

#[derive(Debug, Clone, Default)]
pub struct LinuxPlanOptions {
    pub include_linux: bool,
    pub audit_override: Option<LinuxAuditReport>,
    pub tmp_root_override: Option<PathBuf>,
}

fn command_snapshot(entry_type: &str, size: u64, identity: &str) -> TargetSnapshot {
    TargetSnapshot {
        entry_type: entry_type.to_string(),
        dev: None,
        ino: None,
        size,
        mtime_secs: None,
        mtime_nanos: None,
        content_or_tree_sha256: sha256_hex(identity.as_bytes()),
        git_head: None,
        git_tree: None,
        git_refs_sha256: None,
    }
}

fn is_linux_command_kind(kind: &str) -> bool {
    matches!(
        kind,
        "docker_exited_container" | "docker_dangling_image" | "podman_exited_container"
    )
}

pub fn build_remediation_plan(
    root: &Path,
    ctx: &ProtectionContext,
    opts: &PlanOptions,
) -> Result<RemediationPlan, SjError> {
    build_remediation_plan_with_linux(root, ctx, opts, &LinuxPlanOptions::default())
}

pub fn build_remediation_plan_with_linux(
    root: &Path,
    ctx: &ProtectionContext,
    opts: &PlanOptions,
    linux_opts: &LinuxPlanOptions,
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
                let snapshot = capture_target_snapshot(Path::new(&item.path), false, ctx)?;
                items.push(PlanItem {
                    id: deterministic_item_id("trash_item", &item.path),
                    kind: "trash_item".to_string(),
                    path: item.path,
                    bytes: item.bytes,
                    tier: "tier1".to_string(),
                    safety_reasons: vec!["os_trash_item".to_string(), "not_protected".to_string()],
                    snapshot,
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
            let snapshot = capture_target_snapshot(Path::new(&cand.path), true, ctx)?;
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
                snapshot,
            });
        }
        for blk in report.blocked {
            protected_exclusions.push(ExcludedItem {
                path: blk.path,
                reason: blk.reasons.join(","),
            });
        }
    }

    if linux_opts.include_linux {
        let audit = linux_opts.audit_override.clone().unwrap_or_else(|| {
            discover_linux_audit(&ctx.home_dir, linux_opts.tmp_root_override.as_deref())
        });

        for cache in &audit.package_caches.user_caches {
            let p = Path::new(&cache.path);
            let prot = check_path_protection_anchored(p, ctx);
            if prot.protected {
                protected_exclusions.push(ExcludedItem {
                    path: cache.path.clone(),
                    reason: prot.reason,
                });
                continue;
            }
            if let Ok(snapshot) = capture_target_snapshot(p, false, ctx) {
                items.push(PlanItem {
                    id: deterministic_item_id("linux_user_cache", &cache.path),
                    kind: "linux_user_cache".to_string(),
                    path: cache.path.clone(),
                    bytes: cache.bytes,
                    tier: "tier1".to_string(),
                    safety_reasons: vec![
                        "rebuildable_package_cache".to_string(),
                        "not_protected".to_string(),
                    ],
                    snapshot,
                });
            }
        }

        for tmp_art in &audit.stale_tmp_entries {
            let p = Path::new(&tmp_art.path);
            let prot = check_path_protection_anchored(p, ctx);
            if prot.protected {
                protected_exclusions.push(ExcludedItem {
                    path: tmp_art.path.clone(),
                    reason: prot.reason,
                });
                continue;
            }
            if let Ok(snapshot) = capture_target_snapshot(p, false, ctx) {
                items.push(PlanItem {
                    id: deterministic_item_id("stale_tmp_entry", &tmp_art.path),
                    kind: "stale_tmp_entry".to_string(),
                    path: tmp_art.path.clone(),
                    bytes: tmp_art.bytes,
                    tier: "tier2".to_string(),
                    safety_reasons: vec![tmp_art.reason.clone(), "not_active_mountpoint".to_string()],
                    snapshot,
                });
            }
        }

        for c in &audit.docker.exited_containers {
            let ref_path = format!("docker://container/{}/{}", c.id, c.name);
            items.push(PlanItem {
                id: deterministic_item_id("docker_exited_container", &ref_path),
                kind: "docker_exited_container".to_string(),
                path: ref_path.clone(),
                bytes: c.size_bytes,
                tier: "tier2".to_string(),
                safety_reasons: vec![
                    format!("state:{}", c.state),
                    format!("cmd:docker rm {}", c.id),
                ],
                snapshot: command_snapshot("docker_container", c.size_bytes, &format!("{ref_path}:{}", c.status)),
            });
        }
        for img in &audit.docker.dangling_images {
            let ref_path = format!("docker://image/{}", img.id);
            items.push(PlanItem {
                id: deterministic_item_id("docker_dangling_image", &ref_path),
                kind: "docker_dangling_image".to_string(),
                path: ref_path.clone(),
                bytes: img.size_bytes,
                tier: "tier2".to_string(),
                safety_reasons: vec![
                    "dangling_image".to_string(),
                    format!("cmd:docker rmi {}", img.id),
                ],
                snapshot: command_snapshot("docker_image", img.size_bytes, &format!("{ref_path}:{}", img.size_bytes)),
            });
        }
        if audit.docker.df.build_cache_reclaimable_bytes > 0 {
            protected_exclusions.push(ExcludedItem {
                path: "docker://build-cache".to_string(),
                reason: format!(
                    "manual_review_only:docker_build_cache:{}B:docker builder prune -f",
                    audit.docker.df.build_cache_reclaimable_bytes
                ),
            });
        }

        for c in &audit.podman.exited_containers {
            let ref_path = format!("podman://container/{}/{}", c.id, c.name);
            items.push(PlanItem {
                id: deterministic_item_id("podman_exited_container", &ref_path),
                kind: "podman_exited_container".to_string(),
                path: ref_path.clone(),
                bytes: c.size_bytes,
                tier: "tier2".to_string(),
                safety_reasons: vec![
                    format!("state:{}", c.state),
                    format!("cmd:podman rm {}", c.id),
                ],
                snapshot: command_snapshot("podman_container", c.size_bytes, &format!("{ref_path}:{}", c.status)),
            });
        }
        if audit.podman.df.images_reclaimable_bytes > 0 {
            protected_exclusions.push(ExcludedItem {
                path: "podman://images/dangling".to_string(),
                reason: format!(
                    "manual_review_only:podman_dangling_images:{}B:podman image prune -f",
                    audit.podman.df.images_reclaimable_bytes
                ),
            });
        }
        if audit.podman.df.volumes_reclaimable_bytes > 0 {
            protected_exclusions.push(ExcludedItem {
                path: "podman://volumes/unused".to_string(),
                reason: format!(
                    "manual_review_only:podman_unused_volumes:{}B:podman volume prune -f",
                    audit.podman.df.volumes_reclaimable_bytes
                ),
            });
        }

        if audit.journald.available && audit.journald.bytes > 500 * 1024 * 1024 {
            let bytes = audit.journald.bytes.saturating_sub(500 * 1024 * 1024);
            protected_exclusions.push(ExcludedItem {
                path: "systemd://journald".to_string(),
                reason: format!(
                    "manual_review_only:journald_vacuum:{}B:journalctl --vacuum-size=500M",
                    bytes
                ),
            });
        }

        if audit.package_caches.apt_archives_bytes > 0 {
            protected_exclusions.push(ExcludedItem {
                path: format!("apt://{}", audit.package_caches.apt_archives_path),
                reason: format!(
                    "manual_review_only:apt_cache_clean:{}B:apt-get clean",
                    audit.package_caches.apt_archives_bytes
                ),
            });
        }

        // Manual-review-only items are NEVER placed in `items` and cannot be executed automatically.
        for m in &audit.model_caches {
            protected_exclusions.push(ExcludedItem {
                path: m.path.clone(),
                reason: format!("manual_review_only:model_cache:{}B", m.bytes),
            });
        }
        for b in &audit.old_backups {
            protected_exclusions.push(ExcludedItem {
                path: b.path.clone(),
                reason: format!("manual_review_only:old_backup:{}B", b.bytes),
            });
        }
        for app_mnt in &audit.appimage_mounts {
            protected_exclusions.push(ExcludedItem {
                path: app_mnt.mountpoint.clone(),
                reason: "manual_review_only:active_appimage_mount".to_string(),
            });
        }
        for c in audit
            .docker
            .unhealthy_containers
            .iter()
            .chain(audit.podman.unhealthy_containers.iter())
        {
            protected_exclusions.push(ExcludedItem {
                path: format!("{}://container/{}/{}", c.runtime, c.id, c.name),
                reason: format!("manual_review_only:unhealthy_container:{}", c.status),
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

pub fn execute_plan_item_with_linux(
    plan: &RemediationPlan,
    gate: &ExecutionGate,
    ctx: &ProtectionContext,
    allowed_tmp: &[PathBuf],
) -> Result<PlanItem, SjError> {
    let allowed_trash = default_trash_paths(&ctx.home_dir);
    execute_plan_item_inner(plan, gate, ctx, &allowed_trash, allowed_tmp)
}

pub fn execute_plan_item_with_roots(
    plan: &RemediationPlan,
    gate: &ExecutionGate,
    ctx: &ProtectionContext,
    allowed_trash_roots: &[PathBuf],
) -> Result<PlanItem, SjError> {
    execute_plan_item_inner(plan, gate, ctx, allowed_trash_roots, &allowed_tmp_roots())
}

fn execute_plan_item_inner(
    plan: &RemediationPlan,
    gate: &ExecutionGate,
    ctx: &ProtectionContext,
    allowed_trash_roots: &[PathBuf],
    allowed_tmp: &[PathBuf],
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

    if is_linux_command_kind(&item.kind) {
        execute_linux_command_item(&item)?;
    } else {
        safe_remove_plan_item_with_roots(&item, ctx, allowed_trash_roots, allowed_tmp)?;
    }

    Ok(item)
}

// ---------------------------------------------------------------------------------------------
// Selection-bound confirmation
// ---------------------------------------------------------------------------------------------
//
// A confirmation must cover exactly what will be executed. The whole-plan digest says nothing about
// WHICH items the user picked, so a token confirmed for item A could otherwise authorise A+B. The
// selection digest hashes the canonical (sorted by path, de-duplicated) list of the selected plan items
// including their identity snapshot (dev/ino/size/mtime/content hash/git state), and execution
// recomputes it from a freshly built plan: anything that changed on disk, or a different selection,
// no longer matches and is refused before a single item is touched.

#[derive(Debug, Clone)]
pub struct SelectionGate {
    pub execute: bool,
    pub confirm: bool,
    pub selection_sha256: String,
    pub paths: Vec<String>,
}

#[derive(Debug)]
pub struct SelectionOutcome {
    pub executed: Vec<PlanItem>,
    pub failed: Vec<(PlanItem, String)>,
}

/// Items of `plan` whose path is in `paths` (canonical order, de-duplicated) plus the paths that
/// matched nothing.
pub fn select_by_paths(plan: &RemediationPlan, paths: &[String]) -> (Vec<PlanItem>, Vec<String>) {
    let mut wanted: Vec<&String> = paths.iter().collect();
    wanted.sort();
    wanted.dedup();
    let mut items: Vec<PlanItem> = Vec::new();
    let mut unmatched: Vec<String> = Vec::new();
    for p in wanted {
        match plan.items.iter().find(|i| &i.path == p) {
            Some(i) => items.push(i.clone()),
            None => unmatched.push(p.clone()),
        }
    }
    items.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.id.cmp(&b.id)));
    (items, unmatched)
}

pub fn selection_sha256(items: &[PlanItem]) -> Result<String, SjError> {
    let mut sorted: Vec<&PlanItem> = items.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.id.cmp(&b.id)));
    sorted.dedup_by(|a, b| a.id == b.id && a.path == b.path);
    let mut bytes = b"spacejanitor.selection.v1\n".to_vec();
    bytes.extend(serde_json::to_vec(&sorted)?);
    Ok(sha256_hex(&bytes))
}

pub fn execute_selection(
    plan: &RemediationPlan,
    gate: &SelectionGate,
    ctx: &ProtectionContext,
) -> Result<SelectionOutcome, SjError> {
    let allowed = default_trash_paths(&ctx.home_dir);
    execute_selection_with_roots(plan, gate, ctx, &allowed)
}

pub fn execute_selection_with_roots(
    plan: &RemediationPlan,
    gate: &SelectionGate,
    ctx: &ProtectionContext,
    allowed_trash_roots: &[PathBuf],
) -> Result<SelectionOutcome, SjError> {
    if !gate.execute {
        return Err(SjError::ExecutionGate(
            "missing --execute flag (dry-run is default)".to_string(),
        ));
    }
    if !gate.confirm {
        return Err(SjError::ExecutionGate("missing --confirm flag".to_string()));
    }
    if gate.selection_sha256.is_empty() || gate.paths.is_empty() {
        return Err(SjError::ExecutionGate(
            "both --selection-sha256 and at least one --select <path> are required".to_string(),
        ));
    }
    let (items, unmatched) = select_by_paths(plan, &gate.paths);
    if !unmatched.is_empty() {
        return Err(SjError::ExecutionGate(format!(
            "selected path not in the freshly built plan: {}",
            unmatched.join(", ")
        )));
    }
    if selection_sha256(&items)? != gate.selection_sha256 {
        return Err(SjError::ExecutionGate(
            "selection_sha256 mismatch; the selection or the selected items changed since confirmation, regenerate the plan and retry"
                .to_string(),
        ));
    }
    let mut outcome = SelectionOutcome {
        executed: Vec::new(),
        failed: Vec::new(),
    };
    for item in items {
        let res = if is_linux_command_kind(&item.kind) {
            execute_linux_command_item(&item)
        } else {
            safe_remove_plan_item(&item, ctx, allowed_trash_roots)
        };
        match res {
            Ok(()) => outcome.executed.push(item),
            Err(e) => outcome.failed.push((item, e.to_string())),
        }
    }
    Ok(outcome)
}
