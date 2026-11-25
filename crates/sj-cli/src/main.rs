use clap::{Parser, Subcommand};
use sj_core::{
    orphans::{inspect_orphans, OrphanOptions},
    plan::{build_remediation_plan, execute_plan_item, ExecutionGate, PlanOptions},
    protect::{check_dir_descendants_safe, check_path_protection, ProtectionContext},
    scan::{scan_directory, ScanOptions},
    trash::{default_trash_paths, discover_trash_at},
    SjError, SCHEMA_BLOCKERS_V1, SCHEMA_MEMORY_V1, SCHEMA_ORPHANS_V1, SCHEMA_PROPOSAL_V1,
    SCHEMA_PROTECT_V1, SCHEMA_STORAGE_V1, SCHEMA_TRASH_V1,
};
use std::env;
use std::path::PathBuf;

const ORPHAN_SCAN_WARNING: &str = "warning: orphan scanning runs git inside repositories found on disk and is unreviewed, experimental behavior (see docs: Known limitations). Only use it on repositories you trust.";
const ORPHAN_SCAN_DISABLED_MESSAGE: &str = "Orphan scanning runs git inside repositories found on disk and is disabled by default (unreviewed, experimental). Opt in with --include-orphans.";
use std::process::{Command, ExitCode};

#[derive(Parser)]
#[command(name = "sj", version, about = "SpaceJanitor Rust Core CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan directory storage usage with bounded parallel traversal
    Scan {
        /// Root directory to scan (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Maximum directory traversal depth
        #[arg(long, default_value_t = 4)]
        depth: usize,
        /// Maximum number of top entries to return
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Stay on the same filesystem as the root path
        #[arg(long, default_value_t = false)]
        same_fs: bool,
        /// Emit versioned JSON output
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Inspect OS Trash / Recycle Bin (read-only)
    Trash {
        /// Override trash directory path
        #[arg(long)]
        path: Option<PathBuf>,
        /// Emit versioned JSON output
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Discover nested .git repos/worktrees and prove clean & pushed safety
    Orphans {
        /// Root directory to search (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Maximum nested search depth
        #[arg(long, default_value_t = 5)]
        depth: usize,
        /// Opt in to scanning: runs git inside repositories found on disk (unreviewed, experimental)
        #[arg(long, default_value_t = false)]
        include_orphans: bool,
        /// Emit versioned JSON output
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Build a deterministic dry-run remediation plan (or execute one item with explicit gates)
    Plan {
        /// Root directory for orphan inspection (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Include OS Trash items in the plan
        #[arg(long, default_value_t = false)]
        include_trash: bool,
        /// Opt in to orphan worktrees in the plan: runs git inside repositories found on disk
        /// (OFF by default; unreviewed, experimental)
        #[arg(long, default_value_t = false)]
        include_orphans: bool,
        /// Override trash directory path
        #[arg(long)]
        trash_path: Option<PathBuf>,
        /// Maximum nested orphan search depth
        #[arg(long, default_value_t = 5)]
        depth: usize,
        /// Execute remediation for a single allowlisted item (requires --confirm, --plan-sha256, --item)
        #[arg(long, default_value_t = false)]
        execute: bool,
        /// Explicit confirmation for --execute
        #[arg(long, default_value_t = false)]
        confirm: bool,
        /// Expected plan SHA-256 digest for --execute
        #[arg(long)]
        plan_sha256: Option<String>,
        /// Allowlisted item ID to execute
        #[arg(long)]
        item: Option<String>,
        /// Emit versioned JSON output
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Evaluate paths against the protected-path gate (lexical + symlink-resolved; optional subtree walk)
    Protect {
        /// Paths to evaluate
        #[arg(required = true, num_args = 1.., last = true)]
        paths: Vec<PathBuf>,
        /// Extra user-protected path (the path and everything below it); repeatable
        #[arg(long = "exact")]
        exact: Vec<PathBuf>,
        /// Extra runtime-protected path (for example an active worktree); repeatable
        #[arg(long = "dynamic")]
        dynamic: Vec<PathBuf>,
        /// Extra case-insensitive wildcard pattern (`*`, `?`) matched on the path and its last segment; repeatable
        #[arg(long = "glob")]
        glob: Vec<String>,
        /// Also walk each directory and block when any descendant is protected, a symlink or unreadable
        #[arg(long, default_value_t = false)]
        descendants: bool,
        /// Maximum entries to inspect per directory walk (fail closed when exceeded)
        #[arg(long, default_value_t = 200_000)]
        max_entries: usize,
        /// Emit versioned JSON output
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Verify runtime platform capabilities and schema contracts
    Doctor {
        /// Emit versioned JSON output
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

enum CliError {
    Sj(SjError),
    Usage(String),
}

impl From<SjError> for CliError {
    fn from(err: SjError) -> Self {
        Self::Sj(err)
    }
}

fn print_doctor(json_mode: bool) -> Result<(), CliError> {
    let git_probe = Command::new("git").arg("--version").output();
    let (git_available, git_version) = match git_probe {
        Ok(out) if out.status.success() => (
            true,
            Some(String::from_utf8_lossy(&out.stdout).trim().to_string()),
        ),
        _ => (false, None),
    };

    let home_dir_resolved = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .is_some_and(|p| p.is_dir());

    let ready = git_available && home_dir_resolved;
    let version = env!("CARGO_PKG_VERSION");
    let os = env::consts::OS;
    let arch = env::consts::ARCH;
    let schemas = vec![
        SCHEMA_STORAGE_V1,
        SCHEMA_TRASH_V1,
        SCHEMA_MEMORY_V1,
        SCHEMA_BLOCKERS_V1,
        SCHEMA_ORPHANS_V1,
        SCHEMA_PROPOSAL_V1,
    ];

    if json_mode {
        let report = serde_json::json!({
            "schema": "spacejanitor.doctor.v1",
            "engine": "rust",
            "version": version,
            "os": os,
            "arch": arch,
            "schemas": schemas,
            "git_available": git_available,
            "git_version": git_version,
            "home_dir_resolved": home_dir_resolved,
            "ready": ready,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(SjError::from)?
        );
    } else {
        println!("sj (Rust core) v{version} — {os}/{arch}");
        println!("schemas: {}", schemas.join(", "));
        println!(
            "git: {} ({})",
            if git_available { "ok" } else { "missing" },
            git_version.as_deref().unwrap_or("unavailable")
        );
        println!(
            "home_dir: {}",
            if home_dir_resolved {
                "ok"
            } else {
                "unresolved"
            }
        );
        println!("status: {}", if ready { "READY" } else { "NOT_READY" });
    }
    Ok(())
}

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    let ctx = ProtectionContext::from_env();

    match cli.command {
        Commands::Doctor { json } => {
            print_doctor(json)?;
        }
        Commands::Protect {
            paths,
            exact,
            dynamic,
            glob,
            descendants,
            max_entries,
            json,
        } => {
            let mut pctx = ctx.clone();
            pctx.exact_paths.extend(exact);
            pctx.dynamic_paths = dynamic;
            pctx.glob_patterns = glob;
            let ctx = &pctx;
            let mut results = Vec::with_capacity(paths.len());
            for p in &paths {
                let mut verdict = check_path_protection(p, ctx);
                if !verdict.protected && descendants {
                    verdict = check_dir_descendants_safe(p, ctx, max_entries);
                }
                results.push(serde_json::json!({
                    "path": p.to_string_lossy(),
                    "protected": verdict.protected,
                    "reason": verdict.reason,
                }));
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "schema": SCHEMA_PROTECT_V1,
                        "descendants": descendants,
                        "results": results,
                    }))
                    .map_err(SjError::from)?
                );
            } else {
                for r in &results {
                    println!(
                        "{} {} {}",
                        if r["protected"] == true {
                            "PROTECTED"
                        } else {
                            "SAFE"
                        },
                        r["path"].as_str().unwrap_or(""),
                        r["reason"].as_str().unwrap_or("")
                    );
                }
            }
        }
        Commands::Scan {
            path,
            depth,
            top,
            same_fs,
            json,
        } => {
            let opts = ScanOptions {
                max_depth: depth,
                top_n: top,
                same_filesystem: same_fs,
                ..Default::default()
            };
            let report = scan_directory(&path, &ctx, &opts)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(SjError::from)?
                );
            } else {
                println!(
                    "scan: {} ({} bytes, {} files, status={:?})",
                    report.root, report.total_bytes, report.file_count, report.status
                );
                for entry in &report.entries {
                    println!("  {:>12}  {} ({})", entry.bytes, entry.path, entry.kind);
                }
            }
        }
        Commands::Trash { path, json } => {
            let target = match path {
                Some(p) => p,
                None => default_trash_paths(&ctx.home_dir)
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        CliError::Usage("no default trash path for platform".to_string())
                    })?,
            };
            let report = discover_trash_at(&target, &ctx)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(SjError::from)?
                );
            } else {
                println!(
                    "trash: {} (exists={}, items={}, total={}B, reclaimable={}B, protected={})",
                    report.trash_path,
                    report.exists,
                    report.item_count,
                    report.total_bytes,
                    report.reclaimable_bytes,
                    report.protected_items.len()
                );
            }
        }
        Commands::Orphans {
            path,
            depth,
            include_orphans,
            json,
        } => {
            if !include_orphans {
                // Off by default: nothing is scanned and git is never spawned.
                let report = serde_json::json!({
                    "schema": SCHEMA_ORPHANS_V1,
                    "root": path.to_string_lossy(),
                    "scanned": false,
                    "not_scanned_reason": "orphan_scan_disabled_by_default",
                    "message": ORPHAN_SCAN_DISABLED_MESSAGE,
                    "candidates_scanned": 0,
                    "safe_to_prune": [],
                    "blocked": [],
                });
                if json {
                    println!("{}", serde_json::to_string_pretty(&report).map_err(SjError::from)?);
                } else {
                    println!("orphans: not scanned (disabled by default). {ORPHAN_SCAN_DISABLED_MESSAGE}");
                }
                return Ok(());
            }
            eprintln!("{ORPHAN_SCAN_WARNING}");
            let report = inspect_orphans(&path, &ctx, &OrphanOptions { max_depth: depth })?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(SjError::from)?
                );
            } else {
                println!(
                    "orphans: {} (scanned={}, safe={}, blocked={})",
                    report.root,
                    report.candidates_scanned,
                    report.safe_to_prune.len(),
                    report.blocked.len()
                );
                for c in &report.safe_to_prune {
                    println!("  SAFE    {} ({}B)", c.path, c.bytes);
                }
                for b in &report.blocked {
                    println!("  BLOCKED {} [{}]", b.path, b.reasons.join(", "));
                }
            }
        }
        Commands::Plan {
            path,
            include_trash,
            include_orphans,
            trash_path,
            depth,
            execute,
            confirm,
            plan_sha256,
            item,
            json,
        } => {
            if execute && trash_path.is_some() {
                return Err(CliError::Usage(
                    "cannot combine --trash-path with --execute; execution is restricted to verified OS Trash roots".to_string(),
                ));
            }
            // Orphan scanning is OFF unless explicitly requested; a bare `sj plan` is trash only.
            let (inc_trash, inc_orphans) = if !include_trash && !include_orphans {
                (true, false)
            } else {
                (include_trash, include_orphans)
            };
            if inc_orphans {
                eprintln!("{ORPHAN_SCAN_WARNING}");
            }
            let opts = PlanOptions {
                include_trash: inc_trash,
                include_orphans: inc_orphans,
                trash_path_override: trash_path,
                orphan_max_depth: depth,
            };
            let plan = build_remediation_plan(&path, &ctx, &opts)?;
            if execute {
                let gate = ExecutionGate {
                    execute,
                    confirm,
                    plan_sha256: plan_sha256.unwrap_or_default(),
                    item_id: item.unwrap_or_default(),
                };
                let removed = execute_plan_item(&plan, &gate, &ctx)?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "schema": SCHEMA_PROPOSAL_V1,
                            "mode": "executed",
                            "mutated": true,
                            "plan_sha256": plan.plan_sha256,
                            "executed_item": removed,
                        }))
                        .map_err(SjError::from)?
                    );
                } else {
                    println!("executed: {} ({})", removed.id, removed.path);
                }
            } else if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&plan).map_err(SjError::from)?
                );
            } else {
                println!(
                    "plan: mode={} mutated={} sha256={} items={} reclaimable={}B excluded={}",
                    plan.mode,
                    plan.mutated,
                    plan.plan_sha256,
                    plan.items.len(),
                    plan.total_reclaimable_bytes,
                    plan.protected_exclusions.len()
                );
                for it in &plan.items {
                    println!("  {} [{}] {} ({}B)", it.id, it.tier, it.path, it.bytes);
                }
            }
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::Sj(SjError::ExecutionGate(msg))) | Err(CliError::Usage(msg)) => {
            eprintln!("error: {msg}");
            ExitCode::from(2)
        }
        Err(CliError::Sj(err)) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}
