use clap::{Parser, Subcommand};
use sj_core::{
    orphans::{inspect_orphans, OrphanOptions},
    plan::{build_remediation_plan, execute_plan_item, ExecutionGate, PlanOptions},
    protect::ProtectionContext,
    scan::{scan_directory, ScanOptions},
    trash::{default_trash_paths, discover_trash_at},
    SCHEMA_BLOCKERS_V1, SCHEMA_MEMORY_V1, SCHEMA_ORPHANS_V1, SCHEMA_PROPOSAL_V1, SCHEMA_STORAGE_V1,
    SCHEMA_TRASH_V1,
};
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

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
        /// Include safe-to-prune orphan worktrees in the plan
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
    /// Verify runtime platform capabilities and schema contracts
    Doctor {
        /// Emit versioned JSON output
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

fn print_doctor(json_mode: bool) {
    let os = env::consts::OS;
    let arch = env::consts::ARCH;
    let version = env!("CARGO_PKG_VERSION");
    if json_mode {
        println!(
            "{{\"schema\":\"spacejanitor.doctor.v1\",\"engine\":\"rust\",\"version\":\"{version}\",\"os\":\"{os}\",\"arch\":\"{arch}\",\"schemas\":[\"{SCHEMA_STORAGE_V1}\",\"{SCHEMA_TRASH_V1}\",\"{SCHEMA_MEMORY_V1}\",\"{SCHEMA_BLOCKERS_V1}\",\"{SCHEMA_ORPHANS_V1}\",\"{SCHEMA_PROPOSAL_V1}\"],\"ready\":true}}"
        );
    } else {
        println!("sj (Rust core) v{version} — {os}/{arch}");
        println!("schemas: {SCHEMA_STORAGE_V1}, {SCHEMA_TRASH_V1}, {SCHEMA_MEMORY_V1}, {SCHEMA_BLOCKERS_V1}, {SCHEMA_ORPHANS_V1}, {SCHEMA_PROPOSAL_V1}");
        println!("status: READY");
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let ctx = ProtectionContext::from_env();

    match cli.command {
        Commands::Doctor { json } => {
            print_doctor(json);
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
            let report = scan_directory(&path, &ctx, &opts).map_err(|e| e.to_string())?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
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
                    .ok_or_else(|| "no default trash path for platform".to_string())?,
            };
            let report = discover_trash_at(&target, &ctx).map_err(|e| e.to_string())?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
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
        Commands::Orphans { path, depth, json } => {
            let report = inspect_orphans(&path, &ctx, &OrphanOptions { max_depth: depth })
                .map_err(|e| e.to_string())?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
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
            let (inc_trash, inc_orphans) = if !include_trash && !include_orphans {
                (true, true)
            } else {
                (include_trash, include_orphans)
            };
            let opts = PlanOptions {
                include_trash: inc_trash,
                include_orphans: inc_orphans,
                trash_path_override: trash_path,
                orphan_max_depth: depth,
            };
            let plan = build_remediation_plan(&path, &ctx, &opts).map_err(|e| e.to_string())?;
            if execute {
                let gate = ExecutionGate {
                    execute,
                    confirm,
                    plan_sha256: plan_sha256.unwrap_or_default(),
                    item_id: item.unwrap_or_default(),
                };
                let removed = execute_plan_item(&plan, &gate, &ctx).map_err(|e| e.to_string())?;
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
                        .map_err(|e| e.to_string())?
                    );
                } else {
                    println!("executed: {} ({})", removed.id, removed.path);
                }
            } else if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&plan).map_err(|e| e.to_string())?
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
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}
