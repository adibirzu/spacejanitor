use clap::{Parser, Subcommand};
use sj_core::{
    blockers::collect_blockers_report,
    linux::discover_linux_audit,
    llm_audit::{audit_llm_fleet, AuditPolicy, LlmAuditOptions, SCHEMA_LLM_AUDIT_V1},
    mcp_audit::{audit_mcp_fleet, McpAuditOptions},
    memory::{collect_memory_report, MemoryOptions},
    orphans::{inspect_orphans, OrphanOptions},
    plan::{
        build_remediation_plan, build_remediation_plan_with_linux, execute_plan_item,
        execute_selection, select_by_paths, selection_sha256 as selection_sha256_fn,
        ExecutionGate, LinuxPlanOptions, PlanOptions, SelectionGate,
    },
    protect::{check_dir_descendants_safe, check_path_protection, ProtectionContext},
    reap::{build_reap_plan, execute_reap_plan, ReapExecutionGate},
    scan::{scan_directory, ScanOptions},
    trash::{default_trash_paths, discover_trash_at},
    SjError, SCHEMA_BLOCKERS_V1, SCHEMA_LINUX_AUDIT_V1, SCHEMA_MCP_AUDIT_V1, SCHEMA_MEMORY_V1,
    SCHEMA_ORPHANS_V1, SCHEMA_PROPOSAL_V1, SCHEMA_PROTECT_V1, SCHEMA_REAP_V1, SCHEMA_STORAGE_V1,
    SCHEMA_TRASH_V1,
};
use std::env;
use std::io::{BufRead, Write};
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
    /// Collect system memory totals and per-process true memory footprint
    Memory {
        /// Maximum number of top processes to return
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Emit versioned JSON output
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Collect kernel, VFS, and OS resource pressure blockers
    Blockers {
        /// Emit versioned JSON output
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Audit MCP server configurations, duplicate/orphan processes, and inline secrets
    McpAudit {
        /// Override MCP configuration directories to scan
        #[arg(long = "config-dir")]
        config_dir: Vec<PathBuf>,
        /// Emit versioned JSON output
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Read-only audit of unused LLM plugins/skills, unused MCP servers and idle MCP sessions
    /// (dry-run only: there is no execute path in this release)
    LlmAudit {
        /// Home directory to inventory (defaults to $HOME / %USERPROFILE%)
        #[arg(long)]
        home: Option<PathBuf>,
        /// Idle-session threshold in hours
        #[arg(long, default_value_t = 2.0)]
        idle_hours: f64,
        /// Skill staleness threshold in days
        #[arg(long, default_value_t = 30)]
        unused_skill_days: u64,
        /// Additional plugin ids to keep enabled (repeatable)
        #[arg(long = "keep-plugin")]
        keep_plugin: Vec<String>,
        /// Additional skill names to keep (repeatable)
        #[arg(long = "keep-skill")]
        keep_skill: Vec<String>,
        /// Additional MCP server names to keep (repeatable)
        #[arg(long = "keep-mcp")]
        keep_mcp: Vec<String>,
        /// Emit versioned JSON output
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Plan or execute safe PPID=1 orphan process reaping (dry-run by default)
    Reap {
        /// Minimum process age in minutes before eligibility
        #[arg(long, default_value_t = 30)]
        min_age_mins: u64,
        /// Explicitly request dry-run preview (default)
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Execute termination (requires --confirm and --plan-sha256)
        #[arg(long, default_value_t = false)]
        execute: bool,
        /// Exact confirmation phrase from the dry-run plan
        #[arg(long)]
        confirm: Option<String>,
        /// Expected plan SHA-256 digest from the dry-run plan
        #[arg(long)]
        plan_sha256: Option<String>,
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
        /// Include Linux diagnostics cleanup candidates (user caches, stale /tmp, docker/podman/journald/apt)
        #[arg(long, default_value_t = false)]
        include_linux: bool,
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
        /// Select a plan item by path (repeatable). Dry-run reports the selection digest; with
        /// --execute --selection-sha256 exactly these items are removed, and only if a freshly built
        /// plan hashes to the confirmed digest
        #[arg(long = "select")]
        select: Vec<String>,
        /// Selection digest confirmed by the user (from a dry run with the same --select paths)
        #[arg(long)]
        selection_sha256: Option<String>,
        /// Extra user-protected path (the path and everything below it); repeatable
        #[arg(long = "exact")]
        exact: Vec<PathBuf>,
        /// Extra runtime-protected path; repeatable
        #[arg(long = "dynamic")]
        dynamic: Vec<PathBuf>,
        /// Extra case-insensitive wildcard protection pattern; repeatable
        #[arg(long = "glob")]
        glob: Vec<String>,
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
    /// Audit Linux storage consumers, mounts, containers, journald, caches, and systemd units
    LinuxAudit {
        /// Home/root directory for user cache & model discovery (defaults to HOME)
        #[arg(long)]
        path: Option<PathBuf>,
        /// Optional /tmp directory override
        #[arg(long)]
        tmp_path: Option<PathBuf>,
        /// Emit versioned JSON output
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Serve newline-delimited JSON-RPC 2.0 over stdin/stdout
    ServeStdio,
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

fn build_doctor_json() -> serde_json::Value {
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
        SCHEMA_LINUX_AUDIT_V1,
        SCHEMA_MCP_AUDIT_V1,
        SCHEMA_REAP_V1,
        SCHEMA_LLM_AUDIT_V1,
    ];

    serde_json::json!({
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
    })
}

fn print_doctor(json_mode: bool) -> Result<(), CliError> {
    let report = build_doctor_json();
    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(SjError::from)?
        );
    } else {
        println!(
            "sj (Rust core) v{} — {}/{}",
            report["version"].as_str().unwrap_or(""),
            report["os"].as_str().unwrap_or(""),
            report["arch"].as_str().unwrap_or("")
        );
        let schemas: Vec<&str> = report["schemas"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        println!("schemas: {}", schemas.join(", "));
        println!(
            "git: {} ({})",
            if report["git_available"].as_bool().unwrap_or(false) {
                "ok"
            } else {
                "missing"
            },
            report["git_version"].as_str().unwrap_or("unavailable")
        );
        println!(
            "home_dir: {}",
            if report["home_dir_resolved"].as_bool().unwrap_or(false) {
                "ok"
            } else {
                "unresolved"
            }
        );
        println!(
            "status: {}",
            if report["ready"].as_bool().unwrap_or(false) {
                "READY"
            } else {
                "NOT_READY"
            }
        );
    }
    Ok(())
}

fn jsonrpc_error(id: serde_json::Value, code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    })
}

fn dispatch_rpc_method(
    method: &str,
    params: &serde_json::Value,
    ctx: &ProtectionContext,
) -> Result<serde_json::Value, (i64, String)> {
    match method {
        "doctor" => Ok(build_doctor_json()),
        "scan" => {
            let path = params
                .get("path")
                .and_then(|v| v.as_str())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            let depth = params.get("depth").and_then(|v| v.as_u64()).unwrap_or(4) as usize;
            let top = params.get("top").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
            let same_fs = params
                .get("same_fs")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let opts = ScanOptions {
                max_depth: depth,
                top_n: top,
                same_filesystem: same_fs,
                ..Default::default()
            };
            let report = scan_directory(&path, ctx, &opts).map_err(|e| (-32000, e.to_string()))?;
            serde_json::to_value(report).map_err(|e| (-32000, e.to_string()))
        }
        "trash" => {
            let target = match params.get("path").and_then(|v| v.as_str()) {
                Some(p) => PathBuf::from(p),
                None => default_trash_paths(&ctx.home_dir)
                    .into_iter()
                    .next()
                    .ok_or_else(|| (-32000, "no default trash path for platform".to_string()))?,
            };
            let report = discover_trash_at(&target, ctx).map_err(|e| (-32000, e.to_string()))?;
            serde_json::to_value(report).map_err(|e| (-32000, e.to_string()))
        }
        "orphans" => {
            let path = params
                .get("path")
                .and_then(|v| v.as_str())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            let depth = params.get("depth").and_then(|v| v.as_u64()).unwrap_or(5) as usize;
            if params.get("include_orphans").and_then(|v| v.as_bool()) != Some(true) {
                return Ok(serde_json::json!({
                    "schema": SCHEMA_ORPHANS_V1,
                    "root": path.to_string_lossy(),
                    "scanned": false,
                    "not_scanned_reason": "orphan_scan_disabled_by_default",
                    "message": ORPHAN_SCAN_DISABLED_MESSAGE,
                    "candidates_scanned": 0,
                    "safe_to_prune": [],
                    "blocked": [],
                }));
            }
            let report = inspect_orphans(&path, ctx, &OrphanOptions { max_depth: depth })
                .map_err(|e| (-32000, e.to_string()))?;
            serde_json::to_value(report).map_err(|e| (-32000, e.to_string()))
        }
        "memory" => {
            let top_n = params.get("top").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
            let report = collect_memory_report(&MemoryOptions { top_n })
                .map_err(|e| (-32000, e.to_string()))?;
            serde_json::to_value(report).map_err(|e| (-32000, e.to_string()))
        }
        "blockers" => {
            let report = collect_blockers_report().map_err(|e| (-32000, e.to_string()))?;
            serde_json::to_value(report).map_err(|e| (-32000, e.to_string()))
        }
        "linux_audit" => {
            let home = params
                .get("path")
                .and_then(|v| v.as_str())
                .map(PathBuf::from)
                .unwrap_or_else(|| ctx.home_dir.clone());
            let tmp_path = params.get("tmp_path").and_then(|v| v.as_str()).map(PathBuf::from);
            let report = discover_linux_audit(&home, tmp_path.as_deref());
            serde_json::to_value(report).map_err(|e| (-32000, e.to_string()))
        }
        "mcp_audit" => {
            let config_dirs = params
                .get("config_dirs")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(PathBuf::from))
                        .collect()
                })
                .unwrap_or_default();
            let report = audit_mcp_fleet(&McpAuditOptions {
                config_dirs,
                home_dir: None,
            })
            .map_err(|e| (-32000, e.to_string()))?;
            serde_json::to_value(report).map_err(|e| (-32000, e.to_string()))
        }
        "llm_audit" => {
            let home_dir = params
                .get("home")
                .and_then(|v| v.as_str())
                .map(PathBuf::from)
                .unwrap_or_else(|| ctx.home_dir.clone());
            let mut policy = AuditPolicy::default();
            if let Some(h) = params.get("idle_hours").and_then(|v| v.as_f64()) {
                policy.idle_session_hours = h;
            }
            if let Some(d) = params.get("unused_skill_days").and_then(|v| v.as_u64()) {
                policy.unused_skill_days = d;
            }
            let names = |key: &str| -> Vec<String> {
                params
                    .get(key)
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                    .unwrap_or_default()
            };
            policy.keep_enabled_plugins.extend(names("keep_plugin"));
            policy.keep_enabled_skills.extend(names("keep_skill"));
            policy.keep_enabled_mcps.extend(names("keep_mcp"));
            let report = audit_llm_fleet(&LlmAuditOptions {
                home_dir,
                policy,
                now_epoch_secs: None,
            })
            .map_err(|e| (-32000, e.to_string()))?;
            serde_json::to_value(report).map_err(|e| (-32000, e.to_string()))
        }
        "plan_reap" => {
            let min_age_mins = params
                .get("min_age_mins")
                .and_then(|v| v.as_u64())
                .unwrap_or(30);
            let plan = build_reap_plan(min_age_mins).map_err(|e| (-32000, e.to_string()))?;
            serde_json::to_value(plan).map_err(|e| (-32000, e.to_string()))
        }
        "execute_reap" => {
            let min_age_mins = params
                .get("min_age_mins")
                .and_then(|v| v.as_u64())
                .unwrap_or(30);
            let confirm_phrase = params
                .get("confirm")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let plan_sha256 = params
                .get("plan_sha256")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let plan = build_reap_plan(min_age_mins).map_err(|e| (-32000, e.to_string()))?;
            let report = execute_reap_plan(
                &plan,
                &ReapExecutionGate {
                    execute: true,
                    confirm_phrase,
                    plan_sha256,
                },
            )
            .map_err(|e| (-32000, e.to_string()))?;
            serde_json::to_value(report).map_err(|e| (-32000, e.to_string()))
        }
        "plan_cleanup" => {
            let path = params
                .get("path")
                .and_then(|v| v.as_str())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            let include_trash = params
                .get("include_trash")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            // Orphan scanning runs git inside repos found on disk: off unless explicitly requested.
            let include_orphans = params
                .get("include_orphans")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let trash_path_override = params
                .get("trash_path")
                .and_then(|v| v.as_str())
                .map(PathBuf::from);
            let orphan_max_depth =
                params.get("depth").and_then(|v| v.as_u64()).unwrap_or(5) as usize;
            let plan = build_remediation_plan(
                &path,
                ctx,
                &PlanOptions {
                    include_trash,
                    include_orphans,
                    trash_path_override,
                    orphan_max_depth,
                },
            )
            .map_err(|e| (-32000, e.to_string()))?;
            serde_json::to_value(plan).map_err(|e| (-32000, e.to_string()))
        }
        "execute_cleanup" => {
            let path = params
                .get("path")
                .and_then(|v| v.as_str())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            let include_trash = params
                .get("include_trash")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            // Orphan scanning runs git inside repos found on disk: off unless explicitly requested.
            let include_orphans = params
                .get("include_orphans")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let orphan_max_depth =
                params.get("depth").and_then(|v| v.as_u64()).unwrap_or(5) as usize;
            let confirm = params
                .get("confirm")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let plan_sha256 = params
                .get("plan_sha256")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let item_id = params
                .get("item")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let plan = build_remediation_plan(
                &path,
                ctx,
                &PlanOptions {
                    include_trash,
                    include_orphans,
                    trash_path_override: None,
                    orphan_max_depth,
                },
            )
            .map_err(|e| (-32000, e.to_string()))?;
            let removed = execute_plan_item(
                &plan,
                &ExecutionGate {
                    execute: true,
                    confirm,
                    plan_sha256,
                    item_id,
                },
                ctx,
            )
            .map_err(|e| (-32000, e.to_string()))?;
            Ok(serde_json::json!({
                "schema": SCHEMA_PROPOSAL_V1,
                "mode": "executed",
                "mutated": true,
                "plan_sha256": plan.plan_sha256,
                "executed_item": removed,
            }))
        }
        _ => Err((-32601, "method not found".to_string())),
    }
}

fn run_serve_stdio(ctx: &ProtectionContext) -> Result<(), CliError> {
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    let mut stdout = std::io::stdout();
    let mut buf = Vec::new();

    loop {
        buf.clear();
        let n = lock.read_until(b'\n', &mut buf).map_err(SjError::from)?;
        if n == 0 {
            break;
        }
        let resp_opt = match std::str::from_utf8(&buf) {
            Err(err) => Some(jsonrpc_error(
                serde_json::Value::Null,
                -32700,
                &format!("parse error: invalid utf-8: {err}"),
            )),
            Ok(line) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match serde_json::from_str::<serde_json::Value>(trimmed) {
                    Err(err) => Some(jsonrpc_error(
                        serde_json::Value::Null,
                        -32700,
                        &format!("parse error: {err}"),
                    )),
                    Ok(req) => {
                        let has_id = req.is_object() && req.get("id").is_some();
                        let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
                        let method = req.get("method").and_then(|v| v.as_str());
                        let params = req
                            .get("params")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({}));
                        if !has_id {
                            if let Some(m) = method {
                                let _ = dispatch_rpc_method(m, &params, ctx);
                            }
                            None
                        } else {
                            Some(match method {
                                None => {
                                    jsonrpc_error(id, -32600, "invalid request: missing method")
                                }
                                Some(m) => match dispatch_rpc_method(m, &params, ctx) {
                                    Ok(result) => serde_json::json!({
                                        "jsonrpc": "2.0",
                                        "id": id,
                                        "result": result,
                                    }),
                                    Err((code, msg)) => jsonrpc_error(id, code, &msg),
                                },
                            })
                        }
                    }
                }
            }
        };
        if let Some(resp) = resp_opt {
            let encoded = serde_json::to_string(&resp).map_err(SjError::from)?;
            writeln!(stdout, "{encoded}").map_err(SjError::from)?;
            stdout.flush().map_err(SjError::from)?;
        }
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
        Commands::LinuxAudit {
            path,
            tmp_path,
            json,
        } => {
            let home = path.unwrap_or_else(|| ctx.home_dir.clone());
            let report = discover_linux_audit(&home, tmp_path.as_deref());
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(SjError::from)?
                );
            } else {
                println!(
                    "linux-audit: {}/{} | mounts={} appimages={} docker_exited={} podman_exited={} journald={}B apt={}B systemd_sys_failed={} systemd_user_failed={}",
                    report.os,
                    report.arch,
                    report.mounts.len(),
                    report.appimage_mounts.len(),
                    report.docker.exited_containers.len(),
                    report.podman.exited_containers.len(),
                    report.journald.bytes,
                    report.package_caches.apt_archives_bytes,
                    report.systemd.system_failed.len(),
                    report.systemd.user_failed.len(),
                );
            }
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
        Commands::Memory { top, json } => {
            let report = collect_memory_report(&MemoryOptions { top_n: top })?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(SjError::from)?
                );
            } else {
                println!(
                    "memory ({}): total={}B used={}B compressed={}B swap_used={}B pressure={}",
                    report.os,
                    report.system.total_bytes,
                    report.system.used_bytes,
                    report.system.compressed_bytes,
                    report.system.swap_used_bytes,
                    report.system.pressure_state
                );
                for p in &report.processes {
                    println!(
                        "  pid={:<6} ppid={:<6} footprint={}B  {}",
                        p.pid, p.ppid, p.true_footprint_bytes, p.command
                    );
                }
            }
        }
        Commands::Blockers { json } => {
            let report = collect_blockers_report()?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(SjError::from)?
                );
            } else {
                println!(
                    "blockers ({}): status={} count={}",
                    report.os,
                    report.status,
                    report.blockers.len()
                );
                for b in &report.blockers {
                    println!("  [{}] {}: {} — {}", b.severity, b.id, b.title, b.detail);
                }
            }
        }
        Commands::McpAudit { config_dir, json } => {
            let report = audit_mcp_fleet(&McpAuditOptions {
                config_dirs: config_dir,
                home_dir: None,
            })?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(SjError::from)?
                );
            } else {
                println!(
                    "mcp-audit: files={} servers={} running={} duplicates={} orphans={} secret_findings={}",
                    report.scanned_files.len(),
                    report.configured_servers.len(),
                    report.running_processes.len(),
                    report.duplicate_groups.len(),
                    report.orphan_processes.len(),
                    report.secret_findings.len()
                );
            }
        }
        Commands::LlmAudit {
            home,
            idle_hours,
            unused_skill_days,
            keep_plugin,
            keep_skill,
            keep_mcp,
            json,
        } => {
            let mut policy = AuditPolicy {
                idle_session_hours: idle_hours,
                unused_skill_days,
                ..AuditPolicy::default()
            };
            policy.keep_enabled_plugins.extend(keep_plugin);
            policy.keep_enabled_skills.extend(keep_skill);
            policy.keep_enabled_mcps.extend(keep_mcp);
            let home_dir = home.unwrap_or_else(|| ctx.home_dir.clone());
            let report = audit_llm_fleet(&LlmAuditOptions {
                home_dir,
                policy,
                now_epoch_secs: None,
            })?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(SjError::from)?
                );
            } else {
                println!(
                    "llm-audit (dry-run): plugins={} stale_plugin_caches={} stale_skills={} broken_symlinks={} duplicate_skills={} unused_mcp={} idle_sessions={} planned_actions={}",
                    report.plugins.len(),
                    report.stale_plugin_caches.len(),
                    report.stale_skills.len(),
                    report.broken_skill_symlinks.len(),
                    report.duplicate_skill_dirs.len(),
                    report.unused_mcp_servers.len(),
                    report.idle_sessions.len(),
                    report.planned_actions.len()
                );
            }
        }
        Commands::Reap {
            min_age_mins,
            dry_run,
            execute,
            confirm,
            plan_sha256,
            json,
        } => {
            if dry_run && execute {
                return Err(CliError::Usage(
                    "cannot combine --dry-run and --execute".to_string(),
                ));
            }
            let plan = build_reap_plan(min_age_mins)?;
            if execute {
                let gate = ReapExecutionGate {
                    execute: true,
                    confirm_phrase: confirm.unwrap_or_default(),
                    plan_sha256: plan_sha256.unwrap_or_default(),
                };
                let report = execute_reap_plan(&plan, &gate)?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).map_err(SjError::from)?
                    );
                } else {
                    println!(
                        "reap executed: terminated={} skipped={} sha256={}",
                        report.terminated_count, report.skipped_count, report.plan_sha256
                    );
                }
            } else if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&plan).map_err(SjError::from)?
                );
            } else {
                println!(
                    "reap (dry-run): targets={} excluded={} sha256={} confirm=\"{}\"",
                    plan.targets.len(),
                    plan.excluded.len(),
                    plan.plan_sha256,
                    plan.confirm_phrase
                );
                for t in &plan.targets {
                    println!("  pid={:<6} age={}s {}", t.pid, t.elapsed_secs, t.command);
                }
            }
        }
        Commands::Plan {
            path,
            include_trash,
            include_orphans,
            include_linux,
            trash_path,
            depth,
            execute,
            confirm,
            plan_sha256,
            item,
            select,
            selection_sha256,
            exact,
            dynamic,
            glob,
            json,
        } => {
            let mut pctx = ctx.clone();
            pctx.exact_paths.extend(exact);
            pctx.dynamic_paths = dynamic;
            pctx.glob_patterns = glob;
            let ctx = pctx;
            if execute && trash_path.is_some() {
                return Err(CliError::Usage(
                    "cannot combine --trash-path with --execute; execution is restricted to verified OS Trash roots".to_string(),
                ));
            }
            // Orphan scanning is OFF unless explicitly requested; a bare `sj plan` is trash only.
            let (inc_trash, inc_orphans) = if !include_trash && !include_orphans && !include_linux {
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
            let plan = build_remediation_plan_with_linux(
                &path,
                &ctx,
                &opts,
                &LinuxPlanOptions {
                    include_linux,
                    ..Default::default()
                },
            )?;
            if execute && selection_sha256.is_some() {
                let gate = SelectionGate {
                    execute,
                    confirm,
                    selection_sha256: selection_sha256.unwrap_or_default(),
                    paths: select,
                };
                let out = execute_selection(&plan, &gate, &ctx)?;
                let failed: Vec<serde_json::Value> = out
                    .failed
                    .iter()
                    .map(|(i, e)| serde_json::json!({"id": i.id, "path": i.path, "error": e}))
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "schema": SCHEMA_PROPOSAL_V1,
                        "mode": "executed",
                        "mutated": !out.executed.is_empty(),
                        "selection_sha256": gate.selection_sha256,
                        "executed_items": out.executed,
                        "failed_items": failed,
                    }))
                    .map_err(SjError::from)?
                );
            } else if execute {
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
                let mut value = serde_json::to_value(&plan).map_err(SjError::from)?;
                if !select.is_empty() {
                    let (items, unmatched) = select_by_paths(&plan, &select);
                    value["selection"] = serde_json::json!({
                        "paths": items.iter().map(|i| i.path.clone()).collect::<Vec<_>>(),
                        "ids": items.iter().map(|i| i.id.clone()).collect::<Vec<_>>(),
                        "unmatched": unmatched,
                        "selection_sha256": selection_sha256_fn(&items)?,
                    });
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).map_err(SjError::from)?
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
        Commands::ServeStdio => {
            run_serve_stdio(&ctx)?;
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
