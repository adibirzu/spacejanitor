#!/usr/bin/env node
/**
 * SpaceJanitor AXI CLI (ADR-003 / M4)
 * Token-efficient TOON output by default, versioned JSON contracts via --json.
 * Prefers the Rust `sj` binary when available, falling back to @spacejanitor/core.
 */

import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  adviseWithLocalSlm,
  collectBlockers,
  collectDisk,
  collectDoctor,
  collectMcpAudit,
  collectMemory,
  collectOrphans,
  ORPHAN_SCAN_WARNING,
  collectSummary,
  collectTrash,
  formatToon,
  normalizeReportEnvelope,
  runSjSync,
  buildSjPlanArgs,
} from "../../core/src/index.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VERSION = "0.1.0";

function printHelp() {
  const lines = [
    `spacejanitor-axi v${VERSION} — Cross-platform storage, orphan work, trash & true memory janitor`,
    "",
    "usage: spacejanitor-axi <command> [options]",
    "",
    "commands:",
    "  summary     Aggregated workstation health (disk, memory, blockers, orphans, mcp)",
    "  doctor      Check local OS/arch platform readiness and contract versions",
    "  disk        Audit filesystem capacity and top space consumers",
    "  memory      Audit true RAM footprint (RSS + compressed/swapped)",
    "  blockers    Detect kernel vnode, inotify, handle, and VFS lock blockers",
    "  orphans     Inspect git worktrees/orphan work (OFF by default; needs --include-orphans)",
    "  trash       Inspect OS Trash / Recycle Bin reclamation candidates",
    "  mcp-audit   Audit MCP server fan-out, duplicates, and redacted secret risks",
    "  remediate   Preview dry-run plan (--execute fails closed in Node fallback; use Desktop or Rust sj)",
    "  advise      Optional on-demand local SLM advisor (off by default; requires --slm-url)",
    "",
    "flags:",
    "  --json              Emit machine-readable versioned JSON contract",
    "  --fail-on-alert     Exit with code 2 if status is ALERT or CRITICAL",
    "  --path <dir>        Target path for disk/orphans scan",
    "  --include-orphans   Opt in to orphan scanning: runs git inside repositories found on disk (unreviewed, experimental)",
    "  --execute           Fail-closed execution guard (not implemented in Node AXI CLI)",
    "  --confirm <phrase>  Confirmation phrase from dry-run plan",
    "  --plan-sha256 <sha> SHA-256 digest from dry-run plan",
    "  -h, --help          Show help",
    "  -v, --version       Show version",
  ];
  console.log(lines.join("\n"));
}

function tryRustSj(subArgs) {
  // SPACEJANITOR_NO_SJ=1 forces the Node collectors (hermetic tests, locked-down hosts).
  // The sj binary is located by absolute path only (never PATH); see core/src/sjGate.mjs.
  try {
    const envMs = Number(process.env.SPACEJANITOR_SJ_TIMEOUT_MS);
    const timeoutMs = Number.isFinite(envMs) && envMs > 0 ? envMs : subArgs[0] === "orphans" ? 60000 : 5000;
    const parsed = runSjSync([...subArgs, "--json"], { timeoutMs });
    if (parsed && typeof parsed === "object" && parsed.schema) {
      return normalizeReportEnvelope({ ...parsed, source: "sj-core" });
    }
  } catch {
    // Fallback to Node telemetry collector (read-only views only)
  }
  return null;
}

const VALUE_FLAGS = new Set(["--path", "--confirm", "--plan-sha256", "--slm-url"]);

function parseCliArgs(argv) {
  const flags = new Set();
  const values = new Map();
  let cmd = null;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (VALUE_FLAGS.has(arg)) {
      if (i + 1 < argv.length) {
        values.set(arg, argv[i + 1]);
        i += 1;
      }
    } else if (arg.startsWith("-")) {
      flags.add(arg);
    } else if (!cmd) {
      cmd = arg;
    }
  }
  return { cmd: cmd || "help", flags, values };
}

function emit(report, wantsJson) {
  if (wantsJson) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(formatToon(report));
  }
}

async function main(argv) {
  const { cmd, flags, values } = parseCliArgs(argv);

  if (flags.has("-v") || flags.has("--version")) {
    console.log(VERSION);
    return 0;
  }
  if (flags.has("-h") || flags.has("--help") || cmd === "help") {
    printHelp();
    return 0;
  }

  const wantsJson = flags.has("--json");
  const failOnAlert = flags.has("--fail-on-alert");
  const targetPath = values.get("--path") || process.cwd();

  const includeOrphans = flags.has("--include-orphans");
  if (includeOrphans) console.error(ORPHAN_SCAN_WARNING);
  let report = null;

  if (cmd === "doctor") {
    report = tryRustSj(["doctor"]) || collectDoctor({ version: VERSION });
  } else if (cmd === "summary") {
    report = await collectSummary({ targetPath, includeOrphans });
  } else if (cmd === "disk") {
    report = tryRustSj(["scan", targetPath]) || (await collectDisk({ targetPath }));
  } else if (cmd === "memory") {
    report = tryRustSj(["memory"]) || (await collectMemory());
  } else if (cmd === "blockers") {
    report = tryRustSj(["blockers"]) || (await collectBlockers());
  } else if (cmd === "orphans") {
    // Off unless --include-orphans: no git is spawned and the report says "not scanned".
    report = await collectOrphans({ targetPath, includeOrphans });
  } else if (cmd === "trash") {
    report = tryRustSj(["trash"]) || (await collectTrash());
  } else if (cmd === "mcp-audit") {
    report = tryRustSj(["mcp-audit"]) || (await collectMcpAudit());
  } else if (cmd === "remediate") {
    // Plans and execution are decided by the Rust gate only. The Node CLI never executes.
    if (flags.has("--execute")) {
      emit(
        {
          schema: "spacejanitor.reap.v1",
          executed: false,
          reason: "not_implemented",
          error: "not_implemented: Node AXI CLI is dry-run only; use SpaceJanitor Desktop or `sj plan --execute --confirm`",
        },
        wantsJson
      );
      return 1;
    }
    try {
      report = runSjSync(buildSjPlanArgs({ root: targetPath, includeTrash: true, includeOrphans }), { timeoutMs: 60000 });
      if (report.schema !== "spacejanitor.proposal.v1") throw Object.assign(new Error("sj_unparseable"), { reason: "sj_unparseable" });
    } catch (err) {
      const reason = (err && err.reason) || "sj_unavailable";
      emit(
        { schema: "spacejanitor.reap.v1", executed: false, reason, error: `${reason}: remediation planning requires the Rust sj gate` },
        wantsJson
      );
      return 1;
    }
  } else if (cmd === "advise") {
    const slmUrl = values.get("--slm-url") || "";
    const enabled = Boolean(slmUrl);
    const summary = await collectSummary({ targetPath, includeOrphans });
    report = await adviseWithLocalSlm({
      enabled,
      url: slmUrl || "http://127.0.0.1:11434/v1/chat/completions",
      allowLan: flags.has("--allow-lan"),
      summary,
      memoryReport: summary.memory,
    });
  } else {
    console.error(`Unknown command: ${cmd}`);
    printHelp();
    return 1;
  }

  emit(report, wantsJson);

  if (failOnAlert && (report?.status === "ALERT" || report?.status === "CRITICAL")) {
    return 2;
  }
  return 0;
}

process.exitCode = await main(process.argv.slice(2));
