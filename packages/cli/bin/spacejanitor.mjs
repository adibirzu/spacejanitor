#!/usr/bin/env node
/**
 * SpaceJanitor AXI CLI (ADR-003 / M4)
 * Token-efficient TOON output by default, versioned JSON contracts via --json.
 * Prefers the Rust `sj` binary when available, falling back to @spacejanitor/core.
 */

import { execFileSync } from "node:child_process";
import fs from "node:fs";
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
  collectSummary,
  collectTrash,
  createRemediationPlan,
  formatToon,
  normalizeReportEnvelope,
  verifyRemediationGate,
} from "../../core/src/index.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "../../..");
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
    "  orphans     Inspect clean/pushed vs dirty git worktrees and orphan work",
    "  trash       Inspect OS Trash / Recycle Bin reclamation candidates",
    "  mcp-audit   Audit MCP server fan-out, duplicates, and redacted secret risks",
    "  remediate   Preview dry-run plan (--execute fails closed in Node fallback; use Desktop or Rust sj)",
    "  advise      Optional on-demand local SLM advisor (off by default; requires --slm-url)",
    "",
    "flags:",
    "  --json              Emit machine-readable versioned JSON contract",
    "  --fail-on-alert     Exit with code 2 if status is ALERT or CRITICAL",
    "  --path <dir>        Target path for disk/orphans scan",
    "  --execute           Fail-closed execution guard (not implemented in Node AXI CLI)",
    "  --confirm <phrase>  Confirmation phrase from dry-run plan",
    "  --plan-sha256 <sha> SHA-256 digest from dry-run plan",
    "  -h, --help          Show help",
    "  -v, --version       Show version",
  ];
  console.log(lines.join("\n"));
}

function findRustSjBinary() {
  const envBin = process.env.SPACEJANITOR_SJ_BIN;
  if (envBin && fs.existsSync(envBin)) return envBin;

  const exe = process.platform === "win32" ? "sj.exe" : "sj";
  const candidates = [
    path.resolve(REPO_ROOT, "target", "release", exe),
    path.resolve(REPO_ROOT, "target", "debug", exe),
  ];
  for (const cand of candidates) {
    if (fs.existsSync(cand)) return cand;
  }
  return exe;
}

// How the last Rust call failed ("timed_out" | "error" | null): destructive-action proofs must not
// silently fall back to the weaker Node answer when a Rust binary exists but could not finish.
let lastRustFailure = null;

function rustTimeoutMs(cmd) {
  const fromEnv = Number(process.env.SPACEJANITOR_SJ_TIMEOUT_MS);
  if (Number.isFinite(fromEnv) && fromEnv > 0) return fromEnv;
  return cmd === "orphans" ? 60000 : 5000;
}

function failClosedOnRustFailure(report) {
  if (!lastRustFailure || !report || !Array.isArray(report.candidates)) return report;
  return {
    ...report,
    rustProof: lastRustFailure,
    candidates: report.candidates.map((c) => ({
      ...c,
      safeToPrune: false,
      proofStatus: `rust_proof_${lastRustFailure}`,
    })),
  };
}

function tryRustSj(subArgs) {
  // SPACEJANITOR_NO_SJ=1 forces the Node collectors (hermetic tests, locked-down hosts).
  lastRustFailure = null;
  if (process.env.SPACEJANITOR_NO_SJ === "1") return null;
  const bin = findRustSjBinary();
  try {
    const out = execFileSync(bin, [...subArgs, "--json"], {
      encoding: "utf8",
      timeout: rustTimeoutMs(subArgs[0]),
      stdio: ["ignore", "pipe", "ignore"],
    });
    const parsed = JSON.parse(out);
    if (parsed && typeof parsed === "object" && parsed.schema) {
      return normalizeReportEnvelope({ ...parsed, source: "sj-core" });
    }
  } catch (err) {
    // Fallback to Node telemetry collector, but never silently for a binary that ran and failed
    if (err && err.code !== "ENOENT") {
      lastRustFailure = err.code === "ETIMEDOUT" || err.killed || err.signal ? "timed_out" : "error";
    }
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

  let report = null;

  if (cmd === "doctor") {
    report = tryRustSj(["doctor"]) || collectDoctor({ version: VERSION });
  } else if (cmd === "summary") {
    report = await collectSummary({ targetPath });
  } else if (cmd === "disk") {
    report = tryRustSj(["scan", targetPath]) || (await collectDisk({ targetPath }));
  } else if (cmd === "memory") {
    report = tryRustSj(["memory"]) || (await collectMemory());
  } else if (cmd === "blockers") {
    report = tryRustSj(["blockers"]) || (await collectBlockers());
  } else if (cmd === "orphans") {
    report =
      tryRustSj(["orphans", targetPath]) || failClosedOnRustFailure(await collectOrphans({ targetPath }));
  } else if (cmd === "trash") {
    report = tryRustSj(["trash"]) || (await collectTrash());
  } else if (cmd === "mcp-audit") {
    report = tryRustSj(["mcp-audit"]) || (await collectMcpAudit());
  } else if (cmd === "remediate") {
    const trash = await collectTrash();
    const plan = createRemediationPlan(trash.candidates || []);
    if (flags.has("--execute")) {
      const phrase = values.get("--confirm") || "";
      const planSha256 = values.get("--plan-sha256") || "";
      const gate = verifyRemediationGate({ plan, planSha256, phrase });
      const errObj = {
        schema: "spacejanitor.reap.v1",
        executed: false,
        reason: gate.allowed ? "not_implemented" : gate.reason,
        error: gate.allowed
          ? "not_implemented: Node AXI CLI is read-only/dry-run; use SpaceJanitor Desktop or Rust sj plan --execute"
          : gate.reason,
      };
      emit(errObj, wantsJson);
      return 1;
    }
    report = plan;
  } else if (cmd === "advise") {
    const slmUrl = values.get("--slm-url") || "";
    const enabled = Boolean(slmUrl);
    const summary = await collectSummary({ targetPath });
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
