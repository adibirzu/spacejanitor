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
  verifyRemediationGate,
} from "../../core/src/index.mjs";

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
    "  remediate   Preview dry-run plan (requires --execute --confirm <phrase> --plan-sha256 <sha>)",
    "  advise      Optional on-demand local SLM advisor (off by default; requires --slm-url)",
    "",
    "flags:",
    "  --json              Emit machine-readable versioned JSON contract",
    "  --fail-on-alert     Exit with code 2 if status is ALERT or CRITICAL",
    "  --path <dir>        Target path for disk/orphans scan",
    "  --execute           Execute remediation (requires --confirm and --plan-sha256)",
    "  --confirm <phrase>  Confirmation phrase from dry-run plan",
    "  --plan-sha256 <sha> SHA-256 digest from dry-run plan",
    "  -h, --help          Show help",
    "  -v, --version       Show version",
  ];
  console.log(lines.join("\n"));
}

function findRustSjBinary() {
  const exe = process.platform === "win32" ? "sj.exe" : "sj";
  const candidates = [
    path.resolve(process.cwd(), "target", "release", exe),
    path.resolve(process.cwd(), "target", "debug", exe),
  ];
  for (const cand of candidates) {
    if (fs.existsSync(cand)) return cand;
  }
  return exe;
}

function tryRustSj(subArgs) {
  const bin = findRustSjBinary();
  try {
    const out = execFileSync(bin, [...subArgs, "--json"], {
      encoding: "utf8",
      timeout: 5000,
      stdio: ["ignore", "pipe", "ignore"],
    });
    const parsed = JSON.parse(out);
    if (parsed && typeof parsed === "object" && parsed.schema) {
      return { ...parsed, source: "sj-core" };
    }
  } catch {
    // Fallback to Node telemetry collector
  }
  return null;
}

function getFlagValue(argv, flag) {
  const idx = argv.indexOf(flag);
  if (idx !== -1 && argv[idx + 1] && !argv[idx + 1].startsWith("-")) {
    return argv[idx + 1];
  }
  return undefined;
}

function emit(report, wantsJson) {
  if (wantsJson) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(formatToon(report));
  }
}

async function main(argv) {
  const args = new Set(argv);
  const cmd = argv.find((a) => !a.startsWith("-")) || "help";

  if (args.has("-v") || args.has("--version")) {
    console.log(VERSION);
    return 0;
  }
  if (args.has("-h") || args.has("--help") || cmd === "help") {
    printHelp();
    return 0;
  }

  const wantsJson = args.has("--json");
  const failOnAlert = args.has("--fail-on-alert");
  const targetPath = getFlagValue(argv, "--path") || process.cwd();

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
    report = tryRustSj(["orphans", targetPath]) || (await collectOrphans({ targetPath }));
  } else if (cmd === "trash") {
    report = tryRustSj(["trash"]) || (await collectTrash());
  } else if (cmd === "mcp-audit") {
    report = tryRustSj(["mcp-audit"]) || (await collectMcpAudit());
  } else if (cmd === "remediate") {
    const trash = await collectTrash();
    const plan = createRemediationPlan(trash.candidates || []);
    if (args.has("--execute")) {
      const phrase = getFlagValue(argv, "--confirm") || "";
      const planSha256 = getFlagValue(argv, "--plan-sha256") || "";
      const gate = verifyRemediationGate({ plan, planSha256, phrase });
      if (!gate.allowed) {
        const errObj = {
          schema: "spacejanitor.reap.v1",
          executed: false,
          error: gate.reason,
        };
        emit(errObj, wantsJson);
        return 1;
      }
      emit({ ...plan, dryRun: false, executed: true }, wantsJson);
      return 0;
    }
    report = plan;
  } else if (cmd === "advise") {
    const slmUrl = getFlagValue(argv, "--slm-url") || "";
    const enabled = Boolean(slmUrl);
    const summary = await collectSummary({ targetPath });
    report = await adviseWithLocalSlm({
      enabled,
      url: slmUrl || "http://127.0.0.1:11434/v1/chat/completions",
      allowLan: args.has("--allow-lan"),
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
