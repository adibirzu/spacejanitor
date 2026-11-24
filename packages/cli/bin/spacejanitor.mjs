#!/usr/bin/env node
/**
 * SpaceJanitor AXI CLI (ADR-003)
 * Token-efficient TOON output by default, versioned JSON contracts via --json.
 */

import os from "node:os";
import process from "node:process";
import { SCHEMA_VERSIONS } from "../../core/src/index.mjs";

const VERSION = "0.1.0";

function printHelp() {
  const lines = [
    `spacejanitor v${VERSION} — Cross-platform storage, orphan work, trash & true memory janitor`,
    "",
    "usage: spacejanitor [command] [--json]",
    "",
    "commands:",
    "  doctor      Check local OS/arch platform readiness and contract versions",
    "  disk        Audit filesystem capacity and tiered cleanup candidates (PRD-001)",
    "  memory      Audit true RAM footprint (RSS + compressed/swapped) (PRD-002)",
    "  blockers    Detect kernel vnode, inotify, handle, and VFS lock blockers (PRD-002)",
    "  orphans     Inspect clean/pushed vs dirty git worktrees and orphan PPID=1 work",
    "  trash       Inspect OS Trash / Recycle Bin reclamation candidates",
    "  mcp-audit   Audit MCP server fan-out and duplicate stdio entries",
    "  remediate   Preview dry-run plan (requires --execute --confirm-* to act)",
    "",
    "flags:",
    "  --json        Emit machine-readable versioned JSON contract",
    "  -h, --help    Show help",
    "  -v, --version Show version",
  ];
  console.log(lines.join("\n"));
}

function buildDoctorReport() {
  return {
    schema: "spacejanitor.doctor.v1",
    version: VERSION,
    platform: os.platform(),
    arch: os.arch(),
    release: os.release(),
    node: process.version,
    cpus: os.cpus().length,
    totalMemGiB: Number((os.totalmem() / 1024 ** 3).toFixed(2)),
    freeMemGiB: Number((os.freemem() / 1024 ** 3).toFixed(2)),
    schemas: SCHEMA_VERSIONS,
    safetyMode: "dry-run-default",
    ready: true,
  };
}

function printDoctorToon(report) {
  console.log(`spacejanitor doctor v${report.version}`);
  console.log(`host: ${report.platform}/${report.arch} (release ${report.release}, node ${report.node})`);
  console.log(`cpu_cores: ${report.cpus} | total_mem_gib: ${report.totalMemGiB} | safety: ${report.safetyMode}`);
  console.log(`schemas: ${Object.values(report.schemas).join(", ")}`);
  console.log("status: READY");
}

function main(argv) {
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
  if (cmd === "doctor") {
    const report = buildDoctorReport();
    if (wantsJson) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      printDoctorToon(report);
    }
    return 0;
  }

  const implementedInMilestone = {
    disk: "PRD-001",
    memory: "PRD-002",
    blockers: "PRD-002",
    orphans: "PRD-001",
    trash: "PRD-001",
    "mcp-audit": "PRD-002",
    remediate: "PRD-001 / PRD-002",
  };

  if (cmd in implementedInMilestone) {
    const msg = {
      status: "scaffold",
      command: cmd,
      prd: implementedInMilestone[cmd],
      message: `Collector '${cmd}' is specified in ${implementedInMilestone[cmd]} and scheduled for Milestone 1 implementation.`,
    };
    if (wantsJson) {
      console.log(JSON.stringify(msg, null, 2));
    } else {
      console.log(msg.message);
    }
    return 0;
  }

  console.error(`Unknown command: ${cmd}`);
  printHelp();
  return 1;
}

process.exitCode = main(process.argv.slice(2));
