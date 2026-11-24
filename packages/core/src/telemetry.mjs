import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const GIB = 1024 ** 3;

export const SCHEMA_VERSIONS_EXT = Object.freeze({
  doctor: "spacejanitor.doctor.v1",
  storage: "spacejanitor.storage.v1",
  disk: "spacejanitor.disk.v1",
  memory: "spacejanitor.memory.v1",
  blockers: "spacejanitor.blockers.v1",
  orphans: "spacejanitor.orphans.v1",
  trash: "spacejanitor.trash.v1",
  mcpAudit: "spacejanitor.mcp_audit.v1",
  reap: "spacejanitor.reap.v1",
  plan: "spacejanitor.plan.v1",
  proposal: "spacejanitor.proposal.v1",
  summary: "spacejanitor.summary.v1",
});

function diskStatusFromFreeBytes(freeBytes) {
  const freeGiB = freeBytes / GIB;
  if (freeGiB < 20) return "CRITICAL";
  if (freeGiB < 50) return "ALERT";
  if (freeGiB < 100) return "ALERT";
  if (freeGiB < 150) return "CHECK";
  return "OK";
}

function dirSizeBounded(dirPath, maxDepth = 2, depth = 0) {
  let total = 0;
  let entries;
  try {
    entries = fs.readdirSync(dirPath, { withFileTypes: true });
  } catch {
    return 0;
  }
  for (const ent of entries) {
    if (ent.isSymbolicLink()) continue;
    const full = path.join(dirPath, ent.name);
    if (ent.isFile()) {
      try {
        total += fs.statSync(full).size;
      } catch {
        // ignore unreadable entries
      }
    } else if (ent.isDirectory() && depth < maxDepth) {
      total += dirSizeBounded(full, maxDepth, depth + 1);
    }
  }
  return total;
}

export function collectDoctor({ version = "0.1.0", schemas = SCHEMA_VERSIONS_EXT } = {}) {
  return {
    schema: schemas.doctor,
    version,
    source: "node-fallback",
    platform: os.platform(),
    arch: os.arch(),
    release: os.release(),
    node: process.version,
    cpus: os.cpus().length,
    totalMemGiB: Number((os.totalmem() / GIB).toFixed(2)),
    freeMemGiB: Number((os.freemem() / GIB).toFixed(2)),
    schemas,
    safetyMode: "dry-run-default",
    ready: true,
    timestamp: new Date().toISOString(),
  };
}

export async function collectDisk({ targetPath = os.homedir(), isProtectedFn } = {}) {
  const resolved = path.resolve(targetPath);
  let freeBytes = 0;
  let totalBytes = 0;
  try {
    const stat = fs.statfsSync(resolved);
    freeBytes = Number(stat.bavail) * Number(stat.bsize);
    totalBytes = Number(stat.blocks) * Number(stat.bsize);
  } catch {
    freeBytes = 0;
    totalBytes = 0;
  }

  const topConsumers = [];
  try {
    const entries = fs.readdirSync(resolved, { withFileTypes: true }).slice(0, 40);
    for (const ent of entries) {
      if (ent.isSymbolicLink() || !ent.isDirectory()) continue;
      const full = path.join(resolved, ent.name);
      const bytes = dirSizeBounded(full, 1);
      const prot = isProtectedFn ? isProtectedFn(full) : { protected: false, reason: "" };
      topConsumers.push({
        id: `dir-${ent.name}`,
        path: full,
        bytes,
        kind: "dir",
        protected: Boolean(prot.protected),
        protectedReason: prot.reason || "",
      });
    }
  } catch {
    // ignore unreadable root
  }
  topConsumers.sort((a, b) => b.bytes - a.bytes);

  return {
    schema: SCHEMA_VERSIONS_EXT.disk,
    source: "node-fallback",
    targetPath: resolved,
    status: diskStatusFromFreeBytes(freeBytes),
    totalBytes,
    freeBytes,
    freeGiB: Number((freeBytes / GIB).toFixed(2)),
    thresholdsGiB: { check: 150, alert: 100, floor: 50, critical: 20 },
    topConsumers: topConsumers.slice(0, 15),
    timestamp: new Date().toISOString(),
  };
}

export async function collectTrash({ homeDir = os.homedir() } = {}) {
  const candidates = [];
  const platform = os.platform();
  const trashPath =
    platform === "darwin"
      ? path.join(homeDir, ".Trash")
      : platform === "linux"
        ? path.join(homeDir, ".local", "share", "Trash", "files")
        : "";

  let totalBytes = 0;
  if (trashPath && fs.existsSync(trashPath)) {
    try {
      const entries = fs.readdirSync(trashPath, { withFileTypes: true }).slice(0, 50);
      for (const ent of entries) {
        if (ent.isSymbolicLink()) continue;
        const full = path.join(trashPath, ent.name);
        let bytes = 0;
        if (ent.isFile()) {
          try {
            bytes = fs.statSync(full).size;
          } catch {
            bytes = 0;
          }
        } else if (ent.isDirectory()) {
          bytes = dirSizeBounded(full, 2);
        }
        totalBytes += bytes;
        candidates.push({
          id: `trash-${ent.name}`,
          path: full,
          bytes,
          kind: ent.isDirectory() ? "dir" : "file",
        });
      }
    } catch {
      // ignore permission errors (e.g. macOS TCC on ~/.Trash)
    }
  }

  return {
    schema: SCHEMA_VERSIONS_EXT.trash,
    source: "node-fallback",
    trashPath,
    totalBytes,
    itemCount: candidates.length,
    candidates: candidates.slice(0, 20),
    timestamp: new Date().toISOString(),
  };
}

async function safeExec(cmd, args, cwd) {
  try {
    const { stdout } = await execFileAsync(cmd, args, { cwd, timeout: 3000, maxBuffer: 1024 * 1024 });
    return stdout.trim();
  } catch {
    return "";
  }
}

export async function collectOrphans({ targetPath = process.cwd(), maxAgeDays = 14 } = {}) {
  const resolved = path.resolve(targetPath);
  const candidates = [];

  const insideGit = await safeExec("git", ["rev-parse", "--is-inside-work-tree"], resolved);
  if (insideGit === "true") {
    const wtOut = await safeExec("git", ["worktree", "list", "--porcelain"], resolved);
    const lines = wtOut.split(/\r?\n/);
    for (const line of lines) {
      if (!line.startsWith("worktree ")) continue;
      const wtPath = line.slice("worktree ".length).trim();
      if (!wtPath || wtPath === resolved) continue;
      const dirty = await safeExec("git", ["status", "--porcelain"], wtPath);
      const remotes = await safeExec("git", ["remote"], wtPath);
      const unpushed = await safeExec("git", ["rev-list", "--branches", "--not", "--remotes", "--count"], wtPath);
      const isClean = dirty.length === 0;
      const hasRemote = remotes.length > 0;
      const hasUnpushed = Number(unpushed || "0") > 0;
      candidates.push({
        id: `wt-${path.basename(wtPath)}`,
        path: wtPath,
        kind: "git-worktree",
        clean: isClean,
        hasRemote,
        hasUnpushed,
        safeToPrune: isClean && hasRemote && !hasUnpushed,
        maxAgeDays,
      });
    }
  }

  return {
    schema: SCHEMA_VERSIONS_EXT.orphans,
    source: "node-fallback",
    targetPath: resolved,
    maxAgeDays,
    candidates,
    timestamp: new Date().toISOString(),
  };
}

export async function collectMemory({ top = 15, redactFn = (s) => s } = {}) {
  const totalBytes = os.totalmem();
  const freeBytes = os.freemem();
  const usedBytes = Math.max(0, totalBytes - freeBytes);
  let swapUsedBytes = 0;
  let swapTotalBytes = 0;

  if (os.platform() === "darwin") {
    const swapOut = await safeExec("sysctl", ["-n", "vm.swapusage"]);
    const totalMatch = swapOut.match(/total\s*=\s*([\d.]+)M/);
    const usedMatch = swapOut.match(/used\s*=\s*([\d.]+)M/);
    if (totalMatch) swapTotalBytes = Math.round(Number(totalMatch[1]) * 1024 * 1024);
    if (usedMatch) swapUsedBytes = Math.round(Number(usedMatch[1]) * 1024 * 1024);
  }

  const processes = [];
  if (os.platform() !== "win32") {
    const psOut = await safeExec("ps", ["-ax", "-o", "pid=,ppid=,rss=,comm="]);
    for (const line of psOut.split(/\r?\n/)) {
      const m = line.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/);
      if (!m) continue;
      const rssBytes = Number(m[3]) * 1024;
      processes.push({
        pid: Number(m[1]),
        ppid: Number(m[2]),
        rssBytes,
        trueFootprintBytes: rssBytes,
        command: redactFn(m[4].trim()),
        isOrphanPpid1: Number(m[2]) === 1,
      });
    }
    processes.sort((a, b) => b.trueFootprintBytes - a.trueFootprintBytes);
  }

  const freeRatio = totalBytes > 0 ? freeBytes / totalBytes : 1;
  const status = freeRatio < 0.08 ? "CRITICAL" : freeRatio < 0.15 ? "ALERT" : freeRatio < 0.25 ? "CHECK" : "OK";

  return {
    schema: SCHEMA_VERSIONS_EXT.memory,
    source: "node-fallback",
    status,
    totalBytes,
    freeBytes,
    usedBytes,
    swapTotalBytes,
    swapUsedBytes,
    processes: processes.slice(0, top),
    timestamp: new Date().toISOString(),
  };
}

export async function collectBlockers() {
  const counters = [];
  let worst = "OK";

  if (os.platform() === "darwin") {
    const numVnodes = Number(await safeExec("sysctl", ["-n", "kern.num_vnodes"])) || 0;
    const maxVnodes = Number(await safeExec("sysctl", ["-n", "kern.maxvnodes"])) || 0;
    if (maxVnodes > 0) {
      const pct = Math.round((numVnodes / maxVnodes) * 100);
      const sev = pct >= 90 ? "CRITICAL" : pct >= 75 ? "WARN" : "OK";
      if (sev === "CRITICAL") worst = "CRITICAL";
      else if (sev === "WARN" && worst === "OK") worst = "WARN";
      counters.push({ name: "kern.vnodes", current: numVnodes, max: maxVnodes, percent: pct, status: sev });
    }
  } else if (os.platform() === "linux") {
    try {
      const fileNr = fs.readFileSync("/proc/sys/fs/file-nr", "utf8").trim().split(/\s+/);
      const openFiles = Number(fileNr[0]) || 0;
      const maxFiles = Number(fileNr[2]) || 0;
      if (maxFiles > 0) {
        const pct = Math.round((openFiles / maxFiles) * 100);
        const sev = pct >= 90 ? "CRITICAL" : pct >= 75 ? "WARN" : "OK";
        if (sev === "CRITICAL") worst = "CRITICAL";
        else if (sev === "WARN" && worst === "OK") worst = "WARN";
        counters.push({ name: "fs.file-nr", current: openFiles, max: maxFiles, percent: pct, status: sev });
      }
    } catch {
      // ignore if unavailable
    }
  }

  return {
    schema: SCHEMA_VERSIONS_EXT.blockers,
    source: "node-fallback",
    status: worst,
    counters,
    timestamp: new Date().toISOString(),
  };
}

export async function collectMcpAudit({ configDirs, redactFn = (s) => s } = {}) {
  const dirs = Array.isArray(configDirs) ? configDirs : [];
  const servers = [];
  const seenNames = new Map();

  for (const dir of dirs) {
    if (!dir || !fs.existsSync(dir)) continue;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      if (!ent.isFile() || !ent.name.endsWith(".json")) continue;
      try {
        const raw = JSON.parse(fs.readFileSync(path.join(dir, ent.name), "utf8"));
        const mcpServers = raw?.mcpServers || {};
        for (const [name, cfg] of Object.entries(mcpServers)) {
          const count = (seenNames.get(name) || 0) + 1;
          seenNames.set(name, count);
          const argsStr = Array.isArray(cfg?.args) ? cfg.args.join(" ") : "";
          const redactedArgs = redactFn(argsStr);
          const envKeys = cfg?.env && typeof cfg.env === "object" ? Object.keys(cfg.env) : [];
          const hasSecretRisk =
            redactedArgs.includes("<REDACTED>") ||
            envKeys.some((k) => /KEY|TOKEN|SECRET|PASSWORD/i.test(k));
          servers.push({
            name,
            command: redactFn(String(cfg?.command || "")),
            argsRedacted: redactedArgs,
            duplicateCount: count,
            hasSecretRisk,
            sourceFile: ent.name,
          });
        }
      } catch {
        // ignore invalid json
      }
    }
  }

  return {
    schema: SCHEMA_VERSIONS_EXT.mcpAudit,
    source: "node-fallback",
    totalServers: servers.length,
    duplicateCount: servers.filter((s) => s.duplicateCount > 1).length,
    secretRiskCount: servers.filter((s) => s.hasSecretRisk).length,
    servers,
    timestamp: new Date().toISOString(),
  };
}

const STATUS_RANK = { OK: 0, CHECK: 1, WARN: 2, ALERT: 2, CRITICAL: 3 };

export async function collectSummary(options = {}) {
  const [disk, memory, blockers, orphans, trash, mcpAudit] = await Promise.all([
    collectDisk(options),
    collectMemory(options),
    collectBlockers(options),
    collectOrphans(options),
    collectTrash(options),
    collectMcpAudit(options),
  ]);

  const statuses = [disk.status, memory.status, blockers.status];
  let worst = "OK";
  for (const st of statuses) {
    if ((STATUS_RANK[st] ?? 0) > (STATUS_RANK[worst] ?? 0)) worst = st;
  }

  return {
    schema: SCHEMA_VERSIONS_EXT.summary,
    source: "node-fallback",
    status: worst,
    disk,
    memory,
    blockers,
    orphans,
    trash,
    mcpAudit,
    timestamp: new Date().toISOString(),
  };
}
