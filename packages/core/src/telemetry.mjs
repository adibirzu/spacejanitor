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

async function safeExecResult(cmd, args, cwd) {
  try {
    const { stdout } = await execFileAsync(cmd, args, { cwd, timeout: 3000, maxBuffer: 1024 * 1024 });
    return { ok: true, stdout: stdout.trim() };
  } catch {
    return { ok: false, stdout: "" };
  }
}

async function safeExec(cmd, args, cwd) {
  const res = await safeExecResult(cmd, args, cwd);
  return res.stdout;
}

export async function collectOrphans({ targetPath = process.cwd(), maxAgeDays = 14 } = {}) {
  const resolved = path.resolve(targetPath);
  const candidates = [];

  const insideGit = await safeExecResult("git", ["rev-parse", "--is-inside-work-tree"], resolved);
  if (insideGit.ok && insideGit.stdout === "true") {
    const wtOut = await safeExecResult("git", ["worktree", "list", "--porcelain"], resolved);
    if (wtOut.ok) {
      const lines = wtOut.stdout.split(/\r?\n/);
      for (const line of lines) {
        if (!line.startsWith("worktree ")) continue;
        const wtPath = line.slice("worktree ".length).trim();
        if (!wtPath || wtPath === resolved) continue;

        const dirtyRes = await safeExecResult("git", ["status", "--porcelain"], wtPath);
        const remotesRes = await safeExecResult("git", ["remote"], wtPath);
        const branchesUnpushedRes = await safeExecResult(
          "git",
          ["rev-list", "--branches", "--not", "--remotes", "--count"],
          wtPath
        );
        const headUnpushedRes = await safeExecResult(
          "git",
          ["rev-list", "HEAD", "--not", "--remotes", "--count"],
          wtPath
        );

        const allOk =
          dirtyRes.ok && remotesRes.ok && branchesUnpushedRes.ok && headUnpushedRes.ok;
        if (!allOk) {
          candidates.push({
            id: `wt-${path.basename(wtPath)}`,
            path: wtPath,
            kind: "git-worktree",
            clean: false,
            hasRemote: remotesRes.ok ? remotesRes.stdout.length > 0 : false,
            hasUnpushed: true,
            proofStatus: "unverified",
            safeToPrune: false,
            maxAgeDays,
          });
          continue;
        }

        const isClean = dirtyRes.stdout.length === 0;
        const hasRemote = remotesRes.stdout.length > 0;
        const branchCount = Number(branchesUnpushedRes.stdout);
        const headCount = Number(headUnpushedRes.stdout);
        const countsValid = Number.isFinite(branchCount) && Number.isFinite(headCount);
        const hasUnpushed = !countsValid || branchCount > 0 || headCount > 0;
        const proofStatus = countsValid ? "verified" : "unverified";

        candidates.push({
          id: `wt-${path.basename(wtPath)}`,
          path: wtPath,
          kind: "git-worktree",
          clean: isClean,
          hasRemote,
          hasUnpushed,
          proofStatus,
          safeToPrune: isClean && hasRemote && !hasUnpushed && proofStatus === "verified",
          maxAgeDays,
        });
      }
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

export function parseMacOsVmStat(vmStatOutput, swapOutput = "", totalBytes = os.totalmem()) {
  const pageMatch = vmStatOutput.match(/page size of (\d+) bytes/i);
  const pageSize = pageMatch ? Number(pageMatch[1]) : 16384;
  const readPages = (label) => {
    const m = vmStatOutput.match(new RegExp(`${label}:\\s+(\\d+)\\.`, "i"));
    return m ? Number(m[1]) : 0;
  };
  const freePages = readPages("Pages free");
  const inactivePages = readPages("Pages inactive");
  const speculativePages = readPages("Pages speculative");
  const purgeablePages = readPages("Pages purgeable");
  const availableBytes = (freePages + inactivePages + speculativePages + purgeablePages) * pageSize;

  let swapTotalBytes = 0;
  let swapUsedBytes = 0;
  const totalMatch = swapOutput.match(/total\s*=\s*([\d.]+)M/);
  const usedMatch = swapOutput.match(/used\s*=\s*([\d.]+)M/);
  if (totalMatch) swapTotalBytes = Math.round(Number(totalMatch[1]) * 1024 * 1024);
  if (usedMatch) swapUsedBytes = Math.round(Number(usedMatch[1]) * 1024 * 1024);

  const boundedAvail = Math.min(totalBytes, Math.max(0, availableBytes));
  return { availableBytes: boundedAvail, swapTotalBytes, swapUsedBytes };
}

export async function collectMemory({ top = 15, redactFn = (s) => s } = {}) {
  const totalBytes = os.totalmem();
  let freeBytes = os.freemem();
  let swapUsedBytes = 0;
  let swapTotalBytes = 0;

  if (os.platform() === "darwin") {
    const [vmRes, swapRes] = await Promise.all([
      safeExecResult("vm_stat", []),
      safeExecResult("sysctl", ["-n", "vm.swapusage"]),
    ]);
    if (vmRes.ok && vmRes.stdout) {
      const parsed = parseMacOsVmStat(vmRes.stdout, swapRes.stdout, totalBytes);
      if (parsed.availableBytes > 0) {
        freeBytes = parsed.availableBytes;
      }
      swapTotalBytes = parsed.swapTotalBytes;
      swapUsedBytes = parsed.swapUsedBytes;
    } else if (swapRes.ok) {
      const totalMatch = swapRes.stdout.match(/total\s*=\s*([\d.]+)M/);
      const usedMatch = swapRes.stdout.match(/used\s*=\s*([\d.]+)M/);
      if (totalMatch) swapTotalBytes = Math.round(Number(totalMatch[1]) * 1024 * 1024);
      if (usedMatch) swapUsedBytes = Math.round(Number(usedMatch[1]) * 1024 * 1024);
    }
  }
  const usedBytes = Math.max(0, totalBytes - freeBytes);

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

function defaultMcpConfigDirs(homeDir = os.homedir()) {
  const candidates = [
    path.join(homeDir, ".cursor"),
    path.join(homeDir, ".claude"),
    path.join(homeDir, ".codex"),
    path.join(homeDir, ".codeium", "windsurf"),
    path.join(homeDir, ".config", "claude"),
    path.join(homeDir, ".config", "Code", "User"),
    path.join(homeDir, "Library", "Application Support", "Claude"),
    path.join(homeDir, "Library", "Application Support", "Code", "User"),
  ];
  if (process.env.APPDATA) {
    candidates.push(path.join(process.env.APPDATA, "Claude"));
    candidates.push(path.join(process.env.APPDATA, "Code", "User"));
  }
  return [...new Set(candidates)];
}

function parseTomlMcpServers(tomlText) {
  const servers = {};
  let current = null;
  for (const rawLine of tomlText.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const secMatch = line.match(/^\[(?:mcp_servers|mcpServers)\.([^\]]+)\]$/);
    if (secMatch) {
      const name = secMatch[1].replace(/^["']|["']$/g, "");
      current = servers[name] || { args: [], env: {} };
      servers[name] = current;
      continue;
    }
    if (line.startsWith("[")) {
      current = null;
      continue;
    }
    if (!current) continue;
    const kv = line.match(/^([A-Za-z0-9_.-]+)\s*=\s*(.+)$/);
    if (!kv) continue;
    const [, key, rawVal] = kv;
    if (key === "command" || key === "url") {
      current[key] = rawVal.replace(/^["']|["']$/g, "");
    } else if (key === "args" && rawVal.startsWith("[")) {
      try {
        current.args = JSON.parse(rawVal.replace(/'/g, '"'));
      } catch {
        current.args = [rawVal];
      }
    }
  }
  return servers;
}

export async function collectMcpAudit({ configDirs, homeDir = os.homedir(), redactFn = (s) => s } = {}) {
  const dirs = Array.isArray(configDirs) ? configDirs : defaultMcpConfigDirs(homeDir);
  const servers = [];
  const seenNames = new Map();

  const recordServer = (name, cfg, sourceFile) => {
    const count = (seenNames.get(name) || 0) + 1;
    seenNames.set(name, count);
    const argsList = Array.isArray(cfg?.args) ? cfg.args.map(String) : [];
    const headerList =
      cfg?.headers && typeof cfg.headers === "object"
        ? Object.entries(cfg.headers).map(([k, v]) => `${k}: ${v}`)
        : [];
    const combinedRaw = [cfg?.url ? String(cfg.url) : "", ...argsList, ...headerList]
      .filter(Boolean)
      .join(" ");
    const redactedArgs = redactFn(combinedRaw);
    const rawCommand = String(cfg?.command || "");
    const redactedCommand = redactFn(rawCommand);
    const envEntries = cfg?.env && typeof cfg.env === "object" ? Object.entries(cfg.env) : [];
    const envHasSecret = envEntries.some(
      ([k, v]) =>
        /KEY|TOKEN|SECRET|PASSWORD|AUTH/i.test(k) || redactFn(String(v)) !== String(v)
    );
    const hasSecretRisk =
      redactedArgs !== combinedRaw ||
      redactedCommand !== rawCommand ||
      redactedArgs.includes("<REDACTED>") ||
      redactedCommand.includes("<REDACTED>") ||
      envHasSecret;

    servers.push({
      name,
      command: redactedCommand,
      argsRedacted: redactedArgs,
      duplicateCount: count,
      hasSecretRisk,
      sourceFile,
    });
  };

  for (const dir of dirs) {
    if (!dir || !fs.existsSync(dir)) continue;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      if (!ent.isFile()) continue;
      const fullPath = path.join(dir, ent.name);
      if (ent.name.endsWith(".json")) {
        try {
          const raw = JSON.parse(fs.readFileSync(fullPath, "utf8"));
          const mcpServers = raw?.mcpServers || raw?.servers || {};
          for (const [name, cfg] of Object.entries(mcpServers)) {
            recordServer(name, cfg, ent.name);
          }
        } catch {
          // ignore invalid json
        }
      } else if (ent.name.endsWith(".toml")) {
        try {
          const raw = fs.readFileSync(fullPath, "utf8");
          const mcpServers = parseTomlMcpServers(raw);
          for (const [name, cfg] of Object.entries(mcpServers)) {
            recordServer(name, cfg, ent.name);
          }
        } catch {
          // ignore invalid toml
        }
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

export async function collectCleanableCaches({ homeDir = os.homedir(), isProtectedFn } = {}) {
  const knownCaches = [
    path.join(homeDir, ".cache", "npm"),
    path.join(homeDir, ".npm", "_cacache"),
    path.join(homeDir, ".cache", "pip"),
    path.join(homeDir, ".cache", "yarn"),
    path.join(homeDir, ".cache", "pnpm"),
    path.join(homeDir, "Library", "Caches", "Homebrew"),
    path.join(homeDir, "Library", "Caches", "pip"),
    path.join(homeDir, "Library", "Caches", "pnpm"),
    path.join(homeDir, ".cargo", "registry", "cache"),
    path.join(homeDir, ".gradle", "caches"),
  ];
  const candidates = [];
  for (const cachePath of knownCaches) {
    if (!fs.existsSync(cachePath)) continue;
    const prot = isProtectedFn ? isProtectedFn(cachePath, { homeDir }) : { protected: false };
    if (prot.protected) continue;
    const bytes = dirSizeBounded(cachePath, 2);
    candidates.push({
      id: `cache-${path.basename(path.dirname(cachePath))}-${path.basename(cachePath)}`,
      path: cachePath,
      bytes,
      kind: "dir",
      category: "cache",
      protected: false,
    });
  }
  return candidates;
}

export function normalizeReportEnvelope(raw) {
  if (!raw || typeof raw !== "object") return raw;
  const schema = raw.schema;
  const normStatus = (st) => {
    const up = String(st || "OK").toUpperCase();
    if (up === "FLOOR" || up === "STOP") return "CRITICAL";
    return up;
  };

  if (schema === SCHEMA_VERSIONS_EXT.doctor) {
    return {
      ...raw,
      platform: raw.platform ?? raw.os ?? os.platform(),
      node: raw.node ?? (raw.engine === "rust" ? `rust/${raw.version || "0.1.0"}` : process.version),
      freeMemGiB: raw.freeMemGiB ?? Number((os.freemem() / GIB).toFixed(2)),
      totalMemGiB: raw.totalMemGiB ?? Number((os.totalmem() / GIB).toFixed(2)),
      safetyMode: raw.safetyMode ?? "dry-run-default",
    };
  }

  if (schema === SCHEMA_VERSIONS_EXT.storage || schema === SCHEMA_VERSIONS_EXT.disk) {
    const targetPath = raw.targetPath ?? raw.root ?? process.cwd();
    let freeBytes = raw.freeBytes;
    let totalBytes = raw.totalBytes;
    if (typeof freeBytes !== "number" || typeof totalBytes !== "number") {
      try {
        const st = fs.statfsSync(targetPath);
        freeBytes = Number(st.bavail) * Number(st.bsize);
        totalBytes = Number(st.blocks) * Number(st.bsize);
      } catch {
        freeBytes = 0;
        totalBytes = raw.total_bytes ?? 0;
      }
    }
    const entries = raw.topConsumers ?? raw.entries ?? [];
    const topConsumers = entries.map((e, idx) => ({
      id: e.id ?? `entry-${idx}`,
      path: e.path,
      bytes: Number(e.bytes || 0),
      kind: e.kind || "dir",
      protected: Boolean(e.protected),
      protectedReason: e.protectedReason || "",
    }));
    return {
      ...raw,
      status: normStatus(raw.status),
      targetPath,
      totalBytes,
      freeBytes,
      freeGiB: raw.freeGiB ?? Number((freeBytes / GIB).toFixed(2)),
      topConsumers,
    };
  }

  if (schema === SCHEMA_VERSIONS_EXT.trash) {
    const rawItems = raw.candidates ?? raw.items ?? [];
    const candidates = rawItems.map((it, idx) => ({
      id: it.id ?? `trash-${idx}`,
      path: it.path,
      bytes: Number(it.bytes || 0),
      kind: it.kind || "file",
      protected: Boolean(it.protected),
    }));
    return {
      ...raw,
      trashPath: raw.trashPath ?? raw.trash_path ?? "",
      itemCount: raw.itemCount ?? raw.item_count ?? candidates.length,
      totalBytes: raw.totalBytes ?? raw.total_bytes ?? 0,
      candidates,
    };
  }

  if (schema === SCHEMA_VERSIONS_EXT.orphans) {
    if (Array.isArray(raw.candidates)) return raw;
    const safe = (raw.safe_to_prune || []).map((c, idx) => ({
      id: `wt-safe-${idx}`,
      path: c.path,
      kind: c.is_worktree ? "git-worktree" : "git-repo",
      clean: true,
      hasRemote: true,
      hasUnpushed: false,
      proofStatus: "verified",
      safeToPrune: true,
      bytes: Number(c.bytes || 0),
    }));
    const blocked = (raw.blocked || []).map((c, idx) => ({
      id: `wt-blocked-${idx}`,
      path: c.path,
      kind: "git-worktree",
      clean: false,
      hasRemote: false,
      hasUnpushed: true,
      proofStatus: "unverified",
      safeToPrune: false,
      reasons: c.reasons || [],
    }));
    return {
      ...raw,
      targetPath: raw.targetPath ?? raw.root ?? process.cwd(),
      candidates: [...safe, ...blocked],
    };
  }

  return raw;
}

const STATUS_RANK = { OK: 0, CHECK: 1, WARN: 2, ALERT: 2, CRITICAL: 3 };

export async function collectSummary(options = {}) {
  const [disk, memory, blockers, orphans, trash, mcpAudit, cleanableCaches] = await Promise.all([
    collectDisk(options),
    collectMemory(options),
    collectBlockers(options),
    collectOrphans(options),
    collectTrash(options),
    collectMcpAudit(options),
    collectCleanableCaches(options),
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
    cleanableCaches,
    timestamp: new Date().toISOString(),
  };
}
