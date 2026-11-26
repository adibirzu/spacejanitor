import { isProtectedPath, protectPaths } from "./protect.mjs";
import { SjGateError, runSj } from "./sjGate.mjs";
import { redactSecrets, redactArgv } from "./redact.mjs";
import { execFile } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const GIB = 1024 ** 3;

export const ORPHAN_SCAN_WARNING =
  "warning: orphan scanning runs git inside repositories found on disk and is unreviewed, experimental behavior (see Known limitations). Only use it on repositories you trust.";
export const ORPHAN_SCAN_DISABLED_MESSAGE =
  "Orphan scanning runs git inside repositories found on disk and is disabled by default (unreviewed, experimental). Opt in explicitly (CLI: --include-orphans; desktop: Settings).";

export const SCHEMA_VERSIONS_EXT = Object.freeze({
  doctor: "spacejanitor.doctor.v1",
  storage: "spacejanitor.storage.v1",
  disk: "spacejanitor.disk.v1",
  memory: "spacejanitor.memory.v1",
  blockers: "spacejanitor.blockers.v1",
  orphans: "spacejanitor.orphans.v1",
  trash: "spacejanitor.trash.v1",
  mcpAudit: "spacejanitor.mcp_audit.v1",
  linuxAudit: "spacejanitor.linux_audit.v1",
  reap: "spacejanitor.reap.v1",
  plan: "spacejanitor.plan.v1",
  proposal: "spacejanitor.proposal.v1",
  summary: "spacejanitor.summary.v1",
});

const STATUS_LEVELS = ["OK", "CHECK", "ALERT", "CRITICAL"];

function diskStatusFromFreeBytes(freeBytes, totalBytes = 0) {
  const freeGiB = freeBytes / GIB;
  let byGib = 0;
  if (freeGiB < 20) byGib = 3;
  else if (freeGiB < 100) byGib = 2;
  else if (freeGiB < 150) byGib = 1;

  let byPct = 0;
  if (totalBytes > 0) {
    const usedPct = ((totalBytes - freeBytes) / totalBytes) * 100;
    if (usedPct >= 95) byPct = 3;
    else if (usedPct >= 88) byPct = 2;
    else if (usedPct >= 80) byPct = 1;
  }

  const rank = totalBytes > 0 && totalBytes < 200 * GIB ? byPct : Math.max(byGib, byPct);
  return STATUS_LEVELS[rank];
}

function unescapeMountField(raw) {
  return String(raw)
    .replace(/\\040/g, " ")
    .replace(/\\011/g, "\t")
    .replace(/\\012/g, "\n")
    .replace(/\\134/g, "\\");
}

export function classifyLinuxMount(_device, mountpoint, fstype) {
  const ft = String(fstype || "").toLowerCase();
  const mp = String(mountpoint || "");
  if (
    mp.startsWith("/tmp/.mount_") ||
    ft.startsWith("fuse.appimage") ||
    (ft.startsWith("fuse.") && mp.includes(".mount_")) ||
    (ft === "squashfs" && mp.startsWith("/tmp/.mount_"))
  ) {
    return "appimage";
  }
  if (ft === "overlay" || ft === "overlayfs") return "overlay";
  if (ft === "tmpfs") return "tmpfs";
  if (
    ft === "devtmpfs" ||
    [
      "proc",
      "sysfs",
      "devpts",
      "cgroup",
      "cgroup2",
      "pstore",
      "bpf",
      "tracefs",
      "debugfs",
      "securityfs",
      "hugetlbfs",
      "mqueue",
      "fusectl",
      "configfs",
      "efivarfs",
      "binfmt_misc",
      "autofs",
      "rpc_pipefs",
      "nsfs",
      "ramfs",
      "squashfs",
    ].includes(ft)
  ) {
    return "virtual";
  }
  return "physical";
}

export function parseProcMounts(raw) {
  const mounts = [];
  for (const rawLine of String(raw || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 3) continue;
    const device = unescapeMountField(parts[0]);
    const mountpoint = unescapeMountField(parts[1]);
    const fstype = unescapeMountField(parts[2]);
    const kind = classifyLinuxMount(device, mountpoint, fstype);
    mounts.push({
      device,
      mountpoint,
      fstype,
      kind,
      alertEligible: kind === "physical",
    });
  }
  return mounts;
}

export function parseHumanSize(raw) {
  const first = String(raw || "").split("(")[0].trim();
  if (!first) return 0;
  const m = first.match(/^([\d.]+)\s*([a-zA-Z]*)$/);
  if (!m) return 0;
  const val = Number(m[1]);
  if (!Number.isFinite(val) || val <= 0) return 0;
  const unit = m[2].toLowerCase();
  const mult =
    unit === "" || unit === "b"
      ? 1
      : unit === "k" || unit === "kb"
        ? 1e3
        : unit === "ki" || unit === "kib"
          ? 1024
          : unit === "m" || unit === "mb"
            ? 1e6
            : unit === "mi" || unit === "mib"
              ? 1024 ** 2
              : unit === "g" || unit === "gb"
                ? 1e9
                : unit === "gi" || unit === "gib"
                  ? 1024 ** 3
                  : unit === "t" || unit === "tb"
                    ? 1e12
                    : unit === "ti" || unit === "tib"
                      ? 1024 ** 4
                      : 1;
  return Math.round(val * mult);
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

/**
 * Judge many paths with ONE sj spawn when the stock gate is in use (an injected predicate, used by tests,
 * is simply mapped). Fails closed like the single-path call.
 */
function judgeMany(paths, isProtectedFn, options) {
  if (isProtectedFn === isProtectedPath) return protectPaths(paths, options);
  return paths.map((p) => isProtectedFn(p, options));
}

export async function collectDisk({
  targetPath = os.homedir(),
  isProtectedFn = isProtectedPath,
  statfsOverride = null,
  mountsRaw = null,
  platformOverride = null,
} = {}) {
  const resolved = path.resolve(targetPath);
  const platform = platformOverride || os.platform();
  let freeBytes = 0;
  let totalBytes = 0;
  try {
    const stat = statfsOverride || fs.statfsSync(resolved);
    freeBytes = Number(stat.bavail) * Number(stat.bsize);
    totalBytes = Number(stat.blocks) * Number(stat.bsize);
  } catch {
    freeBytes = 0;
    totalBytes = 0;
  }

  let mounts = [];
  let appimageMounts = [];
  const skipMounts = new Set();
  if (platform === "linux") {
    try {
      const raw = mountsRaw !== null ? mountsRaw : fs.readFileSync("/proc/mounts", "utf8");
      mounts = parseProcMounts(raw);
      appimageMounts = mounts.filter((m) => m.kind === "appimage");
      for (const m of mounts) {
        if (m.mountpoint !== resolved && m.kind !== "physical") {
          skipMounts.add(m.mountpoint);
        }
      }
    } catch {
      // ignore unreadable /proc/mounts
    }
  }

  const topConsumers = [];
  try {
    const entries = fs.readdirSync(resolved, { withFileTypes: true }).slice(0, 40);
    const dirs = entries.filter(
      (ent) => !ent.isSymbolicLink() && ent.isDirectory() && !skipMounts.has(path.join(resolved, ent.name))
    );
    const verdicts = judgeMany(
      dirs.map((ent) => path.join(resolved, ent.name)),
      isProtectedFn,
      {}
    );
    for (const [i, ent] of dirs.entries()) {
      const full = path.join(resolved, ent.name);
      const bytes = dirSizeBounded(full, 1);
      const prot = verdicts[i] || { protected: true, reason: "sj_unparseable" };
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

  const usedPercent = totalBytes > 0 ? Number((((totalBytes - freeBytes) / totalBytes) * 100).toFixed(1)) : 0;

  return {
    schema: SCHEMA_VERSIONS_EXT.disk,
    source: "node-fallback",
    targetPath: resolved,
    status: diskStatusFromFreeBytes(freeBytes, totalBytes),
    totalBytes,
    freeBytes,
    freeGiB: Number((freeBytes / GIB).toFixed(2)),
    usedPercent,
    thresholdsGiB: { check: 150, alert: 100, floor: 50, critical: 20 },
    topConsumers: topConsumers.slice(0, 15),
    ...(platform === "linux" ? { mounts, appimageMounts } : {}),
    timestamp: new Date().toISOString(),
  };
}

export async function collectTrash({ homeDir = os.homedir() } = {}) {
  const candidates = [];
  const platform = os.platform();
  // Must match the Rust gate's default_trash_paths exactly: the desktop selects sj plan items by path.
  const xdgDataHome = process.env.XDG_DATA_HOME;
  const trashPath =
    platform === "darwin"
      ? path.join(homeDir, ".Trash")
      : platform === "linux"
        ? xdgDataHome
          ? path.join(xdgDataHome, "Trash", "files")
          : path.join(homeDir, ".local", "share", "Trash", "files")
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

async function safeExecResult(cmd, args, cwd, { maxBuffer = 1024 * 1024, timeout = 3000 } = {}) {
  try {
    const { stdout } = await execFileAsync(cmd, args, { cwd, timeout, maxBuffer });
    return { ok: true, stdout: stdout.trim() };
  } catch {
    return { ok: false, stdout: "" };
  }
}

async function safeExec(cmd, args, cwd) {
  const res = await safeExecResult(cmd, args, cwd);
  return res.stdout;
}

/**
 * Orphan/worktree discovery and every safety proof come from the Rust gate (`sj orphans`). There is no
 * JavaScript proof. OFF by default: without an explicit opt-in nothing is scanned, git is never spawned
 * and the report says "not scanned" (not an empty "no orphans"). With the opt-in, a missing, slow or
 * unparseable sj yields `error` and no candidates, so nothing can be offered as safe to prune.
 */
export async function collectOrphans({ targetPath = process.cwd(), maxAgeDays = 14, includeOrphans = false } = {}) {
  const resolved = path.resolve(targetPath);
  const base = {
    schema: SCHEMA_VERSIONS_EXT.orphans,
    targetPath: resolved,
    maxAgeDays,
    timestamp: new Date().toISOString(),
  };
  if (!includeOrphans) {
    return {
      ...base,
      source: "not-scanned",
      status: "not_scanned",
      scanned: false,
      notScannedReason: "orphan_scan_disabled_by_default",
      message: ORPHAN_SCAN_DISABLED_MESSAGE,
      candidates: [],
    };
  }
  try {
    const envMs = Number(process.env.SPACEJANITOR_SJ_TIMEOUT_MS);
    const timeoutMs = Number.isFinite(envMs) && envMs > 0 ? envMs : 60000;
    const raw = await runSj(["orphans", "--include-orphans", "--json", resolved], { timeoutMs });
    if (raw.schema !== SCHEMA_VERSIONS_EXT.orphans || !Array.isArray(raw.safe_to_prune) || !Array.isArray(raw.blocked)) {
      throw new SjGateError("sj_unparseable");
    }
    const normalized = normalizeReportEnvelope({ ...raw, source: "sj-core" });
    return { ...base, ...normalized, scanned: true, targetPath: resolved, maxAgeDays };
  } catch (err) {
    return { ...base, source: "sj-unavailable", scanned: false, error: err && err.reason ? err.reason : "sj_unavailable", candidates: [] };
  }
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

export function parseLinuxMeminfo(raw) {
  let totalBytes = 0;
  let available = null;
  let freeBytes = 0;
  let buffers = 0;
  let cached = 0;
  let swapTotalBytes = 0;
  let swapFree = 0;
  for (const line of String(raw || "").split(/\r?\n/)) {
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim();
    const kb = Number((line.slice(idx + 1).trim().split(/\s+/)[0] || "0")) || 0;
    const bytes = kb * 1024;
    if (key === "MemTotal") totalBytes = bytes;
    else if (key === "MemAvailable") available = bytes;
    else if (key === "MemFree") freeBytes = bytes;
    else if (key === "Buffers") buffers = bytes;
    else if (key === "Cached") cached = bytes;
    else if (key === "SwapTotal") swapTotalBytes = bytes;
    else if (key === "SwapFree") swapFree = bytes;
  }
  const availableBytes = Math.min(totalBytes || Infinity, available !== null ? available : freeBytes + buffers + cached);
  return {
    totalBytes,
    availableBytes: Number.isFinite(availableBytes) ? availableBytes : 0,
    freeBytes,
    swapTotalBytes,
    swapUsedBytes: Math.max(0, swapTotalBytes - swapFree),
  };
}

export function parseProcStatusVmSwap(raw) {
  for (const line of String(raw || "").split(/\r?\n/)) {
    if (line.startsWith("VmSwap:")) {
      const kb = Number((line.slice(7).trim().split(/\s+/)[0] || "0")) || 0;
      return kb * 1024;
    }
  }
  return 0;
}

export async function collectMemory({ top = 15, redactFn = redactSecrets, platformOverride = null } = {}) {
  const platform = platformOverride || os.platform();
  let totalBytes = os.totalmem();
  let freeBytes = os.freemem();
  let swapUsedBytes = 0;
  let swapTotalBytes = 0;

  if (platform === "darwin") {
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
  } else if (platform === "linux") {
    try {
      const memRaw = fs.readFileSync("/proc/meminfo", "utf8");
      const parsed = parseLinuxMeminfo(memRaw);
      if (parsed.totalBytes > 0) totalBytes = parsed.totalBytes;
      if (parsed.availableBytes > 0) freeBytes = parsed.availableBytes;
      swapTotalBytes = parsed.swapTotalBytes;
      swapUsedBytes = parsed.swapUsedBytes;
    } catch {
      // fall back to os.freemem()
    }
  }
  const usedBytes = Math.max(0, totalBytes - freeBytes);

  const processes = [];
  if (platform !== "win32") {
    const psOut = await safeExec("ps", ["-ax", "-o", "pid=,ppid=,rss=,comm="]);
    for (const line of psOut.split(/\r?\n/)) {
      const m = line.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/);
      if (!m) continue;
      const pid = Number(m[1]);
      const rssBytes = Number(m[3]) * 1024;
      let swapBytes = 0;
      if (platform === "linux") {
        try {
          swapBytes = parseProcStatusVmSwap(fs.readFileSync(`/proc/${pid}/status`, "utf8"));
        } catch {
          swapBytes = 0;
        }
      }
      processes.push({
        pid,
        ppid: Number(m[2]),
        rssBytes,
        trueFootprintBytes: rssBytes + swapBytes,
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


// Closed-vocabulary sanitizers for runtime-provided free text (mirrors crates/sj-core/src/linux.rs).
// Anything that is not plainly a name/ref/status becomes a hash label; shapes are never "judged secret".
function hash8(raw) {
  return crypto.createHash("sha256").update(String(raw)).digest("hex").slice(0, 8);
}

export function safeName(raw, prefix) {
  const v = String(raw ?? "");
  return /^[A-Za-z0-9][A-Za-z0-9_.:@\\-]{0,95}$/.test(v) ? v : `${prefix}-${hash8(v)}`;
}

export function safeImage(raw) {
  const v = String(raw ?? "");
  if (!v) return "";
  const [body, digest, ...extra] = v.split("@");
  const digestOk = digest === undefined || (extra.length === 0 && /^sha256:[0-9a-fA-F]+$/.test(digest));
  const ok = digestOk && v.length <= 200 && /^[A-Za-z0-9][A-Za-z0-9_.:/-]*$/.test(body) && !body.includes("//");
  return ok ? v : `image-${hash8(v)}`;
}

const STATUS_OPEN = new Set(["up", "exited", "created", "dead", "paused", "restarting", "removing", "running"]);
const STATUS_VOCAB = new Set([
  "about", "an", "a", "less", "than", "second", "seconds", "minute", "minutes", "hour", "hours", "day", "days",
  "week", "weeks", "month", "months", "year", "years", "ago", "healthy", "unhealthy", "starting", "paused", "health:",
]);
export function safeStatus(raw) {
  const v = String(raw ?? "");
  if (!v) return "";
  const words = v.toLowerCase().split(/\s+/).filter(Boolean);
  const ok =
    v.length <= 80 &&
    /^[A-Za-z0-9 ()]+$/.test(v) &&
    STATUS_OPEN.has(words[0]) &&
    words.slice(1).every((w) => {
      const t = w.replace(/^\(+|\)+$/g, "");
      return t === "" || /^\d+$/.test(t) || STATUS_VOCAB.has(t);
    });
  return ok ? v : "<redacted>";
}

const STATE_WORDS = new Set(["", "running", "exited", "created", "dead", "paused", "restarting", "removing", "stopped", "configured"]);
export function safeState(raw) {
  const v = String(raw ?? "").trim().toLowerCase();
  return STATE_WORDS.has(v) ? v : "unknown";
}

function safeToken(raw) {
  return /^[a-z-]{1,24}$/.test(String(raw ?? "")) ? String(raw) : "unknown";
}

export function safeContainerId(raw) {
  return /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(String(raw ?? ""));
}

export function parseSystemctlUnits(stdout, scope = "system") {
  const units = [];
  for (const rawLine of String(stdout || "").split(/\r?\n/)) {
    const line = rawLine.trim().replace(/^●\s*/, "").trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 4) continue;
    const [unit, load, active, sub, ...descParts] = parts;
    const description = descParts.join(" ");
    const lowUnit = unit.toLowerCase();
    const lowDesc = description.toLowerCase();
    const isPodmanHealthcheck =
      ((lowUnit.includes("podman") || lowUnit.includes("libpod")) &&
        (lowUnit.includes("healthcheck") || lowDesc.includes("healthcheck"))) ||
      (lowUnit.includes("healthcheck") && lowDesc.includes("conmon"));
    units.push({
      unit: safeName(unit, "unit"),
      scope,
      load: safeToken(load),
      active: safeToken(active),
      sub: safeToken(sub),
      description: description ? "<redacted>" : "",
      isPodmanHealthcheck,
    });
  }
  return units;
}

export function parseLinuxProcessStates(psOut) {
  let dStateCount = 0;
  let zombieCount = 0;
  for (const line of String(psOut || "").split(/\r?\n/)) {
    const stat = line.trim().split(/\s+/)[0] || "";
    if (stat.startsWith("D")) dStateCount += 1;
    else if (stat.startsWith("Z")) zombieCount += 1;
  }
  return { dStateCount, zombieCount };
}

export async function collectBlockers({ platformOverride = null, procFiles = null, execFn = null } = {}) {
  const platform = platformOverride || os.platform();
  const runExec = execFn || safeExecResult;
  const readProc = (p) => {
    if (procFiles && Object.prototype.hasOwnProperty.call(procFiles, p)) return procFiles[p];
    return fs.readFileSync(p, "utf8");
  };
  const counters = [];
  let worst = "OK";
  const escalate = (sev) => {
    if (sev === "CRITICAL") worst = "CRITICAL";
    else if (sev === "WARN" && worst === "OK") worst = "WARN";
  };

  let systemd = null;

  if (platform === "darwin") {
    const resN = await runExec("sysctl", ["-n", "kern.num_vnodes"]);
    const resM = await runExec("sysctl", ["-n", "kern.maxvnodes"]);
    const numVnodes = Number(resN.stdout) || 0;
    const maxVnodes = Number(resM.stdout) || 0;
    if (maxVnodes > 0) {
      const pct = Math.round((numVnodes / maxVnodes) * 100);
      const sev = pct >= 90 ? "CRITICAL" : pct >= 75 ? "WARN" : "OK";
      escalate(sev);
      counters.push({ name: "kern.vnodes", current: numVnodes, max: maxVnodes, percent: pct, status: sev });
    }
  } else if (platform === "linux") {
    try {
      const fileNr = readProc("/proc/sys/fs/file-nr").trim().split(/\s+/);
      const openFiles = Number(fileNr[0]) || 0;
      const maxFiles = Number(fileNr[2]) || 0;
      if (maxFiles > 0) {
        const pct = Math.round((openFiles / maxFiles) * 100);
        const sev = pct >= 90 ? "CRITICAL" : pct >= 75 ? "WARN" : "OK";
        escalate(sev);
        counters.push({ name: "fs.file-nr", current: openFiles, max: maxFiles, percent: pct, status: sev });
      }
    } catch {
      // ignore if unavailable
    }

    try {
      const maxWatches = Number(readProc("/proc/sys/fs/inotify/max_user_watches").trim()) || 0;
      if (maxWatches > 0) {
        const sev = maxWatches < 65536 ? "WARN" : "OK";
        escalate(sev);
        counters.push({
          name: "fs.inotify.max_user_watches",
          current: maxWatches,
          max: 524288,
          percent: Math.min(100, Math.round((maxWatches / 524288) * 100)),
          status: sev,
        });
      }
    } catch {
      // ignore if unavailable
    }

    const psRes = await runExec("ps", ["-eo", "stat=,pid=,comm="]);
    if (psRes.ok && psRes.stdout) {
      const { dStateCount, zombieCount } = parseLinuxProcessStates(psRes.stdout);
      if (dStateCount > 0) {
        const sev = dStateCount >= 10 ? "CRITICAL" : dStateCount >= 3 ? "WARN" : "OK";
        escalate(sev);
        counters.push({
          name: "proc.d_state",
          current: dStateCount,
          max: 10,
          percent: Math.min(100, Math.round((dStateCount / 10) * 100)),
          status: sev,
        });
      }
      if (zombieCount > 0) {
        const sev = zombieCount >= 25 ? "CRITICAL" : zombieCount >= 5 ? "WARN" : "OK";
        escalate(sev);
        counters.push({
          name: "proc.zombies",
          current: zombieCount,
          max: 25,
          percent: Math.min(100, Math.round((zombieCount / 25) * 100)),
          status: sev,
        });
      }
    }

    const [sysRes, userRes, allUserRes] = await Promise.all([
      runExec("systemctl", ["--failed", "--no-legend", "--no-pager", "--plain"]),
      runExec("systemctl", ["--user", "--failed", "--no-legend", "--no-pager", "--plain"]),
      runExec("systemctl", ["--user", "list-units", "--all", "--type=service,timer", "--no-legend", "--no-pager", "--plain"]),
    ]);
    const systemFailed = sysRes.ok ? parseSystemctlUnits(sysRes.stdout, "system") : [];
    const userFailed = userRes.ok ? parseSystemctlUnits(userRes.stdout, "user") : [];
    if (allUserRes.ok && allUserRes.stdout) {
      for (const u of parseSystemctlUnits(allUserRes.stdout, "user")) {
        const sub = u.sub.toLowerCase();
        const act = u.active.toLowerCase();
        if (
          u.isPodmanHealthcheck &&
          (act === "failed" || sub === "auto-restart" || sub === "failed") &&
          !userFailed.some((e) => e.unit === u.unit)
        ) {
          userFailed.push(u);
        }
      }
    }
    const podmanHealthcheckIssues = userFailed.filter((u) => u.isPodmanHealthcheck);
    systemd = {
      available: Boolean(sysRes.ok || userRes.ok),
      userBusAvailable: Boolean(userRes.ok),
      systemFailed,
      userFailed,
      podmanHealthcheckIssues,
    };

    if (systemFailed.length > 0) {
      const sev = systemFailed.length >= 3 ? "CRITICAL" : "WARN";
      escalate(sev);
      counters.push({
        name: "systemd.system_failed",
        current: systemFailed.length,
        max: Math.max(1, systemFailed.length),
        percent: 100,
        status: sev,
      });
    }
    if (userFailed.length > 0) {
      escalate("WARN");
      counters.push({
        name: "systemd.user_failed",
        current: userFailed.length,
        max: Math.max(1, userFailed.length),
        percent: 100,
        status: "WARN",
      });
    }
    if (podmanHealthcheckIssues.length > 0) {
      escalate("WARN");
      counters.push({
        name: "podman.healthcheck_failed",
        current: podmanHealthcheckIssues.length,
        max: Math.max(1, podmanHealthcheckIssues.length),
        percent: 100,
        status: "WARN",
      });
    }
  }

  return {
    schema: SCHEMA_VERSIONS_EXT.blockers,
    source: "node-fallback",
    status: worst,
    counters,
    ...(systemd ? { systemd } : {}),
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

// Replace every URL's path/query/fragment by nothing: only scheme://host[:port] is reported, because
// hosted MCP services often put the bearer secret in the path. Returns the text and whether a
// secret-looking path/query was dropped.
function stripUrlPaths(text) {
  let risky = false;
  const out = String(text).replace(/\b([a-z][a-z0-9+.-]*:\/\/[^\s/?#"']*)([^\s"']*)/gi, (_m, origin, rest) => {
    if (/[A-Za-z0-9_-]{16,}|\?[^\s]+=/.test(rest)) risky = true;
    return rest && rest !== "/" ? `${origin}/<path-omitted>` : origin;
  });
  return { text: out, risky };
}

// Pull HTTP headers out of argv (`--header "N: v"`, `--header=N:v`, `-H "N: v"`, `-H"N: v"`) so their
// values are never printed. Returns the argv without the values plus [name, value] pairs.
function extractHeaderArgs(args) {
  const rest = [];
  const headers = [];
  const take = (raw) => {
    const text = String(raw);
    const i = text.indexOf(":");
    if (i === -1) headers.push([text.trim(), ""]);
    else headers.push([text.slice(0, i).trim(), text.slice(i + 1).trim()]);
  };
  const isFlag = (x) => typeof x === "string" && x.startsWith("-");
  for (let i = 0; i < args.length; i++) {
    const a = String(args[i]);
    if (a === "--header" || a === "-H" || a === "--headers") {
      rest.push(a);
      if (i + 1 >= args.length) continue;
      const first = String(args[++i]);
      if (first.includes(":")) {
        take(first); // "Name: value"
      } else if (i + 1 < args.length && !isFlag(String(args[i + 1]))) {
        // mcp-proxy style two-argument form: KEY VALUE
        headers.push([first.trim(), String(args[++i])]);
      } else {
        headers.push([first.trim(), ""]);
      }
    } else if (a.startsWith("--header=") || a.startsWith("--headers=")) {
      take(a.slice(a.indexOf("=") + 1));
      rest.push("--header");
    } else if (a.startsWith("-H") && a.length > 2 && !a.startsWith("--")) {
      take(a.slice(2));
      rest.push("-H");
    } else {
      rest.push(a);
    }
  }
  return { rest, headers };
}

function parseTomlMcpServers(tomlText) {
  const servers = {};
  let current = null;
  let currentTable = null;
  for (const rawLine of tomlText.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const secMatch = line.match(/^\[(?:mcp_servers|mcpServers)\.([^\]]+)\]$/);
    if (secMatch) {
      const name = secMatch[1].replace(/^["']|["']$/g, "");
      const sub = name.match(/^(.+)\.(env|headers)$/);
      if (sub) {
        const parent = servers[sub[1]] || { args: [], env: {} };
        servers[sub[1]] = parent;
        parent[sub[2]] = parent[sub[2]] || {};
        current = parent;
        currentTable = parent[sub[2]];
        continue;
      }
      current = servers[name] || { args: [], env: {} };
      servers[name] = current;
      currentTable = null;
      continue;
    }
    if (line.startsWith("[")) {
      current = null;
      currentTable = null;
      continue;
    }
    if (!current) continue;
    const kv = line.match(/^([A-Za-z0-9_.-]+)\s*=\s*(.+)$/);
    if (!kv) continue;
    const [, key, rawVal] = kv;
    if (currentTable) {
      currentTable[key] = rawVal.replace(/^["']|["']$/g, "");
    } else if (key === "command" || key === "url") {
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

export async function collectMcpAudit({ configDirs, homeDir = os.homedir(), redactFn = redactSecrets } = {}) {
  const dirs = Array.isArray(configDirs) ? configDirs : defaultMcpConfigDirs(homeDir);
  const servers = [];
  const seenNames = new Map();

  const recordServer = (name, cfg, sourceFile) => {
    const count = (seenNames.get(name) || 0) + 1;
    seenNames.set(name, count);
    const rawArgs = Array.isArray(cfg?.args) ? cfg.args.map(String) : [];
    const { rest: argsList, headers: argHeaders } = extractHeaderArgs(rawArgs);
    // Header VALUES are never emitted: names only. A header whose name or value looks credential-like
    // flags the server as secret-risky.
    const headerEntries = [
      ...(cfg?.headers && typeof cfg.headers === "object" ? Object.entries(cfg.headers) : []),
      ...argHeaders,
    ];
    const headerNames = headerEntries.map(([k]) => redactFn(String(k)));
    const headerHasSecret = headerEntries.some(
      ([k, v]) =>
        /KEY|TOKEN|SECRET|PASSWORD|AUTH|COOKIE|SIGN|TEAM|CRED/i.test(String(k)) ||
        redactFn(String(v)) !== String(v) ||
        /[A-Za-z0-9_-]{16,}/.test(String(v))
    );
    const combinedRaw = [cfg?.url ? String(cfg.url) : "", ...argsList]
      .filter(Boolean)
      .join(" ");
    // Redact per ARGUMENT before joining so a credential value with spaces cannot leak its tail.
    const boundarySafe = [cfg?.url ? String(cfg.url) : "", ...redactArgv(argsList)]
      .filter(Boolean)
      .join(" ");
    const safeName = redactFn(String(name));
    const stripped = stripUrlPaths(redactFn(boundarySafe));
    const redactedArgs = stripped.text;
    const rawCommand = String(cfg?.command || "");
    const redactedCommand = redactFn(rawCommand);
    const envEntries = cfg?.env && typeof cfg.env === "object" ? Object.entries(cfg.env) : [];
    const envHasSecret = envEntries.some(
      ([k, v]) =>
        /KEY|TOKEN|SECRET|PASSWORD|AUTH/i.test(k) || redactFn(String(v)) !== String(v)
    );
    const hasSecretRisk =
      stripped.risky ||
      headerHasSecret ||
      redactedArgs !== combinedRaw ||
      redactedCommand !== rawCommand ||
      safeName !== String(name) ||
      redactedArgs.includes("<REDACTED>") ||
      redactedCommand.includes("<REDACTED>") ||
      envHasSecret;

    servers.push({
      name: safeName,
      command: redactedCommand,
      argsRedacted: redactedArgs,
      headerNames,
      duplicateCount: count,
      hasSecretRisk,
      sourceFile: redactFn(String(sourceFile)),
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

// Same bound as the Rust discovery (check_dir_descendants_safe(.., 50_000)): fail closed past it.
const LINUX_DESCENDANTS = { descendants: true, maxEntries: 50_000 };

export async function collectCleanableCaches({ homeDir = os.homedir(), isProtectedFn = isProtectedPath, descendants = false } = {}) {
  const knownCaches = [
    path.join(homeDir, ".cache", "npm"),
    path.join(homeDir, ".npm", "_cacache"),
    path.join(homeDir, ".cache", "pip"),
    path.join(homeDir, ".cache", "uv"),
    path.join(homeDir, ".cache", "yarn"),
    path.join(homeDir, ".cache", "pnpm"),
    path.join(homeDir, ".cache", "go-build"),
    path.join(homeDir, ".cache", "pipenv"),
    path.join(homeDir, "Library", "Caches", "Homebrew"),
    path.join(homeDir, "Library", "Caches", "pip"),
    path.join(homeDir, "Library", "Caches", "pnpm"),
    path.join(homeDir, "AppData", "Local", "npm-cache"),
    path.join(homeDir, "AppData", "Local", "pip", "Cache"),
    path.join(homeDir, ".cargo", "registry", "cache"),
    path.join(homeDir, ".gradle", "caches"),
  ];
  const candidates = [];
  const present = knownCaches.filter((cachePath) => fs.existsSync(cachePath));
  const verdicts = judgeMany(present, isProtectedFn, descendants ? { homeDir, ...LINUX_DESCENDANTS } : { homeDir });
  for (const [i, cachePath] of present.entries()) {
    const prot = verdicts[i] || { protected: true };
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

function parseDockerDfOutput(stdout) {
  const df = {
    available: false,
    imagesTotalBytes: 0,
    imagesReclaimableBytes: 0,
    containersTotalBytes: 0,
    containersReclaimableBytes: 0,
    volumesTotalBytes: 0,
    volumesReclaimableBytes: 0,
    buildCacheTotalBytes: 0,
    buildCacheReclaimableBytes: 0,
  };
  const trimmed = String(stdout || "").trim();
  if (!trimmed) return df;
  const rows = [];
  if (trimmed.startsWith("[")) {
    try {
      const arr = JSON.parse(trimmed);
      if (Array.isArray(arr)) rows.push(...arr);
    } catch {
      // ignore
    }
  } else {
    for (const line of trimmed.split(/\r?\n/)) {
      try {
        rows.push(JSON.parse(line.trim()));
      } catch {
        // ignore
      }
    }
  }
  for (const obj of rows) {
    if (!obj || typeof obj !== "object" || !obj.Type) continue;
    df.available = true;
    const t = String(obj.Type).toLowerCase();
    const sz = parseHumanSize(obj.Size);
    const rec = parseHumanSize(obj.Reclaimable);
    if (t === "images") {
      df.imagesTotalBytes = sz;
      df.imagesReclaimableBytes = rec;
    } else if (t === "containers") {
      df.containersTotalBytes = sz;
      df.containersReclaimableBytes = rec;
    } else if (t === "local volumes" || t === "volumes") {
      df.volumesTotalBytes = sz;
      df.volumesReclaimableBytes = rec;
    } else if (t === "build cache") {
      df.buildCacheTotalBytes = sz;
      df.buildCacheReclaimableBytes = rec;
    }
  }
  return df;
}

function parseContainerPs(stdout, runtime) {
  const trimmed = String(stdout || "").trim();
  if (!trimmed) return [];
  const rows = [];
  if (trimmed.startsWith("[")) {
    try {
      const arr = JSON.parse(trimmed);
      if (Array.isArray(arr)) rows.push(...arr);
    } catch {
      // ignore
    }
  } else {
    for (const line of trimmed.split(/\r?\n/)) {
      try {
        rows.push(JSON.parse(line.trim()));
      } catch {
        // ignore
      }
    }
  }
  const out = [];
  for (const obj of rows) {
    if (!obj || typeof obj !== "object") continue;
    const id = String(obj.Id || obj.ID || "");
    if (!safeContainerId(id)) continue;
    const name = Array.isArray(obj.Names) ? String(obj.Names[0] || id) : String(obj.Names || id);
    const status = String(obj.Status || "");
    const state = String(obj.State || "");
    const lowState = state.toLowerCase();
    const lowStatus = status.toLowerCase();
    const stopped =
      ["exited", "created", "dead"].includes(lowState) ||
      lowStatus.startsWith("exited") ||
      lowStatus === "created" ||
      lowStatus.startsWith("dead");
    const unhealthy = lowStatus.includes("unhealthy");
    out.push({
      runtime,
      id,
      name: safeName(name, "container"),
      image: safeImage(String(obj.Image || "")),
      status: safeStatus(status),
      state: safeState(state),
      sizeBytes:
        typeof obj.Size === "number"
          ? obj.Size
          : obj.Size && typeof obj.Size === "object"
            ? Number(obj.Size.rwSize) || 0
            : parseHumanSize(obj.Size),
      stopped,
      unhealthy,
    });
  }
  return out;
}

function parseJournaldUsage(stdout) {
  for (const raw of String(stdout || "").split(/\s+/)) {
    const tok = raw.replace(/[.,;]+$/, "");
    const m = tok.match(/^([\d.]+)([BKMGT])$/i);
    if (!m) continue;
    const val = Number(m[1]);
    if (!Number.isFinite(val) || val < 0) continue;
    const u = m[2].toUpperCase();
    const mult = u === "B" ? 1 : u === "K" ? 1024 : u === "M" ? 1024 ** 2 : u === "G" ? 1024 ** 3 : 1024 ** 4;
    return Math.round(val * mult);
  }
  return null;
}

const PROTECTED_TMP_NAMES = [
  /^\.X11/,
  /^\.ICE/,
  /^systemd-private-/,
  /^ssh-/,
  /^tmux-/,
  /^orbit-/,
  /^\.font-unix$/,
  /^\.XIM-unix$/,
];

function dirNewestMtimeMs(dirPath, rootMtimeMs, state = { seen: 0, maxEntries: 50_000 }) {
  let newest = rootMtimeMs;
  let entries;
  try {
    entries = fs.readdirSync(dirPath, { withFileTypes: true });
  } catch {
    return Infinity;
  }
  for (const ent of entries) {
    state.seen += 1;
    if (state.seen > state.maxEntries) return Infinity;
    if (ent.isSymbolicLink()) return Infinity;
    const full = path.join(dirPath, ent.name);
    let st;
    try {
      st = fs.lstatSync(full);
    } catch {
      return Infinity;
    }
    if (st.mtimeMs > newest) newest = st.mtimeMs;
    if (ent.isDirectory()) {
      const childNewest = dirNewestMtimeMs(full, st.mtimeMs, state);
      if (childNewest > newest) newest = childNewest;
    }
  }
  return newest;
}

export async function collectLinuxAudit({
  platformOverride = null,
  homeDir = os.homedir(),
  tmpDir = "/tmp",
  aptArchivesDir = "/var/cache/apt/archives",
  staleAgeMs = 24 * 3600 * 1000,
  mountsRaw = null,
  execFn = null,
  isProtectedFn = isProtectedPath,
} = {}) {
  const platform = platformOverride || os.platform();
  const runExec = execFn || safeExecResult;
  const nowMs = Date.now();

  let mounts = [];
  let appimageMounts = [];
  const activeMountSet = new Set();
  if (platform === "linux") {
    try {
      const raw = mountsRaw !== null ? mountsRaw : fs.readFileSync("/proc/mounts", "utf8");
      mounts = parseProcMounts(raw);
      appimageMounts = mounts.filter((m) => m.kind === "appimage");
      for (const m of mounts) activeMountSet.add(m.mountpoint);
    } catch {
      // ignore
    }
  }

  const [dockerDfRes, dockerPsRes, dockerImgRes, podmanDfRes, podmanPsRes, journalRes] = await Promise.all([
    runExec("docker", ["system", "df", "--format", "{{json .}}"]),
    runExec("docker", ["ps", "-a", "--size", "--format", "{{json .}}"]),
    runExec("docker", ["images", "--filter", "dangling=true", "--format", "{{json .}}"]),
    runExec("podman", ["system", "df", "--format", "json"]),
    runExec("podman", ["ps", "-a", "--size", "--format", "json"]),
    platform === "linux" ? runExec("journalctl", ["--disk-usage"]) : Promise.resolve({ ok: false, stdout: "" }),
  ]);

  const dockerDf = parseDockerDfOutput(dockerDfRes.ok ? dockerDfRes.stdout : "");
  const dockerAll = parseContainerPs(dockerPsRes.ok ? dockerPsRes.stdout : "", "docker");
  const dockerDangling = [];
  if (dockerImgRes.ok && dockerImgRes.stdout) {
    for (const line of dockerImgRes.stdout.split(/\r?\n/)) {
      try {
        const obj = JSON.parse(line.trim());
        if (obj?.ID) {
          dockerDangling.push({
            id: String(obj.ID),
            repository: String(obj.Repository || "<none>"),
            tag: String(obj.Tag || "<none>"),
            sizeBytes: parseHumanSize(obj.Size),
          });
        }
      } catch {
        // ignore
      }
    }
  }

  const podmanDf = parseDockerDfOutput(podmanDfRes.ok ? podmanDfRes.stdout : "");
  const podmanAll = parseContainerPs(podmanPsRes.ok ? podmanPsRes.stdout : "", "podman");

  const journalBytes = journalRes.ok ? parseJournaldUsage(journalRes.stdout) : null;

  let aptArchivesBytes = 0;
  if (platform === "linux" && aptArchivesDir && fs.existsSync(aptArchivesDir)) {
    try {
      for (const ent of fs.readdirSync(aptArchivesDir, { withFileTypes: true })) {
        if (ent.isSymbolicLink() || !ent.isFile() || !ent.name.endsWith(".deb")) continue;
        try {
          aptArchivesBytes += fs.statSync(path.join(aptArchivesDir, ent.name)).size;
        } catch {
          // ignore
        }
      }
    } catch {
      // ignore
    }
  }

  const userCaches = await collectCleanableCaches({ homeDir, isProtectedFn, descendants: true });

  const staleTmpEntries = [];
  if ((platform === "linux" || tmpDir !== "/tmp") && tmpDir && fs.existsSync(tmpDir)) {
    try {
      const ents = fs.readdirSync(tmpDir, { withFileTypes: true });
      const candidates = [];
      for (const ent of ents) {
        if (ent.isSymbolicLink()) continue;
        if (PROTECTED_TMP_NAMES.some((re) => re.test(ent.name))) continue;
        if (!ent.isFile() && !ent.isDirectory()) continue;
        const full = path.join(tmpDir, ent.name);
        if (activeMountSet.has(full)) continue;
        let st;
        try {
          st = fs.lstatSync(full);
        } catch {
          continue;
        }
        const newestMtimeMs = ent.isDirectory() ? dirNewestMtimeMs(full, st.mtimeMs) : st.mtimeMs;
        if (!Number.isFinite(newestMtimeMs)) continue;
        const ageMs = Math.max(0, nowMs - newestMtimeMs);
        if (ageMs < staleAgeMs) continue;
        if (staleAgeMs === 0 && !ent.name.startsWith(".mount_") && !ent.name.startsWith("sj-")) continue;
        candidates.push({ ent, full, st, ageDays: Math.floor(ageMs / 86_400_000) });
      }
      const verdicts = judgeMany(
        candidates.map((c) => c.full),
        isProtectedFn,
        { homeDir, ...LINUX_DESCENDANTS }
      );
      for (const [i, c] of candidates.entries()) {
        if (verdicts[i]?.protected !== false) continue;
        const bytes = c.ent.isDirectory() ? dirSizeBounded(c.full, 2) : c.st.size;
        staleTmpEntries.push({
          path: c.full,
          bytes,
          kind: "stale_tmp_entry",
          ageDays: c.ageDays,
          manualReviewOnly: false,
          reason: c.ent.name.startsWith(".mount_") ? "stale_unmounted_appimage_dir" : "stale_tmp_artifact",
        });
      }
    } catch {
      // ignore
    }
  }

  const modelRoots = [
    path.join(homeDir, ".cache", "huggingface", "hub"),
    path.join(homeDir, ".ollama", "models"),
    path.join(homeDir, ".cache", "torch", "hub"),
    path.join(homeDir, ".cache", "vllm"),
    path.join(homeDir, ".cache", "lm-studio", "models"),
  ];
  if (process.env.HF_HOME) modelRoots.push(process.env.HF_HOME);
  if (process.env.OLLAMA_MODELS) modelRoots.push(process.env.OLLAMA_MODELS);
  const modelCaches = [];
  // Env-supplied roots must be absolute; every root is judged by the sj gate (with descendants).
  const modelCandidates = [...new Set(modelRoots)].filter((p) => p && path.isAbsolute(p) && fs.existsSync(p));
  const modelVerdicts = judgeMany(modelCandidates, isProtectedFn, { homeDir, ...LINUX_DESCENDANTS });
  for (const [i, p] of modelCandidates.entries()) {
    if (modelVerdicts[i]?.protected !== false) continue;
    try {
      const st = fs.lstatSync(p);
      if (st.isSymbolicLink()) continue;
      modelCaches.push({
        path: p,
        bytes: st.isDirectory() ? dirSizeBounded(p, 3) : st.size,
        kind: "model_cache",
        ageDays: Math.max(0, Math.floor((nowMs - st.mtimeMs) / 86_400_000)),
        manualReviewOnly: true,
        reason: "manual_review_only:model_cache",
      });
    } catch {
      // ignore
    }
  }

  const oldBackups = [];
  const backupMinAgeMs = staleAgeMs === 0 ? 0 : 30 * 86_400_000;
  const backupCandidates = [];
  for (const rel of ["backups", "backup", path.join(".local", "share", "backups")]) {
    const dir = path.join(homeDir, rel);
    if (!fs.existsSync(dir)) continue;
    try {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        if (ent.isSymbolicLink()) continue;
        const full = path.join(dir, ent.name);
        const st = fs.lstatSync(full);
        const ageMs = Math.max(0, nowMs - st.mtimeMs);
        if (ageMs < backupMinAgeMs) continue;
        backupCandidates.push({ full, st, ageMs });
      }
    } catch {
      // ignore
    }
  }
  const backupVerdicts = judgeMany(
    backupCandidates.map((c) => c.full),
    isProtectedFn,
    { homeDir, ...LINUX_DESCENDANTS }
  );
  for (const [i, c] of backupCandidates.entries()) {
    if (backupVerdicts[i]?.protected !== false) continue;
    oldBackups.push({
      path: c.full,
      bytes: c.st.isDirectory() ? dirSizeBounded(c.full, 2) : c.st.size,
      kind: "old_backup",
      ageDays: Math.floor(c.ageMs / 86_400_000),
      manualReviewOnly: true,
      reason: "manual_review_only:old_backup",
    });
  }

  return {
    schema: SCHEMA_VERSIONS_EXT.linuxAudit,
    source: "node-fallback",
    os: platform,
    arch: os.arch(),
    mounts,
    appimageMounts,
    docker: {
      available: dockerDf.available || dockerAll.length > 0 || dockerDangling.length > 0,
      df: dockerDf,
      buildCacheReclaimableBytes: dockerDf.buildCacheReclaimableBytes,
      imagesReclaimableBytes: dockerDf.imagesReclaimableBytes,
      exitedContainers: dockerAll.filter((c) => c.stopped),
      unhealthyContainers: dockerAll.filter((c) => c.unhealthy && !c.stopped),
      danglingImages: dockerDangling,
    },
    podman: {
      available: podmanDf.available || podmanAll.length > 0,
      df: podmanDf,
      exitedContainers: podmanAll.filter((c) => c.stopped),
      unhealthyContainers: podmanAll.filter((c) => c.unhealthy && !c.stopped),
      danglingImages: [],
    },
    journald: {
      available: journalBytes !== null,
      bytes: journalBytes ?? 0,
      vacuumTarget: "500M",
    },
    packageCaches: {
      aptArchivesPath: aptArchivesDir,
      aptArchivesBytes,
      userCaches,
    },
    staleTmpEntries,
    modelCaches,
    oldBackups,
    timestamp: new Date().toISOString(),
  };
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

  if (schema === SCHEMA_VERSIONS_EXT.memory && raw.system) {
    const sys = raw.system || {};
    const totalBytes = Number(sys.total_bytes || 0);
    const usedBytes = Number(sys.used_bytes || 0);
    const freeBytes = Math.max(0, totalBytes - usedBytes);
    const pState = String(sys.pressure_state || "normal").toUpperCase();
    const status = pState === "CRITICAL" ? "CRITICAL" : pState === "WARN" ? "ALERT" : "OK";
    const processes = (raw.processes || []).map((p) => ({
      pid: Number(p.pid || 0),
      ppid: Number(p.ppid || 0),
      rssBytes: Number(p.resident_bytes ?? p.rssBytes ?? 0),
      trueFootprintBytes: Number(p.true_footprint_bytes ?? p.trueFootprintBytes ?? 0),
      command: String(p.command || ""),
      isOrphanPpid1: Number(p.ppid || 0) === 1,
    }));
    return {
      ...raw,
      status: raw.status || status,
      totalBytes,
      freeBytes,
      usedBytes,
      swapTotalBytes: Number(sys.swap_total_bytes || 0),
      swapUsedBytes: Number(sys.swap_used_bytes || 0),
      processes,
    };
  }

  if (schema === SCHEMA_VERSIONS_EXT.blockers) {
    const out = { ...raw };
    if (!Array.isArray(out.counters)) {
      const m = out.metrics || {};
      const counters = [];
      const addRatio = (name, cur, max) => {
        if (typeof cur === "number" && typeof max === "number" && max > 0) {
          const percent = Math.round((cur / max) * 100);
          const status = percent >= 90 ? "CRITICAL" : percent >= 75 ? "WARN" : "OK";
          counters.push({ name, current: cur, max, percent, status });
        }
      };
      addRatio("kern.vnodes", m.vnodes_used, m.vnodes_max);
      addRatio("fs.file-nr", m.files_used, m.files_max);
      addRatio("fs.inotify.watches", m.inotify_watches_used, m.inotify_watches_max);
      out.counters = counters;
    }
    if (out.systemd) {
      const sd = out.systemd;
      const normUnit = (u) => ({
        unit: u.unit,
        scope: u.scope,
        load: u.load,
        active: u.active,
        sub: u.sub,
        description: u.description,
        isPodmanHealthcheck: Boolean(u.isPodmanHealthcheck ?? u.is_podman_healthcheck),
      });
      out.systemd = {
        available: Boolean(sd.available),
        userBusAvailable: Boolean(sd.userBusAvailable ?? sd.user_bus_available),
        systemFailed: (sd.systemFailed ?? sd.system_failed ?? []).map(normUnit),
        userFailed: (sd.userFailed ?? sd.user_failed ?? []).map(normUnit),
        podmanHealthcheckIssues: (sd.podmanHealthcheckIssues ?? sd.podman_healthcheck_issues ?? []).map(normUnit),
      };
    }
    return out;
  }

  if (schema === SCHEMA_VERSIONS_EXT.linuxAudit && (raw.package_caches || raw.packageCaches)) {
    const dk = raw.docker || {};
    const dkDf = dk.df || {};
    const pm = raw.podman || {};
    const pmDf = pm.df || {};
    const pc = raw.packageCaches ?? raw.package_caches ?? {};
    const dkImagesBytes =
      dkDf.imagesReclaimableBytes ?? dkDf.images_reclaimable_bytes ?? dk.imagesReclaimableBytes ?? 0;
    const dkBuildBytes =
      dkDf.buildCacheReclaimableBytes ?? dkDf.build_cache_reclaimable_bytes ?? dk.buildCacheReclaimableBytes ?? 0;
    const pmImagesBytes = pmDf.imagesReclaimableBytes ?? pmDf.images_reclaimable_bytes ?? 0;
    const pmVolumesBytes = pmDf.volumesReclaimableBytes ?? pmDf.volumes_reclaimable_bytes ?? 0;
    return {
      ...raw,
      appimageMounts: raw.appimageMounts ?? raw.appimage_mounts ?? [],
      docker: {
        available: Boolean(dk.available),
        df: {
          available: Boolean(dkDf.available),
          imagesReclaimableBytes: dkImagesBytes,
          buildCacheReclaimableBytes: dkBuildBytes,
        },
        buildCacheReclaimableBytes: dkBuildBytes,
        imagesReclaimableBytes: dkImagesBytes,
        exitedContainers: dk.exitedContainers ?? dk.exited_containers ?? [],
        unhealthyContainers: dk.unhealthyContainers ?? dk.unhealthy_containers ?? [],
        danglingImages: dk.danglingImages ?? dk.dangling_images ?? [],
      },
      podman: {
        available: Boolean(pm.available),
        df: {
          available: Boolean(pmDf.available),
          imagesReclaimableBytes: pmImagesBytes,
          volumesReclaimableBytes: pmVolumesBytes,
        },
        exitedContainers: pm.exitedContainers ?? pm.exited_containers ?? [],
        unhealthyContainers: pm.unhealthyContainers ?? pm.unhealthy_containers ?? [],
        danglingImages: pm.danglingImages ?? pm.dangling_images ?? [],
      },
      packageCaches: {
        aptArchivesPath: pc.aptArchivesPath ?? pc.apt_archives_path ?? "/var/cache/apt/archives",
        aptArchivesBytes: pc.aptArchivesBytes ?? pc.apt_archives_bytes ?? 0,
        userCaches: pc.userCaches ?? pc.user_caches ?? [],
      },
      staleTmpEntries: raw.staleTmpEntries ?? raw.stale_tmp_entries ?? [],
      modelCaches: raw.modelCaches ?? raw.model_caches ?? [],
      oldBackups: raw.oldBackups ?? raw.old_backups ?? [],
    };
  }

  return raw;
}

const STATUS_RANK = { OK: 0, CHECK: 1, WARN: 2, ALERT: 2, CRITICAL: 3 };

export async function collectSummary(options = {}) {
  const [disk, memory, blockers, orphans, trash, mcpAudit, cleanableCaches, linuxAudit] = await Promise.all([
    collectDisk(options),
    collectMemory(options),
    collectBlockers(options),
    collectOrphans(options),
    collectTrash(options),
    collectMcpAudit(options),
    collectCleanableCaches(options),
    os.platform() === "linux" || options.includeLinuxAudit ? collectLinuxAudit(options) : Promise.resolve(null),
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
    ...(linuxAudit ? { linuxAudit } : {}),
    timestamp: new Date().toISOString(),
  };
}
