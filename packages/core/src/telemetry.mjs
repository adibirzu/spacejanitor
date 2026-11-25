import { isProtectedPath } from "./protect.mjs";
import { redactSecrets, redactArgv } from "./redact.mjs";
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

export async function collectDisk({ targetPath = os.homedir(), isProtectedFn = isProtectedPath } = {}) {
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
      const prot = isProtectedFn(full);
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

async function safeExecResult(cmd, args, cwd, { maxBuffer = 1024 * 1024, timeout = 3000, env, input } = {}) {
  try {
    const pending = execFileAsync(cmd, args, { cwd, timeout, maxBuffer, ...(env ? { env } : {}) });
    if (input !== undefined && pending.child?.stdin) {
      pending.child.stdin.on("error", () => {});
      pending.child.stdin.end(input);
    }
    const { stdout } = await pending;
    return { ok: true, stdout: stdout.trim() };
  } catch {
    return { ok: false, stdout: "" };
  }
}


// Repo-controlled git config can EXECUTE commands (core.fsmonitor, hooks) or LIE about the working
// tree (fsmonitor answering "nothing changed"), so every proof call neutralises it.
const GIT_SAFE_ARGS = [
  "-c", "core.fsmonitor=false",
  "-c", "core.untrackedCache=false",
  "-c", `core.hooksPath=${os.devNull}`,
  "-c", "protocol.ext.allow=never",
  "--no-optional-locks",
];

function gitSafeEnv() {
  const env = {
    ...process.env,
    GIT_TERMINAL_PROMPT: "0",
    GIT_OPTIONAL_LOCKS: "0",
    // isolated global/system config and a non-interactive ssh: a proof can neither be steered by, nor hang on, ambient config
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_SSH_COMMAND: "ssh -o BatchMode=yes",
  };
  // Git for Windows does not reliably accept a device path as a config file, so global-config
  // isolation is POSIX-only; the repo-config gate (executableConfigRisk) is what protects Windows.
  if (process.platform !== "win32") {
    env.GIT_CONFIG_GLOBAL = os.devNull;
    env.GIT_CONFIG_SYSTEM = os.devNull;
  }
  for (const k of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE"]) {
    delete env[k];
  }
  return env;
}

const EXEC_CONFIG_PATTERNS = [
  /^filter\..+\.(clean|smudge|process)$/,
  /^remote\..+\.(uploadpack|receivepack|vcs|proxy)$/,
  /^core\.(sshcommand|gitproxy|askpass|pager|editor|alternaterefscommand)$/,
  /^credential\./,
  /^url\..+\.(insteadof|pushinsteadof)$/,
  /^include\./,
  /^includeif\./,
  /^diff\.external$/,
  /^diff\..+\.(textconv|command)$/,
  /^gpg\.(.+\.)?program$/,
  /^uploadpack\./,
  /^http\.(proxy|sslcertpasswordprotected)$/,
  /^ssh\./,
];

/** Returns the offending (lowercased) key when a git config key can make git execute a command, else null. */
export function classifyExecutableConfigKey(key) {
  const k = String(key).toLowerCase();
  return EXEC_CONFIG_PATTERNS.some((re) => re.test(k)) ? k : null;
}

/**
 * Read the repo-local and worktree config WITHOUT running anything (git config --file only parses) and
 * report the first key that could execute a command. Unreadable config fails closed.
 */
async function executableConfigRisk(gitDir) {
  const files = [];
  let commonDir = gitDir;
  try {
    const rel = fs.readFileSync(path.join(gitDir, "commondir"), "utf8").trim();
    if (rel) commonDir = path.resolve(gitDir, rel);
  } catch {
    // no commondir file: this IS the common dir
  }
  files.push(path.join(commonDir, "config"));
  const wtCfg = path.join(gitDir, "config.worktree");
  if (fs.existsSync(wtCfg)) files.push(wtCfg);
  for (const f of files) {
    if (!fs.existsSync(f)) continue;
    const res = await safeExecResult("git", ["config", "--file", f, "--list", "--name-only", "-z"], os.tmpdir(), { env: gitSafeEnv() });
    if (!res.ok) return "repo_config_can_execute:unreadable_config";
    for (const key of res.stdout.split("\0")) {
      const hit = key && classifyExecutableConfigKey(key);
      if (hit) return `repo_config_can_execute:${hit}`;
    }
  }
  return null;
}

function resolveCommonDir(gitDir) {
  try {
    const rel = fs.readFileSync(path.join(gitDir, "commondir"), "utf8").trim();
    return rel ? path.resolve(gitDir, rel) : gitDir;
  } catch {
    return gitDir;
  }
}

/** git against the SHARED git dir (branch reflogs live there and outlive a linked worktree). */
function gitProofCommon(commonDir, args, opts = {}) {
  return safeExecResult("git", [...GIT_SAFE_ARGS, "--git-dir", commonDir, ...args], os.tmpdir(), { ...opts, env: gitSafeEnv() });
}

/** Heads and tags the remotes actually hold (one ls-remote per remote), limited to objects we have. */
async function remoteTagAndHeadTips(G, remotes) {
  const tips = new Set();
  for (const remote of remotes) {
    const r = await G(["ls-remote", "--heads", "--tags", "--", remote], { timeout: 15000 });
    if (!r.ok) continue;
    for (const line of r.stdout.split(/\r?\n/)) {
      const sha = line.split(/\s+/)[0];
      if (/^[0-9a-f]{40,64}$/i.test(sha)) tips.add(sha);
    }
  }
  if (tips.size === 0) return [];
  const present = await G(["cat-file", "--batch-check"], { input: [...tips].join("\n") + "\n" });
  if (!present.ok) return [];
  return present.stdout.split(/\r?\n/).filter((l) => l && !l.endsWith(" missing")).map((l) => l.split(/\s+/)[0]);
}

function resolveWorktreeGitDir(wtPath) {
  try {
    const dotGit = path.join(wtPath, ".git");
    const st = fs.lstatSync(dotGit);
    if (st.isDirectory()) return dotGit;
    if (!st.isFile()) return null;
    const m = fs.readFileSync(dotGit, "utf8").match(/^gitdir:\s*(.+)\s*$/m);
    if (!m) return null;
    return path.resolve(wtPath, m[1].trim());
  } catch {
    return null;
  }
}

/** git call with an explicit --git-dir/--work-tree (config.worktree decoys and inherited GIT_DIR cannot redirect it). */
function gitProof(wtPath, gitDir, args, opts = {}) {
  return safeExecResult(
    "git",
    [...GIT_SAFE_ARGS, "--git-dir", gitDir, "--work-tree", wtPath, ...args],
    wtPath,
    { ...opts, env: gitSafeEnv() }
  );
}

function gitSafeIn(cwd, args, opts = {}) {
  return safeExecResult("git", [...GIT_SAFE_ARGS, ...args], cwd, { ...opts, env: gitSafeEnv() });
}

async function safeExec(cmd, args, cwd) {
  const res = await safeExecResult(cmd, args, cwd);
  return res.stdout;
}

/**
 * Prove (or fail to prove) that a linked worktree can be removed without losing anything.
 * Mirrors the Rust core (crates/sj-core/src/orphans.rs): dirty, untracked, ignored files, stashes,
 * unpushed commits/branches, no remote and detached/unborn HEAD all block; any git failure blocks.
 */
export async function inspectWorktree(wtPath, { maxAgeDays = 14, locked = false } = {}) {
  const base = {
    id: `wt-${path.basename(wtPath)}`,
    path: wtPath,
    kind: "git-worktree",
    maxAgeDays,
  };
  const unverified = (extra = {}) => ({
    ...base,
    clean: false,
    hasRemote: false,
    hasUnpushed: true,
    hasIgnored: false,
    hasStashes: false,
    hasIndexFlags: false,
    locked,
    proofStatus: "unverified",
    safeToPrune: false,
    ...extra,
  });
  if (!wtPath || !fs.existsSync(wtPath)) return unverified();
  const gitDir = resolveWorktreeGitDir(wtPath);
  if (!gitDir) return unverified();
  locked = locked || fs.existsSync(path.join(gitDir, "locked"));
  const configRisk = await executableConfigRisk(gitDir);
  if (configRisk) return unverified({ configRisk });
  const G = (args, opts) => gitProof(wtPath, gitDir, args, opts);

  const [statusRes, remotesRes, branchesRes, headRes, stashRes, symRes, headOkRes, flagsRes, extraRefsRes, reflogRes] = await Promise.all([
    G(["status", "--porcelain=v1", "--untracked-files=all", "--ignored=traditional", "--ignore-submodules=none"]),
    G(["remote"]),
    G(["rev-list", "--branches", "--not", "--remotes", "--count"]),
    G(["rev-list", "HEAD", "--not", "--remotes", "--count"]),
    G(["stash", "list"]),
    G(["symbolic-ref", "-q", "HEAD"]),
    G(["rev-parse", "--verify", "-q", "HEAD"]),
    // lowercase tags = assume-unchanged, "S" = skip-worktree: git status stays clean while edits exist
    G(["ls-files", "-v", "-z"], { maxBuffer: 64 * 1024 * 1024, timeout: 15000 }),
    // tags and per-worktree ref namespaces: lost with the worktree unless a remote holds them
    G(["for-each-ref", "--format=%(objectname)", "refs/tags", "refs/worktree", "refs/bisect", "refs/rewritten"]),
    // commits made on a detached HEAD and then left behind live only in this worktree's HEAD reflog
    G(["reflog", "show", "--format=%H", "HEAD"], { maxBuffer: 8 * 1024 * 1024 }),
  ]);
  if (![statusRes, remotesRes, branchesRes, headRes, stashRes, flagsRes, extraRefsRes, reflogRes].every((r) => r.ok)) {
    return unverified({ hasRemote: remotesRes.ok ? remotesRes.stdout.length > 0 : false });
  }
  const refShas = [...new Set(extraRefsRes.stdout.split(/\s+/).filter(Boolean))];
  const reflogShas = [...new Set(reflogRes.stdout.split(/\s+/).filter(Boolean))];
  let extraUnpushed = false;
  if (refShas.length + reflogShas.length > 3000 || [...refShas, ...reflogShas].some((x) => !/^[0-9a-f]{7,64}$/i.test(x))) {
    extraUnpushed = true; // cannot verify: fail closed
  } else {
    // shas travel on stdin (Windows command lines are short); remote tags are only fetched lazily
    const commonDir = resolveCommonDir(gitDir);
    const sharedG = commonDir !== gitDir ? (args, opts) => gitProofCommon(commonDir, args, opts) : null;
    let remoteTips = null;
    const getRemoteTips = async () => {
      if (remoteTips === null) remoteTips = await remoteTagAndHeadTips(G, remotesRes.stdout.split(/\s+/).filter(Boolean));
      return remoteTips;
    };
    const unreachable = async (run, shas, pre = [], notArgs = ["--remotes"]) => {
      if (shas.length === 0) return 0;
      const count = async (tips) => {
        const input = shas.join("\n") + "\n" + tips.map((t) => `^${t}`).join("\n") + (tips.length ? "\n" : "");
        const r = await run(["rev-list", "--count", ...pre, "--stdin", "--not", ...notArgs], { input });
        const n = Number(r.stdout);
        return r.ok && Number.isFinite(n) ? n : Infinity;
      };
      const n = await count([]);
      if (n === 0) return 0;
      return count(await getRemoteTips());
    };
    if ((await unreachable(G, refShas)) > 0) extraUnpushed = true;
    if (!extraUnpushed && reflogShas.length) {
      // linked worktree: commits still held by the SHARED reflogs (amend/rebase before push) are not lost
      const n = sharedG
        ? await unreachable(sharedG, reflogShas, ["--single-worktree"], ["--reflog", "--remotes"])
        : await unreachable(G, reflogShas);
      if (n > 0) extraUnpushed = true;
    }
  }
  const lines = statusRes.stdout.split(/\r?\n/).filter(Boolean);
  const hasIgnored = lines.some((l) => l.startsWith("!!"));
  const hasDirty = lines.some((l) => !l.startsWith("!!"));
  const hasRemote = remotesRes.stdout.length > 0;
  const hasStashes = stashRes.stdout.length > 0;
  const hasIndexFlags = flagsRes.stdout.split("\0").some((e) => /^[a-zS]/.test(e));
  const branchCount = Number(branchesRes.stdout);
  const headCount = Number(headRes.stdout);
  const countsValid = Number.isFinite(branchCount) && Number.isFinite(headCount);
  const hasUnpushed = !countsValid || branchCount > 0 || headCount > 0 || extraUnpushed;
  const onBranch = symRes.ok && symRes.stdout.length > 0 && headOkRes.ok;
  const proofStatus = countsValid ? "verified" : "unverified";
  return {
    ...base,
    clean: !hasDirty && !hasIgnored && !hasIndexFlags,
    hasRemote,
    hasUnpushed,
    hasIgnored,
    hasStashes,
    hasIndexFlags,
    locked,
    detachedHead: !onBranch,
    proofStatus,
    safeToPrune:
      !hasDirty && !hasIgnored && !hasIndexFlags && hasRemote && !hasUnpushed && !hasStashes && onBranch && !locked && proofStatus === "verified",
  };
}

/**
 * `git worktree remove` for a linked worktree, run against the MAIN repository with explicit
 * --git-dir/--work-tree and the same neutralised config as the proofs (no --force: git itself still
 * refuses dirty or locked worktrees). Works for worktrees placed beside the repo as well as inside it.
 */
export async function removeLinkedWorktree(wtPath) {
  const gitDir = resolveWorktreeGitDir(wtPath);
  if (!gitDir) return { ok: false, error: "worktree_git_dir_unresolvable" };
  const commonDir = resolveCommonDir(gitDir);
  if (commonDir === gitDir || path.basename(commonDir) !== ".git") return { ok: false, error: "main_repo_unresolvable" };
  const mainWorkTree = path.dirname(commonDir);
  try {
    await execFileAsync(
      "git",
      [...GIT_SAFE_ARGS, "--git-dir", commonDir, "--work-tree", mainWorkTree, "worktree", "remove", wtPath],
      { cwd: mainWorkTree, timeout: 15000, env: gitSafeEnv() }
    );
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message.split("\n")[0] : "worktree_remove_failed" };
  }
}

export async function collectOrphans({ targetPath = process.cwd(), maxAgeDays = 14 } = {}) {
  const resolved = path.resolve(targetPath);
  const candidates = [];

  const insideGit = await gitSafeIn(resolved, ["rev-parse", "--is-inside-work-tree"]);
  if (insideGit.ok && insideGit.stdout === "true") {
    const wtOut = await gitSafeIn(resolved, ["worktree", "list", "--porcelain"]);
    if (wtOut.ok) {
      // git lists the main working tree first: it is never an orphan, however the target is spelled.
      const blocks = wtOut.stdout.split(/\r?\n\r?\n/).filter(Boolean);
      for (const [idx, block] of blocks.entries()) {
        if (idx === 0) continue;
        const lines = block.split(/\r?\n/);
        const first = lines.find((l) => l.startsWith("worktree "));
        if (!first) continue;
        const wtPath = first.slice("worktree ".length).trim();
        if (!wtPath || wtPath === resolved) continue;
        const locked = lines.some((l) => l === "locked" || l.startsWith("locked "));
        candidates.push(await inspectWorktree(wtPath, { maxAgeDays, locked }));
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

export async function collectMemory({ top = 15, redactFn = redactSecrets } = {}) {
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

export async function collectCleanableCaches({ homeDir = os.homedir(), isProtectedFn = isProtectedPath } = {}) {
  const knownCaches = [
    path.join(homeDir, ".cache", "npm"),
    path.join(homeDir, ".npm", "_cacache"),
    path.join(homeDir, ".cache", "pip"),
    path.join(homeDir, ".cache", "yarn"),
    path.join(homeDir, ".cache", "pnpm"),
    path.join(homeDir, "Library", "Caches", "Homebrew"),
    path.join(homeDir, "Library", "Caches", "pip"),
    path.join(homeDir, "Library", "Caches", "pnpm"),
    path.join(homeDir, "AppData", "Local", "npm-cache"),
    path.join(homeDir, "AppData", "Local", "pip", "Cache"),
    path.join(homeDir, ".cargo", "registry", "cache"),
    path.join(homeDir, ".gradle", "caches"),
  ];
  const candidates = [];
  for (const cachePath of knownCaches) {
    if (!fs.existsSync(cachePath)) continue;
    const prot = isProtectedFn(cachePath, { homeDir });
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
