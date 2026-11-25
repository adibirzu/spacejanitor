/**
 * The only bridge from Node to the safety gate. Every destructive-safety decision (protected paths,
 * descendant walks, worktree proofs, plans, execution) is made by the Rust `sj` binary; this module
 * locates that binary by ABSOLUTE path (never PATH), runs it with a timeout, validates what comes
 * back and fails CLOSED: any missing, non-executable, slow, failing or unparseable sj is an error
 * that callers must turn into "refuse".
 */
import { execFile, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const exeName = (platform = process.platform) => (platform === "win32" ? "sj.exe" : "sj");
const DEFAULT_REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const DEFAULT_TIMEOUT_MS = 15000;
const MAX_BUFFER = 32 * 1024 * 1024;

export class SjGateError extends Error {
  constructor(reason) {
    super(reason);
    this.name = "SjGateError";
    this.reason = reason;
  }
}

function usable(candidate, platform = process.platform) {
  if (typeof candidate !== "string" || !path.isAbsolute(candidate)) return false;
  try {
    if (!fs.statSync(candidate).isFile()) return false;
    if (platform !== "win32") fs.accessSync(candidate, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

// undefined = auto-discover, null = forced unavailable, string = explicit absolute path
let configured;

/** Pin (string), disable (null) or reset to discovery (undefined) the sj binary used by this process. */
export function configureSjBinary(binaryPath) {
  configured = binaryPath;
}

/**
 * Locate the sj binary. Order: bundled `<resourcesPath>/bin/sj` (packaged app), then the
 * SPACEJANITOR_SJ_BIN override, then the repo's own target/{release,debug}. PATH is never searched.
 * SPACEJANITOR_NO_SJ=1 disables sj entirely (the gate then fails closed).
 */
export function resolveSjBinary({
  env = process.env,
  platform = process.platform,
  resourcesPath = process.resourcesPath || "",
  repoRoot = DEFAULT_REPO_ROOT,
} = {}) {
  if (env.SPACEJANITOR_NO_SJ === "1") return null;
  if (resourcesPath) {
    const bundled = path.join(resourcesPath, "bin", exeName(platform));
    if (usable(bundled, platform)) return bundled;
  }
  if (env.SPACEJANITOR_SJ_BIN && usable(env.SPACEJANITOR_SJ_BIN, platform)) return env.SPACEJANITOR_SJ_BIN;
  for (const profile of ["release", "debug"]) {
    const cand = path.join(repoRoot, "target", profile, exeName(platform));
    if (usable(cand, platform)) return cand;
  }
  return null;
}

/** The binary this process will use right now, or null (fail closed). */
export function activeSjBinary() {
  if (process.env.SPACEJANITOR_NO_SJ === "1") return null;
  if (configured === null) return null;
  if (typeof configured === "string") return usable(configured) ? configured : null;
  return resolveSjBinary();
}

function childEnv(homeDir) {
  const env = { ...process.env };
  if (homeDir) {
    env.HOME = homeDir;
    env.USERPROFILE = homeDir;
  }
  return env;
}

function parseJson(stdout) {
  try {
    const parsed = JSON.parse(stdout);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed;
  } catch {
    // fall through
  }
  throw new SjGateError("sj_unparseable");
}

/** Run sj synchronously and return its parsed JSON object. Throws SjGateError(reason) on any failure. */
export function runSjSync(args, { homeDir, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const bin = activeSjBinary();
  if (!bin) throw new SjGateError("sj_unavailable");
  const res = spawnSync(bin, args, {
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: MAX_BUFFER,
    shell: false,
    windowsHide: true,
    env: childEnv(homeDir),
  });
  if (res.error) {
    if (res.error.code === "ETIMEDOUT" || res.signal === "SIGTERM") throw new SjGateError("sj_timeout");
    throw new SjGateError("sj_unavailable");
  }
  if (res.status !== 0) throw new SjGateError(`sj_exit_${res.status ?? "signal"}`);
  return parseJson(res.stdout);
}

/** Async variant of runSjSync. `allowExit` lists non-zero exits whose stdout is still a JSON verdict. */
export function runSj(args, { homeDir, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    const bin = activeSjBinary();
    if (!bin) return reject(new SjGateError("sj_unavailable"));
    execFile(
      bin,
      args,
      { encoding: "utf8", timeout: timeoutMs, maxBuffer: MAX_BUFFER, windowsHide: true, env: childEnv(homeDir) },
      (err, stdout, stderr) => {
        if (err) {
          if (err.killed || err.signal === "SIGTERM" || err.code === "ETIMEDOUT") return reject(new SjGateError("sj_timeout"));
          if (typeof err.code === "number") {
            const e = new SjGateError(`sj_exit_${err.code}`);
            e.stderr = String(stderr || "").slice(0, 500);
            return reject(e);
          }
          return reject(new SjGateError("sj_unavailable"));
        }
        try {
          resolve(parseJson(stdout));
        } catch (e) {
          reject(e);
        }
      }
    );
  });
}
