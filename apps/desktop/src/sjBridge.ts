import { ChildProcessWithoutNullStreams, execFile, spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { promisify } from "node:util";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const core = require("@spacejanitor/core");
const execFileAsync = promisify(execFile);

function rustTimeoutMs(method: string): number {
  const fromEnv = Number(process.env.SPACEJANITOR_SJ_TIMEOUT_MS);
  if (Number.isFinite(fromEnv) && fromEnv > 0) return fromEnv;
  return method === "orphans" ? 60000 : 6000;
}

// Reports that may carry command lines / config values get a second redaction pass in the
// main process, regardless of what the sidecar already did.
const REDACTED_METHODS = new Set(["mcp-audit", "memory", "blockers", "summary"]);

function finalizeSidecarReport(method: string, report: Record<string, unknown>): Record<string, unknown> {
  const normalized = core.normalizeReportEnvelope({ ...report, source: "sj-core" });
  return REDACTED_METHODS.has(method) ? core.redactSlmPayload(normalized) : normalized;
}

export interface ResolveBinaryOptions {
  resourcesPath?: string;
  cwd?: string;
  isPackaged?: boolean;
  platform?: NodeJS.Platform;
  existsSync?: (p: string) => boolean;
  isExecutable?: (p: string) => boolean;
  env?: NodeJS.ProcessEnv;
  repoRoot?: string;
}

const PACKAGE_REPO_ROOT = path.resolve(__dirname, "../../..");

function defaultIsExecutable(p: string, platform: NodeJS.Platform): boolean {
  if (platform === "win32") return true;
  try {
    fs.accessSync(p, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Locate the Rust `sj` gate binary by ABSOLUTE path. Never searches PATH or the cwd. A packaged app
 * only ever uses the binary bundled in its own resources (`<resources>/bin/sj`); when that is
 * missing the answer is null and every destructive action is refused. SPACEJANITOR_NO_SJ=1 disables sj.
 */
export function resolveSjBinary(options: ResolveBinaryOptions = {}): string | null {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  if (env.SPACEJANITOR_NO_SJ === "1") return null;
  const exe = platform === "win32" ? "sj.exe" : "sj";
  const exists = options.existsSync ?? fs.existsSync;
  // Injected predicates are test seams. Production uses the shared trust check (absolute, regular file
  // not a symlink, executable, owned by the user or root, not group/world writable, no world-writable
  // parent): the same code the core gate and the CLI use.
  const injected = options.existsSync !== undefined || options.isExecutable !== undefined;
  const isExec = options.isExecutable ?? ((p: string) => defaultIsExecutable(p, platform));
  const usable = (p: string): boolean =>
    injected ? path.isAbsolute(p) && exists(p) && isExec(p) : core.sjBinaryProblem(p, { platform }) === null;
  const resourcesPath = options.resourcesPath ?? (process as { resourcesPath?: string }).resourcesPath ?? "";
  const isPackaged = options.isPackaged ?? false;

  if (resourcesPath) {
    const bundled = path.join(resourcesPath, "bin", exe);
    if (usable(bundled)) return bundled;
  }
  if (isPackaged) {
    return null;
  }

  const envBin = env.SPACEJANITOR_SJ_BIN;
  if (envBin && usable(envBin)) return envBin;

  const repoRoot = options.repoRoot ?? PACKAGE_REPO_ROOT;
  for (const profile of ["release", "debug"]) {
    const cand = path.resolve(repoRoot, "target", profile, exe);
    if (usable(cand)) return cand;
  }
  return null;
}

interface PendingRpc {
  method: string;
  resolve: (value: Record<string, unknown>) => void;
  reject: (err: Error) => void;
  timer: NodeJS.Timeout;
}

export class SjBridge {
  private readonly binaryPath: string | null;
  private proc: ChildProcessWithoutNullStreams | null = null;
  private buffer = "";
  private nextId = 1;
  private readonly pending = new Map<number, PendingRpc>();

  constructor(options: { binaryPath?: string | null } = {}) {
    const requested = options.binaryPath !== undefined ? options.binaryPath : resolveSjBinary();
    // An explicit path gets the same trust checks as a resolved one (regular file, not a symlink, not
    // group/world writable, ...): read-only spawns must not run a binary the gate itself would refuse.
    this.binaryPath = requested && core.sjBinaryProblem(requested) === null ? requested : null;
    // Every safety decision in this process (core protect checks, orphan proofs, plan/execute) runs
    // through exactly this binary. null pins the gate closed: destructive actions are refused.
    core.configureSjBinary(this.binaryPath);
  }

  /** Whether destructive remediation can be attempted. Read-only views never depend on this. */
  remediationAvailable(): { available: boolean; reason: string } {
    return core.activeSjBinary() ? { available: true, reason: "" } : { available: false, reason: "sj_unavailable" };
  }

  private ensureSidecar(): boolean {
    if (!this.binaryPath) return false;
    if (this.proc && !this.proc.killed) return true;
    try {
      const child = spawn(this.binaryPath, ["serve-stdio"], {
        stdio: ["pipe", "pipe", "pipe"],
        shell: false,
      });
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (chunk: string) => this.handleStdout(chunk));
      child.stderr.on("data", () => {
        // drain stderr cleanly
      });
      const failPending = (reason: string) => {
        this.proc = null;
        for (const [id, req] of this.pending.entries()) {
          clearTimeout(req.timer);
          req.reject(new Error(reason));
          this.pending.delete(id);
        }
      };
      child.on("error", (err) => failPending(err.message || "sj_sidecar_error"));
      child.stdin.on("error", (err) => failPending(err.message || "sj_stdin_error"));
      child.on("exit", () => failPending("sj_sidecar_exited"));
      this.proc = child;
      return true;
    } catch {
      this.proc = null;
      return false;
    }
  }

  private handleStdout(chunk: string): void {
    this.buffer += chunk;
    let idx = this.buffer.indexOf("\n");
    while (idx !== -1) {
      const line = this.buffer.slice(0, idx).trim();
      this.buffer = this.buffer.slice(idx + 1);
      if (line) {
        try {
          const msg = JSON.parse(line);
          const id = Number(msg.id);
          const req = this.pending.get(id);
          if (req) {
            clearTimeout(req.timer);
            this.pending.delete(id);
            if (msg.error) {
              req.reject(new Error(String(msg.error.message || "rpc_error")));
            } else {
              req.resolve(finalizeSidecarReport(req.method, msg.result || {}));
            }
          }
        } catch {
          // ignore malformed line
        }
      }
      idx = this.buffer.indexOf("\n");
    }
  }

  private callSidecar(method: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      if (!this.ensureSidecar() || !this.proc) {
        reject(new Error("sidecar_unavailable"));
        return;
      }
      const id = this.nextId++;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error("sidecar_timeout"));
      }, rustTimeoutMs(method));
      this.pending.set(id, { method, resolve, reject, timer });
      const payload = JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n";
      this.proc.stdin.write(payload);
    });
  }

  // "timed_out" | "error" when the Rust binary ran but could not finish: destructive-action proofs
  // must not silently fall back to the weaker Node answer.
  private lastRustFailure: string | null = null;

  private async callOneShot(method: string, params: Record<string, unknown>): Promise<Record<string, unknown> | null> {
    this.lastRustFailure = null;
    if (!this.binaryPath) return null;
    const cmdMap: Record<string, string[]> = {
      doctor: ["doctor", "--json"],
      disk: ["scan", "--json", ...(params.targetPath ? ["--", String(params.targetPath)] : [])],
      trash: ["trash", "--json"],
      memory: ["memory", "--json"],
      blockers: ["blockers", "--json"],
      "mcp-audit": ["mcp-audit", "--json"],
    };
    const args = cmdMap[method];
    if (!args) return null;
    try {
      const { stdout } = await execFileAsync(this.binaryPath, args, {
        timeout: rustTimeoutMs(method),
        maxBuffer: 4 * 1024 * 1024,
      });
      const parsed = JSON.parse(stdout);
      if (parsed && typeof parsed === "object" && parsed.schema) {
        return finalizeSidecarReport(method, parsed);
      }
    } catch (err) {
      const e = err as NodeJS.ErrnoException & { killed?: boolean; signal?: string };
      if (e && e.code !== "ENOENT") {
        this.lastRustFailure = e.code === "ETIMEDOUT" || e.killed || e.signal ? "timed_out" : "error";
      }
      return null;
    }
    return null;
  }

  async invoke(method: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    // Orphan scanning is OFF unless the main process explicitly opted in: nothing runs, no git is spawned
    // and the report says "not scanned". With the opt-in the proof is Rust sj only (core -> sj orphans);
    // a missing/slow sj yields an error report with no candidates, never a weaker Node answer.
    if (method === "orphans") {
      return core.collectOrphans({ targetPath: params.targetPath, includeOrphans: params.includeOrphans === true });
    }
    if (this.binaryPath) {
      try {
        return await this.callSidecar(method, params);
      } catch {
        const oneShot = await this.callOneShot(method, params);
        if (oneShot) return oneShot;
      }
    }

    // Safe built-in Node telemetry collector fallback
    switch (method) {
      case "doctor":
        return core.collectDoctor();
      case "disk":
        return core.collectDisk(params);
      case "memory":
        return core.collectMemory(params);
      case "blockers":
        return core.collectBlockers();
      case "trash":
        return core.collectTrash(params);
      case "mcp-audit":
        return core.collectMcpAudit(params);
      case "summary":
        return core.collectSummary(params);
      default:
        throw new Error(`Unsupported bridge method: ${method}`);
    }
  }

  dispose(): void {
    if (this.proc && !this.proc.killed) {
      this.proc.kill();
    }
    this.proc = null;
  }
}
