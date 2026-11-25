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
}

const PACKAGE_REPO_ROOT = path.resolve(__dirname, "../../..");

export function resolveSjBinary(options: ResolveBinaryOptions = {}): string | null {
  const platform = options.platform ?? process.platform;
  const exe = platform === "win32" ? "sj.exe" : "sj";
  const exists = options.existsSync ?? fs.existsSync;
  const resourcesPath = options.resourcesPath ?? (process as { resourcesPath?: string }).resourcesPath ?? "";
  const isPackaged = options.isPackaged ?? false;

  if (resourcesPath) {
    const bundled = path.join(resourcesPath, "bin", exe);
    if (exists(bundled)) return bundled;
  }
  if (isPackaged) {
    return null;
  }

  const envBin = process.env.SPACEJANITOR_SJ_BIN;
  if (envBin && exists(envBin)) return envBin;

  const repoCandidates = [
    path.resolve(PACKAGE_REPO_ROOT, "target", "release", exe),
    path.resolve(PACKAGE_REPO_ROOT, "target", "debug", exe),
  ];
  for (const cand of repoCandidates) {
    if (exists(cand)) return cand;
  }

  const pathEnv = process.env.PATH || "";
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue;
    const full = path.join(dir, exe);
    if (exists(full)) return full;
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
    this.binaryPath = options.binaryPath !== undefined ? options.binaryPath : resolveSjBinary();
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
      orphans: ["orphans", "--json", ...(params.targetPath ? ["--", String(params.targetPath)] : [])],
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

  private failClosed(method: string, report: Record<string, unknown>): Record<string, unknown> {
    const failure = this.lastRustFailure;
    const candidates = (report as { candidates?: Array<Record<string, unknown>> }).candidates;
    if (method !== "orphans" || !failure || !Array.isArray(candidates)) return report;
    return {
      ...report,
      rustProof: failure,
      candidates: candidates.map((c) => ({ ...c, safeToPrune: false, proofStatus: `rust_proof_${failure}` })),
    };
  }

  async invoke(method: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
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
      case "orphans":
        return this.failClosed(method, await core.collectOrphans(params));
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
