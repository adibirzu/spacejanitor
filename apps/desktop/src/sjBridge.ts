import { ChildProcessWithoutNullStreams, execFile, spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { promisify } from "node:util";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const core = require("@spacejanitor/core");
const execFileAsync = promisify(execFile);

export interface ResolveBinaryOptions {
  resourcesPath?: string;
  cwd?: string;
  platform?: NodeJS.Platform;
  existsSync?: (p: string) => boolean;
}

export function resolveSjBinary(options: ResolveBinaryOptions = {}): string | null {
  const platform = options.platform ?? process.platform;
  const exe = platform === "win32" ? "sj.exe" : "sj";
  const exists = options.existsSync ?? fs.existsSync;
  const resourcesPath = options.resourcesPath ?? (process as { resourcesPath?: string }).resourcesPath ?? "";
  const cwd = options.cwd ?? process.cwd();

  const candidates = [
    resourcesPath ? path.join(resourcesPath, "bin", exe) : "",
    path.resolve(cwd, "target", "release", exe),
    path.resolve(cwd, "target", "debug", exe),
    path.resolve(cwd, "..", "..", "target", "release", exe),
    path.resolve(cwd, "..", "..", "target", "debug", exe),
  ].filter(Boolean);

  for (const cand of candidates) {
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
      child.on("exit", () => {
        this.proc = null;
        for (const [id, req] of this.pending.entries()) {
          clearTimeout(req.timer);
          req.reject(new Error("sj_sidecar_exited"));
          this.pending.delete(id);
        }
      });
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
              req.resolve({ ...(msg.result || {}), source: "sj-core" });
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
      }, 6000);
      this.pending.set(id, { resolve, reject, timer });
      const payload = JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n";
      this.proc.stdin.write(payload);
    });
  }

  private async callOneShot(method: string, params: Record<string, unknown>): Promise<Record<string, unknown> | null> {
    if (!this.binaryPath) return null;
    const cmdMap: Record<string, string[]> = {
      doctor: ["doctor", "--json"],
      disk: ["scan", ...(params.targetPath ? [String(params.targetPath)] : []), "--json"],
      trash: ["trash", "--json"],
      orphans: ["orphans", ...(params.targetPath ? [String(params.targetPath)] : []), "--json"],
      memory: ["memory", "--json"],
      blockers: ["blockers", "--json"],
      "mcp-audit": ["mcp-audit", "--json"],
    };
    const args = cmdMap[method];
    if (!args) return null;
    try {
      const { stdout } = await execFileAsync(this.binaryPath, args, {
        timeout: 6000,
        maxBuffer: 4 * 1024 * 1024,
      });
      const parsed = JSON.parse(stdout);
      if (parsed && typeof parsed === "object" && parsed.schema) {
        return { ...parsed, source: "sj-core" };
      }
    } catch {
      return null;
    }
    return null;
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
        return core.collectOrphans(params);
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
