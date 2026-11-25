import fs from "node:fs";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const core = require("@spacejanitor/core");

export interface RemediationCandidate {
  id: string;
  path: string;
  bytes: number;
  kind: "file" | "dir" | "git-worktree";
}

export interface RemediationPlan {
  schema: string;
  planId: string;
  dryRun: boolean;
  items: RemediationCandidate[];
  blockedItems: Array<{ id: string; path: string; bytes: number; reason: string }>;
  totalBytes: number;
  planSha256: string;
  confirmationPhrase: string;
  createdAtMs: number;
  expiresAtMs: number;
}

export interface ItemIdentity {
  dev: string;
  ino: string;
}

function snapshotIdentity(p: string): ItemIdentity | null {
  try {
    const st = fs.lstatSync(p, { bigint: true });
    return { dev: st.dev.toString(), ino: st.ino.toString() };
  } catch {
    return null;
  }
}

export class RemediationGate {
  private readonly homeDir?: string;
  private activePlan: RemediationPlan | null = null;
  private activeIdentities: Record<string, ItemIdentity | null> = {};
  private readonly approved = new Map<string, RemediationCandidate>();
  private readonly usedDigests = new Set<string>();
  private executing = false;

  constructor(options: { homeDir?: string } = {}) {
    this.homeDir = options.homeDir;
  }

  registerApprovedCandidates(candidates: RemediationCandidate[]): void {
    this.approved.clear();
    for (const c of candidates) {
      if (c && typeof c.path === "string" && c.path.trim()) {
        this.approved.set(c.path, {
          id: String(c.id ?? c.path),
          path: c.path,
          bytes: Number(c.bytes) || 0,
          kind: c.kind === "dir" || c.kind === "git-worktree" ? c.kind : "file",
        });
      }
    }
  }

  createDryRunPlan(candidates: RemediationCandidate[], nowMs = Date.now()): RemediationPlan {
    // Fail closed: only paths the main process itself reported may be planned, and the
    // size/kind come from that server-side record, never from the renderer.
    const trusted: RemediationCandidate[] = [];
    for (const cand of candidates) {
      const known = cand && typeof cand.path === "string" ? this.approved.get(cand.path) : undefined;
      if (!known) {
        throw new Error(`unapproved_candidate: ${cand?.path || "unknown"}`);
      }
      trusted.push({ ...known });
    }
    const plan: RemediationPlan = core.createRemediationPlan(trusted, {
      homeDir: this.homeDir,
      nowMs,
    });
    this.activePlan = plan;
    // Bind each planned path to the filesystem object it was planned against (dev/inode), so the
    // executor can refuse a path that was swapped for another object after authorization.
    this.activeIdentities = {};
    for (const item of plan.items) this.activeIdentities[item.path] = snapshotIdentity(item.path);
    return plan;
  }

  authorizeExecute(params: {
    planSha256: string;
    phrase: string;
    nowMs?: number;
  }): { allowed: boolean; reason: string; plan?: RemediationPlan; identities?: Record<string, ItemIdentity | null> } {
    if (this.executing) {
      return { allowed: false, reason: "remediation_mutex_locked" };
    }
    if (!this.activePlan) {
      return { allowed: false, reason: "no_active_dry_run_plan" };
    }
    if (this.usedDigests.has(params.planSha256)) {
      return { allowed: false, reason: "confirmation_token_already_used" };
    }

    let check: { allowed: boolean; reason: string };
    try {
      check = core.verifyRemediationGate({
        plan: this.activePlan,
        planSha256: params.planSha256,
        phrase: params.phrase,
        nowMs: params.nowMs ?? Date.now(),
        homeDir: this.homeDir,
      });
    } catch {
      return { allowed: false, reason: "gate_verification_error" };
    }

    if (!check.allowed) {
      return { allowed: false, reason: check.reason };
    }

    this.usedDigests.add(params.planSha256);
    return { allowed: true, reason: "verified", plan: this.activePlan, identities: { ...this.activeIdentities } };
  }

  withMutex<T>(fn: () => Promise<T>): Promise<T> {
    if (this.executing) {
      return Promise.reject(new Error("remediation_mutex_locked"));
    }
    this.executing = true;
    return fn().finally(() => {
      this.executing = false;
    });
  }
}
