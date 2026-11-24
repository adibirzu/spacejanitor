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

export class RemediationGate {
  private readonly homeDir?: string;
  private activePlan: RemediationPlan | null = null;
  private readonly approvedPaths = new Set<string>();
  private hasRegisteredCandidates = false;
  private readonly usedDigests = new Set<string>();
  private executing = false;

  constructor(options: { homeDir?: string } = {}) {
    this.homeDir = options.homeDir;
  }

  registerApprovedCandidates(candidates: RemediationCandidate[]): void {
    this.approvedPaths.clear();
    this.hasRegisteredCandidates = true;
    for (const c of candidates) {
      if (c && typeof c.path === "string" && c.path.trim()) {
        this.approvedPaths.add(c.path);
      }
    }
  }

  createDryRunPlan(candidates: RemediationCandidate[], nowMs = Date.now()): RemediationPlan {
    if (this.hasRegisteredCandidates) {
      for (const cand of candidates) {
        if (!cand || !this.approvedPaths.has(cand.path)) {
          throw new Error(`unapproved_candidate: ${cand?.path || "unknown"}`);
        }
      }
    }
    const plan: RemediationPlan = core.createRemediationPlan(candidates, {
      homeDir: this.homeDir,
      nowMs,
    });
    this.activePlan = plan;
    return plan;
  }

  authorizeExecute(params: {
    planSha256: string;
    phrase: string;
    nowMs?: number;
  }): { allowed: boolean; reason: string; plan?: RemediationPlan } {
    if (this.executing) {
      return { allowed: false, reason: "remediation_mutex_locked" };
    }
    if (!this.activePlan) {
      return { allowed: false, reason: "no_active_dry_run_plan" };
    }
    if (this.usedDigests.has(params.planSha256)) {
      return { allowed: false, reason: "confirmation_token_already_used" };
    }

    const check = core.verifyRemediationGate({
      plan: this.activePlan,
      planSha256: params.planSha256,
      phrase: params.phrase,
      nowMs: params.nowMs ?? Date.now(),
      homeDir: this.homeDir,
    });

    if (!check.allowed) {
      return { allowed: false, reason: check.reason };
    }

    this.usedDigests.add(params.planSha256);
    return { allowed: true, reason: "verified", plan: this.activePlan };
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
