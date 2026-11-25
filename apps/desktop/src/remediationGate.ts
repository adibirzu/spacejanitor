// eslint-disable-next-line @typescript-eslint/no-var-requires
const core = require("@spacejanitor/core");

/**
 * Remediation session state for the desktop app. Every SAFETY decision (protected paths, descendant
 * walks, worktree/orphan proofs, what may be removed, no-follow entry-by-entry deletion with
 * execute-time re-checks) is made by the Rust `sj` binary through `sj plan` / `sj plan --execute`.
 * This class only keeps the UI two-step session (digest, phrase, TTL, single use, mutex) and
 * refuses everything when sj is missing, slow or returns anything it cannot parse.
 */

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

export type RunSj = (
  args: string[],
  options?: { homeDir?: string; timeoutMs?: number }
) => Promise<Record<string, unknown>>;

interface SjPlanItem {
  id: string;
  kind: string;
  path: string;
  bytes: number;
  [extra: string]: unknown;
}

interface SjPlan {
  planSha256: string;
  items: SjPlanItem[];
  exclusions: Array<{ path: string; reason: string }>;
}

const PLAN_TTL_MS = 5 * 60 * 1000;
const PLAN_TIMEOUT_MS = 120_000;
const EXECUTE_TIMEOUT_MS = 300_000;
const SHA256_RE = /^[0-9a-f]{64}$/;

function unparseable(): Error {
  return new core.SjGateError("sj_unparseable");
}

function reasonOf(err: unknown): string {
  const e = err as { reason?: string; stderr?: string; message?: string };
  const base = e?.reason || e?.message || "remediation_failed";
  const detail = typeof e?.stderr === "string" ? e.stderr.trim() : "";
  return detail ? `${base}: ${detail}` : base;
}

function parseSjPlan(raw: Record<string, unknown>): SjPlan {
  if (!raw || raw.schema !== "spacejanitor.proposal.v1" || raw.mode !== "dry-run" || raw.mutated !== false) {
    throw unparseable();
  }
  const sha = raw.plan_sha256;
  if (typeof sha !== "string" || !SHA256_RE.test(sha) || !Array.isArray(raw.items)) throw unparseable();
  const items: SjPlanItem[] = [];
  for (const it of raw.items as Array<Record<string, unknown>>) {
    if (
      !it ||
      typeof it.id !== "string" ||
      typeof it.kind !== "string" ||
      typeof it.path !== "string" ||
      !it.path ||
      typeof it.bytes !== "number"
    ) {
      throw unparseable();
    }
    items.push(it as unknown as SjPlanItem);
  }
  const excl = Array.isArray(raw.protected_exclusions) ? (raw.protected_exclusions as Array<Record<string, unknown>>) : [];
  const exclusions = excl
    .filter((e) => e && typeof e.path === "string")
    .map((e) => ({ path: String(e.path), reason: String(e.reason || "protected") }));
  return { planSha256: sha, items, exclusions };
}

function uiKind(sjKind: string): RemediationCandidate["kind"] {
  return sjKind === "orphan_worktree" ? "git-worktree" : "file";
}

interface ActivePlan {
  plan: RemediationPlan;
  sha: string;
  root: string;
  items: SjPlanItem[];
}

export class RemediationGate {
  private readonly homeDir?: string;
  private readonly runSj: RunSj;
  private planRoot: string;
  private active: ActivePlan | null = null;
  private readonly approved = new Map<string, RemediationCandidate>();
  private readonly usedDigests = new Set<string>();
  private executing = false;

  constructor(options: { homeDir?: string; runSj?: RunSj; planRoot?: string } = {}) {
    this.homeDir = options.homeDir;
    this.runSj = options.runSj ?? ((args, opts) => core.runSj(args, { homeDir: this.homeDir, ...opts }));
    this.planRoot = options.planRoot ?? process.cwd();
  }

  /** The directory sj inspects for orphan worktrees; set from reports the main process produced. */
  setPlanRoot(root: string): void {
    if (typeof root === "string" && root.trim()) this.planRoot = root;
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

  /**
   * Ask sj for the dry-run plan and expose the part the user selected. Sizes, kinds and the digest
   * are sj's; renderer-supplied values are never trusted. Selected paths sj did not plan are blocked
   * with sj's own exclusion reason. Throws (fail closed) when sj is unavailable or unparseable.
   */
  async createDryRunPlan(candidates: RemediationCandidate[], nowMs = Date.now()): Promise<RemediationPlan> {
    const wanted = new Set<string>();
    for (const cand of candidates) {
      const known = cand && typeof cand.path === "string" ? this.approved.get(cand.path) : undefined;
      if (!known) {
        throw new Error(`unapproved_candidate: ${cand?.path || "unknown"}`);
      }
      wanted.add(known.path);
    }

    const root = this.planRoot;
    const sjPlan = parseSjPlan(await this.runSj(["plan", root, "--json"], { timeoutMs: PLAN_TIMEOUT_MS }));
    const selected = sjPlan.items.filter((i) => wanted.has(i.path));
    const plannedPaths = new Set(selected.map((i) => i.path));
    const blockedItems: RemediationPlan["blockedItems"] = [];
    for (const p of wanted) {
      if (plannedPaths.has(p)) continue;
      const excl = sjPlan.exclusions.find((e) => e.path === p);
      blockedItems.push({
        id: this.approved.get(p)?.id ?? p,
        path: p,
        bytes: this.approved.get(p)?.bytes ?? 0,
        reason: excl ? excl.reason : "not_in_sj_plan",
      });
    }

    const plan: RemediationPlan = {
      schema: "spacejanitor.plan.v1",
      planId: sjPlan.planSha256,
      dryRun: true,
      items: selected.map((i) => ({ id: i.id, path: i.path, bytes: i.bytes, kind: uiKind(i.kind) })),
      blockedItems,
      totalBytes: selected.reduce((acc, i) => acc + i.bytes, 0),
      planSha256: sjPlan.planSha256,
      confirmationPhrase: `CONFIRM-${sjPlan.planSha256.slice(0, 8).toUpperCase()}`,
      createdAtMs: nowMs,
      expiresAtMs: nowMs + PLAN_TTL_MS,
    };
    this.active = { plan, sha: sjPlan.planSha256, root, items: selected };
    return plan;
  }

  authorizeExecute(params: {
    planSha256: string;
    phrase: string;
    nowMs?: number;
  }): { allowed: boolean; reason: string; plan?: ActivePlan } {
    if (this.executing) return { allowed: false, reason: "remediation_mutex_locked" };
    if (this.usedDigests.has(params.planSha256)) return { allowed: false, reason: "confirmation_token_already_used" };
    const active = this.active;
    if (!active) return { allowed: false, reason: "no_active_dry_run_plan" };
    if (active.items.length === 0) return { allowed: false, reason: "empty_or_missing_plan" };
    if (!params.planSha256 || params.planSha256 !== active.sha) return { allowed: false, reason: "plan_sha256_mismatch" };
    if (!params.phrase || params.phrase !== active.plan.confirmationPhrase) {
      return { allowed: false, reason: "confirmation_phrase_mismatch" };
    }
    if ((params.nowMs ?? Date.now()) > active.plan.expiresAtMs) return { allowed: false, reason: "confirmation_token_expired" };
    this.usedDigests.add(params.planSha256);
    return { allowed: true, reason: "verified", plan: active };
  }

  /** Authorize and execute the confirmed plan, one `sj plan --execute` call per selected item. */
  async run(params: { planSha256: string; phrase: string; nowMs?: number }): Promise<Record<string, unknown>> {
    const auth = this.authorizeExecute(params);
    if (!auth.allowed || !auth.plan) {
      return { schema: "spacejanitor.reap.v1", executed: false, error: auth.reason };
    }
    const active = auth.plan;
    this.executing = true;
    const removed: string[] = [];
    const failed: Array<{ path: string; error: string }> = [];
    try {
      let first = true;
      for (const item of active.items) {
        try {
          await this.executeItem(active, item, first);
          removed.push(item.path);
        } catch (err) {
          failed.push({ path: item.path, error: reasonOf(err) });
        }
        first = false;
      }
    } finally {
      this.executing = false;
      this.active = null;
    }
    return {
      schema: "spacejanitor.reap.v1",
      executed: failed.length === 0 && removed.length > 0,
      partial: removed.length > 0 && failed.length > 0,
      planSha256: params.planSha256,
      removed,
      failed,
    };
  }

  private async executeItem(active: ActivePlan, item: SjPlanItem, first: boolean): Promise<void> {
    // sj rebuilds and re-proves the plan at execution. Removing an item changes the digest of the
    // rest, so later items are bound to a freshly planned digest, but only when sj still reports
    // the exact item the user confirmed.
    const fresh = parseSjPlan(await this.runSj(["plan", active.root, "--json"], { timeoutMs: PLAN_TIMEOUT_MS }));
    const current = fresh.items.find((i) => i.id === item.id);
    if (!current || JSON.stringify(current) !== JSON.stringify(item)) {
      throw new Error("item_changed_since_plan");
    }
    if (first && fresh.planSha256 !== active.sha) {
      throw new Error("plan_changed_since_confirmation");
    }
    const out = await this.runSj(
      ["plan", active.root, "--execute", "--confirm", "--plan-sha256", fresh.planSha256, "--item", item.id, "--json"],
      { timeoutMs: EXECUTE_TIMEOUT_MS }
    );
    const done = out.executed_item as { id?: unknown } | undefined;
    if (out.mode !== "executed" || out.mutated !== true || !done || done.id !== item.id) {
      throw unparseable();
    }
  }
}
