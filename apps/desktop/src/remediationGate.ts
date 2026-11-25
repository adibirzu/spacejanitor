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

const MAX_REASON_CHARS = 300;

/**
 * Every error string that can leave the main process (IPC result, UI banner) passes through the shared
 * redactor first; sj stderr is never forwarded raw and is capped.
 */
function redactForRenderer(text: string): string {
  let out: string;
  try {
    out = String(core.redactSecrets(text));
  } catch {
    return "redaction_failed";
  }
  return out.length > MAX_REASON_CHARS ? `${out.slice(0, MAX_REASON_CHARS)}...` : out;
}

function reasonOf(err: unknown): string {
  const e = err as { reason?: string; stderr?: string; message?: string };
  const base = e?.reason || e?.message || "remediation_failed";
  const detail = typeof e?.stderr === "string" ? e.stderr.trim() : "";
  return redactForRenderer(detail ? `${base}: ${detail}` : base);
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

function planArgs(root: string, orphans: boolean): string[] {
  return ["plan", root, "--json", ...(orphans ? ["--include-orphans"] : [])];
}

function uiKind(sjKind: string): RemediationCandidate["kind"] {
  return sjKind === "orphan_worktree" ? "git-worktree" : "file";
}

interface ActivePlan {
  orphans: boolean;
  plan: RemediationPlan;
  sha: string;
  root: string;
  items: SjPlanItem[];
}

export class RemediationGate {
  private readonly homeDir?: string;
  private readonly runSj: RunSj;
  private readonly orphanScanEnabled: () => boolean;
  private planRoot: string;
  private active: ActivePlan | null = null;
  private readonly approved = new Map<string, RemediationCandidate>();
  private executing = false;

  constructor(options: { homeDir?: string; runSj?: RunSj; planRoot?: string; orphanScanEnabled?: () => boolean } = {}) {
    this.orphanScanEnabled = options.orphanScanEnabled ?? (() => false);
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
    // Orphan worktrees are planned only when the main-process opt-in is on (default OFF: trash only).
    const orphans = this.orphanScanEnabled() === true;
    const sjPlan = parseSjPlan(await this.runSj(planArgs(root, orphans), { timeoutMs: PLAN_TIMEOUT_MS }));
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
    this.active = { plan, sha: sjPlan.planSha256, root, items: selected, orphans };
    return plan;
  }

  authorizeExecute(params: {
    planSha256: string;
    phrase: string;
    nowMs?: number;
  }): { allowed: boolean; reason: string; plan?: ActivePlan } {
    if (this.executing) return { allowed: false, reason: "remediation_mutex_locked" };
    const active = this.active;
    if (!active) return { allowed: false, reason: "no_active_dry_run_plan" };
    if (active.items.length === 0) return { allowed: false, reason: "empty_or_missing_plan" };
    if (!params.planSha256 || params.planSha256 !== active.sha) return { allowed: false, reason: "plan_sha256_mismatch" };
    if (!params.phrase || params.phrase !== active.plan.confirmationPhrase) {
      return { allowed: false, reason: "confirmation_phrase_mismatch" };
    }
    if ((params.nowMs ?? Date.now()) > active.plan.expiresAtMs) return { allowed: false, reason: "confirmation_token_expired" };
    // Single use per dry-run. sj's digest is content-addressed (no nonce), so single use is enforced
    // by consuming this plan instance, never by remembering the digest: re-planning the same
    // leftovers after a failed or cancelled cleanup must stay possible.
    this.active = null;
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
      // The user confirmed one digest. If sj no longer reports it, nothing runs.
      let planError: string | null = null;
      try {
        const current = parseSjPlan(await this.runSj(planArgs(active.root, active.orphans), { timeoutMs: PLAN_TIMEOUT_MS }));
        if (current.planSha256 !== active.sha) planError = "plan_changed_since_confirmation";
      } catch (err) {
        planError = reasonOf(err);
      }
      for (const item of active.items) {
        if (planError) {
          failed.push({ path: item.path, error: planError });
          continue;
        }
        try {
          await this.executeItem(active, item);
          removed.push(item.path);
        } catch (err) {
          failed.push({ path: item.path, error: reasonOf(err) });
        }
      }
    } finally {
      this.executing = false;
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

  private async executeItem(active: ActivePlan, item: SjPlanItem): Promise<void> {
    // sj rebuilds and re-proves the plan at execution. Removing an item changes the digest of the
    // rest, so later items are bound to a freshly planned digest, but only when sj still reports
    // the exact item the user confirmed.
    const fresh = parseSjPlan(await this.runSj(planArgs(active.root, active.orphans), { timeoutMs: PLAN_TIMEOUT_MS }));
    const current = fresh.items.find((i) => i.id === item.id);
    if (!current || JSON.stringify(current) !== JSON.stringify(item)) {
      throw new Error("item_changed_since_plan");
    }
    const out = await this.runSj(
      [...planArgs(active.root, active.orphans), "--execute", "--confirm", "--plan-sha256", fresh.planSha256, "--item", item.id],
      { timeoutMs: EXECUTE_TIMEOUT_MS }
    );
    const done = out.executed_item as { id?: unknown } | undefined;
    if (out.mode !== "executed" || out.mutated !== true || !done || done.id !== item.id) {
      throw unparseable();
    }
  }
}
