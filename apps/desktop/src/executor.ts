import fs from "node:fs";
import path from "node:path";
import { ItemIdentity, RemediationPlan } from "./remediationGate";
import { worktreePruneBlockReason } from "./worktreeGuard";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const core = require("@spacejanitor/core");

export interface ExecutorDeps {
  homeDir: string;
  isInsideOsTrash: (p: string) => boolean;
  trashItem: (p: string) => Promise<void>;
  removeWorktree: (p: string) => Promise<void>;
  /** test seam: runs after each item has been handled (while later items are still pending) */
  afterItem?: (item: { path: string }) => void | Promise<void>;
  /** test seam: runs immediately before every unlink/rmdir */
  beforeUnlink?: (p: string) => void;
}

export interface ReapResult {
  schema: string;
  executed: boolean;
  partial: boolean;
  planSha256: string;
  removed: string[];
  failed: Array<{ path: string; error: string }>;
}

function judge(p: string, homeDir: string): void {
  const v = core.isProtectedPath(p, { homeDir, descendantOfJudged: true });
  if (v.protected) throw new Error(`protected_descendant:${v.reason}:${p}`);
}

/**
 * Remove a tree entry by entry with no-follow semantics. Every entry is re-judged immediately before
 * it is touched; symlinks are refused (never followed, never unlinked); directories are removed with a
 * NON-recursive rmdir, so an entry that appears after the listing makes the removal fail instead of
 * being swept away.
 */
function removeTreeNoFollow(full: string, deps: ExecutorDeps, top: boolean): void {
  const st = fs.lstatSync(full);
  if (st.isSymbolicLink()) throw new Error(`symlink_refused:${full}`);
  if (!top) judge(full, deps.homeDir);
  if (st.isDirectory()) {
    for (const name of fs.readdirSync(full)) removeTreeNoFollow(path.join(full, name), deps, false);
    deps.beforeUnlink?.(full);
    fs.rmdirSync(full);
  } else {
    deps.beforeUnlink?.(full);
    fs.unlinkSync(full);
  }
}

export async function executePlanItems(
  plan: RemediationPlan,
  identities: Record<string, ItemIdentity | null>,
  deps: ExecutorDeps
): Promise<ReapResult> {
  const removed: string[] = [];
  const failed: Array<{ path: string; error: string }> = [];
  for (const item of plan.items) {
    try {
      let st: fs.BigIntStats;
      try {
        st = fs.lstatSync(item.path, { bigint: true });
      } catch {
        failed.push({ path: item.path, error: "target_missing" });
        continue;
      }
      if (st.isSymbolicLink()) throw new Error("symlink_target_refused");
      const snap = identities[item.path];
      if (!snap || snap.dev !== st.dev.toString() || snap.ino !== st.ino.toString()) {
        throw new Error("identity_mismatch");
      }
      const prot = core.isProtectedPath(item.path, { homeDir: deps.homeDir });
      if (prot.protected) throw new Error(`protected_target:${prot.reason}`);
      if (st.isDirectory()) {
        const desc = core.findProtectedDescendant(item.path, { homeDir: deps.homeDir });
        if (desc.protected) throw new Error(desc.reason.startsWith("protected_descendant") ? desc.reason : `protected_descendant:${desc.reason}`);
      }
      if (item.kind === "git-worktree") {
        const blocked = await worktreePruneBlockReason(item.path);
        if (blocked) throw new Error(blocked);
        await deps.removeWorktree(item.path);
      } else if (deps.isInsideOsTrash(item.path)) {
        removeTreeNoFollow(item.path, deps, true);
      } else {
        await deps.trashItem(item.path);
      }
      removed.push(item.path);
    } catch (err) {
      failed.push({ path: item.path, error: err instanceof Error ? err.message : "remediation_failed" });
    }
    await deps.afterItem?.(item);
  }
  return {
    schema: "spacejanitor.reap.v1",
    executed: failed.length === 0 && removed.length > 0,
    partial: removed.length > 0 && failed.length > 0,
    planSha256: plan.planSha256,
    removed,
    failed,
  };
}
