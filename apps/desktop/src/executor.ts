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
  /** orphan/worktree removal runs git in repositories we did not create: OFF unless this returns true */
  orphanScanEnabled?: () => boolean;
  /** test seam: runs after each item has been handled (while later items are still pending) */
  afterItem?: (item: { path: string }) => void | Promise<void>;
  /** test seam: runs immediately before every unlink/rmdir */
  beforeUnlink?: (p: string) => void;
  /** filled by the walk: every entry actually unlinked/rmdir'd, so a mid-walk failure can report it honestly */
  deleted?: string[];
  /** test seam: runs right after a directory has been listed, before its children are touched */
  afterReaddir?: (dir: string) => void;
}

export interface ReapResult {
  schema: string;
  executed: boolean;
  partial: boolean;
  planSha256: string;
  removed: string[];
  failed: Array<{ path: string; error: string; partiallyRemoved?: string[] }>;
}

function judge(p: string, homeDir: string): void {
  const v = core.isProtectedPath(p, { homeDir, descendantOfJudged: true });
  if (v.protected) throw new Error(`protected_descendant:${v.reason}:${p}`);
}

function sameDir(p: string, id: { dev: bigint; ino: bigint }): void {
  let st: fs.BigIntStats;
  try {
    st = fs.lstatSync(p, { bigint: true });
  } catch {
    throw new Error(`directory_swapped:${p}`);
  }
  if (st.isSymbolicLink() || !st.isDirectory() || st.dev !== id.dev || st.ino !== id.ino) {
    throw new Error(`directory_swapped:${p}`);
  }
}

/**
 * Remove a tree entry by entry with no-follow semantics. Every entry is re-judged immediately before
 * it is touched; symlinks are refused (never followed, never unlinked); directories are removed with a
 * NON-recursive rmdir, so an entry that appears after the listing makes the removal fail instead of
 * being swept away. Each directory's device/inode is recorded when it is listed and re-checked before
 * every child operation, so a parent swapped for a symlink mid-walk is detected instead of followed.
 * Residual: Node has no openat(), so a swap in the instant between that re-check and the syscall
 * cannot be excluded; the fd-relative Rust safe_remove is the complete fix (see PR notes).
 */
function removeTreeNoFollow(full: string, deps: ExecutorDeps, top: boolean, expected?: { dev: bigint; ino: bigint }): void {
  const st = fs.lstatSync(full, { bigint: true });
  if (st.isSymbolicLink()) throw new Error(`symlink_refused:${full}`);
  if (expected && (st.dev !== expected.dev || st.ino !== expected.ino)) throw new Error(`directory_swapped:${full}`);
  if (!top) judge(full, deps.homeDir);
  const id = { dev: st.dev, ino: st.ino };
  if (st.isDirectory()) {
    const names = fs.readdirSync(full);
    deps.afterReaddir?.(full);
    for (const name of names) {
      sameDir(full, id);
      const child = path.join(full, name);
      const cst = fs.lstatSync(child, { bigint: true });
      if (cst.isDirectory() && !cst.isSymbolicLink()) {
        removeTreeNoFollow(child, deps, false, { dev: cst.dev, ino: cst.ino });
      } else {
        sameDir(full, id);
        removeTreeNoFollow(child, deps, false);
      }
    }
    sameDir(full, id);
    deps.beforeUnlink?.(full);
    fs.rmdirSync(full);
    deps.deleted?.push(full);
  } else {
    deps.beforeUnlink?.(full);
    fs.unlinkSync(full);
    deps.deleted?.push(full);
  }
}

export async function executePlanItems(
  plan: RemediationPlan,
  identities: Record<string, ItemIdentity | null>,
  deps: ExecutorDeps
): Promise<ReapResult> {
  const removed: string[] = [];
  const failed: Array<{ path: string; error: string; partiallyRemoved?: string[] }> = [];
  for (const item of plan.items) {
    const deleted: string[] = [];
    const itemDeps: ExecutorDeps = { ...deps, deleted };
    try {
      if (item.kind === "git-worktree" && deps.orphanScanEnabled?.() !== true) {
        throw new Error("orphan_scanning_disabled");
      }
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
        const blocked = await worktreePruneBlockReason(item.path, { includeOrphans: true });
        if (blocked) throw new Error(blocked);
        await deps.removeWorktree(item.path);
      } else if (deps.isInsideOsTrash(item.path)) {
        removeTreeNoFollow(item.path, itemDeps, true);
      } else {
        await deps.trashItem(item.path);
      }
      removed.push(item.path);
    } catch (err) {
      failed.push({
        path: item.path,
        error: err instanceof Error ? err.message : "remediation_failed",
        // honest partial outcome: what the walk really deleted before it stopped
        ...(deleted.length ? { partiallyRemoved: deleted } : {}),
      });
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
