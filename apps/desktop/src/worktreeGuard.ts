// eslint-disable-next-line @typescript-eslint/no-var-requires
const core = require("@spacejanitor/core");

/**
 * Last line of defence before `git worktree remove` (which permanently deletes ignored files):
 * re-prove at execution time that the worktree holds nothing unrecoverable. Returns null when safe,
 * otherwise a machine-readable reason. Anything that cannot be proven blocks.
 */
export async function worktreePruneBlockReason(
  worktreePath: string,
  options: { includeOrphans?: boolean } = {}
): Promise<string | null> {
  // OFF by default: no git is run against a repository we did not create unless explicitly enabled
  if (options.includeOrphans !== true) return "orphan_scan_disabled_by_default";
  try {
    const proof = await core.inspectWorktree(worktreePath, { includeOrphans: true });
    if (proof && proof.safeToPrune === true && proof.proofStatus === "verified") return null;
    if (!proof) return "worktree_proof_unavailable";
    if (proof.configRisk) return String(proof.configRisk);
    if (proof.locked) return "worktree_locked";
    if (proof.hasIgnored) return "worktree_has_ignored_files";
    if (proof.hasIndexFlags) return "worktree_index_flags_hide_changes";
    if (!proof.clean) return "worktree_not_clean";
    if (proof.hasStashes) return "worktree_has_stashes";
    if (proof.hasUnpushed) return "worktree_has_unpushed_commits";
    if (proof.detachedHead) return "worktree_detached_head";
    if (!proof.hasRemote) return "worktree_has_no_remote";
    return "worktree_not_provably_safe";
  } catch {
    return "worktree_proof_error";
  }
}

/** Remove a linked worktree via the main repository (explicit --git-dir/--work-tree, neutralised config). */
export async function removeWorktreeSafely(worktreePath: string, options: { includeOrphans?: boolean } = {}): Promise<void> {
  const res = await core.removeLinkedWorktree(worktreePath, { includeOrphans: options.includeOrphans === true });
  if (!res.ok) throw new Error(res.error || "worktree_remove_failed");
}
