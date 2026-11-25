// eslint-disable-next-line @typescript-eslint/no-var-requires
const core = require("@spacejanitor/core");

/**
 * Last line of defence before `git worktree remove` (which permanently deletes ignored files):
 * re-prove at execution time that the worktree holds nothing unrecoverable. Returns null when safe,
 * otherwise a machine-readable reason. Anything that cannot be proven blocks.
 */
export async function worktreePruneBlockReason(worktreePath: string): Promise<string | null> {
  try {
    const proof = await core.inspectWorktree(worktreePath);
    if (proof && proof.safeToPrune === true && proof.proofStatus === "verified") return null;
    if (!proof) return "worktree_proof_unavailable";
    if (proof.hasIgnored) return "worktree_has_ignored_files";
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
