import type { DiskConsumer } from "./types.js";

/**
 * The UI offers exactly what the main process's gate accepted. Items are `selectable` only when the
 * host annotated them as such; caches, protected items and anything not (yet) checked are listed as
 * blocked with a reason and get no checkbox.
 */
export interface CandidateLists {
  selectable: DiskConsumer[];
  blocked: DiskConsumer[];
}

type OrphanLike = {
  id: string;
  path: string;
  kind?: string;
  safeToPrune?: boolean;
  protected?: boolean;
  protectedReason?: string;
  selectable?: boolean;
  blockedReason?: string;
};

interface Input {
  cleanableCaches?: DiskConsumer[];
  trash?: { candidates?: DiskConsumer[] };
  orphans?: { candidates?: OrphanLike[] };
}

function classify(c: DiskConsumer, selectable: DiskConsumer[], blocked: DiskConsumer[]): void {
  if (c.selectable === true && !c.protected) {
    selectable.push(c);
  } else {
    blocked.push({ ...c, blockedReason: c.blockedReason || c.protectedReason || "not_checked_by_gate" });
  }
}

export function buildCandidateLists(summary: Input | null | undefined): CandidateLists {
  const selectable: DiskConsumer[] = [];
  const blocked: DiskConsumer[] = [];
  for (const c of summary?.cleanableCaches ?? []) classify(c, selectable, blocked);
  for (const c of summary?.trash?.candidates ?? []) classify(c, selectable, blocked);
  for (const o of summary?.orphans?.candidates ?? []) {
    if (!o.safeToPrune) continue;
    classify(
      {
        id: o.id,
        path: o.path,
        bytes: 0,
        kind: "git-worktree",
        protected: o.protected,
        protectedReason: o.protectedReason,
        selectable: o.selectable,
        blockedReason: o.blockedReason,
      },
      selectable,
      blocked
    );
  }
  return { selectable, blocked };
}
