import { RemediationCandidate } from "./remediationGate";

/**
 * What the UI may offer for cleanup must be what the gate would accept. `annotateSummary` tags every
 * remediation candidate with `selectable` / `blockedReason`, taking the verdict from the Rust gate
 * (`sj protect`, batched). Cache directories are never planned by `sj plan`, so they are always shown as
 * not removable. Anything the gate could not judge is not selectable (fail closed).
 */

export type ProtectVerdict = { path: string; protected: boolean; reason: string };
export type ProtectFn = (paths: string[]) => ProtectVerdict[];

type Row = Record<string, unknown> & { path?: unknown };

const CACHE_BLOCKED_REASON = "not_planned_by_sj: cache directories cannot be removed from the desktop";

function verdictsFor(paths: string[], protect: ProtectFn): Map<string, ProtectVerdict> {
  const map = new Map<string, ProtectVerdict>();
  if (paths.length === 0) return map;
  let rows: ProtectVerdict[] = [];
  try {
    rows = protect(paths);
  } catch {
    rows = [];
  }
  for (const p of paths) {
    const hit = Array.isArray(rows) ? rows.find((r) => r && r.path === p) : undefined;
    map.set(p, hit ?? { path: p, protected: true, reason: "sj_unavailable" });
  }
  return map;
}

function tag(row: Row, verdict: ProtectVerdict | undefined): Row {
  if (verdict && !verdict.protected) return { ...row, selectable: true };
  return { ...row, selectable: false, blockedReason: verdict?.reason || "not_checked_by_gate" };
}

export function annotateSummary(summary: Record<string, unknown>, protect: ProtectFn): Record<string, unknown> {
  const out: Record<string, unknown> = { ...summary };

  if (Array.isArray(summary.cleanableCaches)) {
    out.cleanableCaches = (summary.cleanableCaches as Row[]).map((c) => ({
      ...c,
      selectable: false,
      blockedReason: CACHE_BLOCKED_REASON,
    }));
  }

  const trash = summary.trash as { candidates?: Row[] } | undefined;
  const orphans = summary.orphans as { candidates?: Row[] } | undefined;
  const trashRows = Array.isArray(trash?.candidates) ? (trash!.candidates as Row[]) : [];
  const orphanRows = Array.isArray(orphans?.candidates) ? (orphans!.candidates as Row[]) : [];
  const offered = [
    ...trashRows.map((r) => r.path),
    ...orphanRows.filter((r) => r.safeToPrune === true).map((r) => r.path),
  ].filter((p): p is string => typeof p === "string" && p !== "");
  const verdicts = verdictsFor([...new Set(offered)], protect);

  if (trash && Array.isArray(trash.candidates)) {
    out.trash = {
      ...trash,
      candidates: trashRows.map((r) => tag(r, typeof r.path === "string" ? verdicts.get(r.path) : undefined)),
    };
  }
  if (orphans && Array.isArray(orphans.candidates)) {
    out.orphans = {
      ...orphans,
      candidates: orphanRows.map((r) =>
        r.safeToPrune === true ? tag(r, typeof r.path === "string" ? verdicts.get(r.path) : undefined) : r
      ),
    };
  }
  return out;
}

/** The only candidates the main process will accept for a dry-run plan: selectable trash/orphans. */
export function approvedFromSummary(summary: Record<string, unknown>): RemediationCandidate[] {
  const trash = (summary.trash as { candidates?: Row[] } | undefined)?.candidates;
  const orphans = (summary.orphans as { candidates?: Row[] } | undefined)?.candidates;
  const rows: Row[] = [
    ...(Array.isArray(trash) ? trash : []),
    ...(Array.isArray(orphans) ? orphans.filter((o) => o.safeToPrune === true) : []),
  ];
  return rows
    .filter((r) => r.selectable === true && typeof r.path === "string" && r.path !== "" && r.protected !== true)
    .map((r) => ({
      id: String(r.id ?? r.path),
      path: String(r.path),
      bytes: Number(r.bytes) || 0,
      kind: (r.kind === "dir" || r.kind === "git-worktree" ? r.kind : "file") as RemediationCandidate["kind"],
    }));
}
