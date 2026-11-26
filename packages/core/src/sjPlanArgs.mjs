/**
 * The ONE place that builds `sj plan` argument lists (desktop dry-run/execute, AXI CLI remediate).
 *
 * `sj plan` treats `--include-orphans` on its own as "orphans INSTEAD of trash" (the defaults only
 * apply when neither include flag is present), so the trash kind is always requested explicitly and
 * orphan scanning is only ever an extra on top of it. Orphans stay opt-in: pass includeOrphans only
 * when the user turned the scan on.
 *
 *   includeTrash  includeOrphans  result
 *   true          false           --include-trash                      (default, unchanged behaviour)
 *   true          true            --include-trash --include-orphans
 *   false         true            --include-orphans
 *   false         false           null  (nothing was selected: there is nothing to ask sj about)
 */
export function buildSjPlanArgs({ root, includeTrash = true, includeOrphans = false, includeLinux = false, ruleFlags = [], selects = [] } = {}) {
  if (!includeTrash && !includeOrphans && !includeLinux) return null;
  return [
    "plan",
    root,
    "--json",
    ...(includeTrash ? ["--include-trash"] : []),
    ...(includeOrphans ? ["--include-orphans"] : []),
    ...(includeLinux ? ["--include-linux"] : []),
    ...ruleFlags,
    ...selects.flatMap((p) => ["--select", p]),
  ];
}
