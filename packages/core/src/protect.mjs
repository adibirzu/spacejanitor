/**
 * Protected-path checks. There is NO denylist in JavaScript: every verdict is produced by the Rust
 * `sj protect` gate (crates/sj-core/src/protect.rs). This module only forwards a path to sj,
 * validates the reply and fails closed (protected: true) on anything it cannot prove.
 */
import { runSjSync } from "./sjGate.mjs";

const SCHEMA_PROTECT = "spacejanitor.protect.v1";

function deny(reason) {
  return { protected: true, reason };
}

// eslint-disable-next-line no-control-regex
const CONTROL_CHAR_RE = /[\u0000-\u001f\u007f]/;

function ask(
  candidatePath,
  { homeDir, descendants = false, timeoutMs, maxEntries, exactPaths, dynamicProtectedPaths, globPatterns } = {}
) {
  if (typeof candidatePath !== "string" || candidatePath.trim() === "") return deny("empty_path");
  // NUL cannot be passed as an argument at all and control characters are never legitimate: refuse early.
  if (CONTROL_CHAR_RE.test(candidatePath)) return deny("control_character_in_path");
  const args = ["protect", "--json"];
  for (const [flag, list] of [
    ["--exact", exactPaths],
    ["--dynamic", dynamicProtectedPaths],
    ["--glob", globPatterns],
  ]) {
    for (const v of Array.isArray(list) ? list : []) {
      if (typeof v !== "string" || v === "" || CONTROL_CHAR_RE.test(v)) return deny("invalid_custom_rule");
      args.push(`${flag}=${v}`);
    }
  }
  if (descendants) args.push("--descendants");
  if (maxEntries) args.push("--max-entries", String(maxEntries));
  args.push("--", candidatePath);
  let reply;
  try {
    reply = runSjSync(args, { homeDir, timeoutMs });
  } catch (err) {
    return deny(err && err.reason ? err.reason : "sj_unavailable");
  }
  const row = Array.isArray(reply.results) && reply.results.length === 1 ? reply.results[0] : null;
  if (
    reply.schema !== SCHEMA_PROTECT ||
    !row ||
    row.path !== candidatePath ||
    typeof row.protected !== "boolean"
  ) {
    return deny("sj_unparseable");
  }
  return { protected: row.protected, reason: row.protected ? String(row.reason || "protected") : "" };
}

/** Is this path protected? `homeDir` overrides the home the gate evaluates against (tests). */
export function isProtectedPath(candidatePath, options = {}) {
  return ask(candidatePath, options);
}

/**
 * Recursive removal deletes the whole subtree, so a directory is only as safe as its most protected
 * descendant. sj walks the tree without following symlinks and blocks on any protected entry,
 * symlink, unreadable directory or exceeded limit.
 */
export function findProtectedDescendant(dirPath, options = {}) {
  return ask(dirPath, { ...options, descendants: true });
}

/**
 * Judge many paths with ONE sj spawn (the read-only views annotate dozens of entries). Fails closed for
 * every path when sj is unavailable, slow or returns anything that does not line up.
 */
export function protectPaths(paths, options = {}) {
  const list = Array.isArray(paths) ? paths.map((p) => (typeof p === "string" ? p : "")) : [];
  const closed = (reason) => list.map((path) => ({ path, protected: true, reason }));
  if (list.length === 0) return [];
  if (list.some((p) => p.trim() === "" || CONTROL_CHAR_RE.test(p))) {
    // judge individually so the bad entries get their own reason and the rest are still answered
    return list.map((p) => ({ path: p, ...ask(p, options) }));
  }
  const { homeDir, timeoutMs } = options;
  let reply;
  try {
    reply = runSjSync(["protect", "--json", "--", ...list], { homeDir, timeoutMs });
  } catch (err) {
    return closed(err && err.reason ? err.reason : "sj_unavailable");
  }
  const rows = Array.isArray(reply.results) ? reply.results : null;
  if (reply.schema !== SCHEMA_PROTECT || !rows || rows.length !== list.length) return closed("sj_unparseable");
  const out = [];
  for (let i = 0; i < list.length; i += 1) {
    const row = rows[i];
    if (!row || row.path !== list[i] || typeof row.protected !== "boolean") return closed("sj_unparseable");
    out.push({ path: list[i], protected: row.protected, reason: row.protected ? String(row.reason || "protected") : "" });
  }
  return out;
}
