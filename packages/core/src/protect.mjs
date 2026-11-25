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

function ask(candidatePath, { homeDir, descendants = false, timeoutMs, maxEntries } = {}) {
  if (typeof candidatePath !== "string" || candidatePath.trim() === "") return deny("empty_path");
  const args = ["protect", "--json"];
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
