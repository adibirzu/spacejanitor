import { isProtectedPath } from "./protect.mjs";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// Fail closed: a throwing or non-conforming protection check counts as protected.
function safeProtected(fn, p, opts) {
  try {
    const r = fn(p, opts);
    if (r && typeof r === "object" && r.protected === false) return r;
    return { protected: true, reason: (r && r.reason) || "protection_check_failed" };
  } catch {
    return { protected: true, reason: "protection_check_error" };
  }
}

const DEFAULT_MAX_DESCENDANTS = 200000;

/**
 * Recursive removal deletes the whole subtree, so a candidate directory is only as safe as its most
 * protected descendant. Walk the subtree WITHOUT following symlinks and block when any entry is
 * protected, when any entry is a symlink, or when the walk cannot complete (fail closed).
 * Mirrors check_dir_descendants_safe in crates/sj-core/src/protect.rs.
 */
export function findProtectedDescendant(dirPath, options = {}) {
  const { homeDir, isProtectedFn = isProtectedPath, maxEntries = DEFAULT_MAX_DESCENDANTS } = options;
  let st;
  try {
    st = fs.lstatSync(dirPath);
  } catch {
    return { protected: false, reason: "" }; // nothing to walk (missing targets are reported elsewhere)
  }
  if (!st.isDirectory()) return { protected: false, reason: "" };
  let seen = 0;
  const stack = [dirPath];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return { protected: true, reason: `unreadable_directory:${dir}` };
    }
    for (const ent of entries) {
      seen += 1;
      if (seen > maxEntries) return { protected: true, reason: "descendant_check_limit_exceeded" };
      const full = path.join(dir, ent.name);
      if (ent.isSymbolicLink()) return { protected: true, reason: `symlink_descendant:${full}` };
      const prot = safeProtected(isProtectedFn, full, { homeDir, descendantOfJudged: true });
      if (prot.protected) return { protected: true, reason: `protected_descendant:${prot.reason}:${full}` };
      if (ent.isDirectory()) stack.push(full);
    }
  }
  return { protected: false, reason: "" };
}

const DEFAULT_TTL_MS = 5 * 60 * 1000;

/**
 * Create a deterministic dry-run remediation plan with SHA-256 digest and 5-minute TTL.
 * Protected paths are filtered out and recorded in blockedItems.
 */
export function createRemediationPlan(candidates = [], options = {}) {
  const { homeDir, nowMs = Date.now(), ttlMs = DEFAULT_TTL_MS, isProtectedFn = isProtectedPath } = options;
  const items = [];
  const blockedItems = [];

  for (const cand of candidates) {
    if (!cand || !cand.path) continue;
    let prot = safeProtected(isProtectedFn, cand.path, { homeDir });
    if (!prot.protected) {
      prot = findProtectedDescendant(cand.path, { homeDir, isProtectedFn });
    }
    if (prot.protected) {
      blockedItems.push({
        id: cand.id || cand.path,
        path: cand.path,
        bytes: Number(cand.bytes || 0),
        reason: prot.reason,
      });
    } else {
      items.push({
        id: cand.id || cand.path,
        path: cand.path,
        bytes: Number(cand.bytes || 0),
        kind: cand.kind || "file",
      });
    }
  }

  items.sort((a, b) => a.path.localeCompare(b.path));
  const nonce = crypto.randomBytes(16).toString("hex");
  const canonical = JSON.stringify({
    nonce,
    items: items.map((i) => [i.id, i.path, i.bytes, i.kind]),
  });
  const planSha256 = crypto.createHash("sha256").update(canonical).digest("hex");
  const totalBytes = items.reduce((acc, i) => acc + i.bytes, 0);

  return {
    schema: "spacejanitor.plan.v1",
    planId: planSha256,
    nonce,
    dryRun: true,
    items,
    blockedItems,
    totalBytes,
    planSha256,
    confirmationPhrase: `CONFIRM-${planSha256.slice(0, 8).toUpperCase()}`,
    createdAtMs: nowMs,
    expiresAtMs: nowMs + ttlMs,
  };
}

/**
 * Verify two-step remediation gate before any destructive execution.
 */
export function verifyRemediationGate({ plan, planSha256, phrase, nowMs = Date.now(), homeDir, isProtectedFn = isProtectedPath }) {
  if (!plan || !Array.isArray(plan.items) || plan.items.length === 0) {
    return { allowed: false, reason: "empty_or_missing_plan" };
  }
  if (!planSha256 || planSha256 !== plan.planSha256) {
    return { allowed: false, reason: "plan_sha256_mismatch" };
  }
  if (!phrase || phrase !== plan.confirmationPhrase) {
    return { allowed: false, reason: "confirmation_phrase_mismatch" };
  }
  if (typeof plan.expiresAtMs === "number" && nowMs > plan.expiresAtMs) {
    return { allowed: false, reason: "confirmation_token_expired" };
  }

  for (const item of plan.items) {
    let prot = safeProtected(isProtectedFn, item.path, { homeDir });
    if (!prot.protected) {
      prot = findProtectedDescendant(item.path, { homeDir, isProtectedFn });
    }
    if (prot.protected) {
      return { allowed: false, reason: `protected_target_detected:${prot.reason}` };
    }
  }

  return { allowed: true, reason: "verified" };
}
