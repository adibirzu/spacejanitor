import crypto from "node:crypto";

const DEFAULT_TTL_MS = 5 * 60 * 1000;

/**
 * Create a deterministic dry-run remediation plan with SHA-256 digest and 5-minute TTL.
 * Protected paths are filtered out and recorded in blockedItems.
 */
export function createRemediationPlan(candidates = [], options = {}) {
  const { homeDir, nowMs = Date.now(), ttlMs = DEFAULT_TTL_MS, isProtectedFn } = options;
  const items = [];
  const blockedItems = [];

  for (const cand of candidates) {
    if (!cand || !cand.path) continue;
    const prot = isProtectedFn ? isProtectedFn(cand.path, { homeDir }) : { protected: false, reason: "" };
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
export function verifyRemediationGate({ plan, planSha256, phrase, nowMs = Date.now(), homeDir, isProtectedFn }) {
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
    const prot = isProtectedFn ? isProtectedFn(item.path, { homeDir }) : { protected: false, reason: "" };
    if (prot.protected) {
      return { allowed: false, reason: `protected_target_detected:${prot.reason}` };
    }
  }

  return { allowed: true, reason: "verified" };
}
