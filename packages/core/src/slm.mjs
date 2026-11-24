const GIB = 1024 ** 3;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

function isPrivateLanIpv4(host) {
  const parts = host.split(".");
  if (parts.length !== 4) return false;
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = nums;
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  return false;
}

function isLanHostname(host) {
  const lower = host.toLowerCase();
  return lower.endsWith(".local") || lower.endsWith(".lan") || isPrivateLanIpv4(lower);
}

/**
 * Enforce loopback-only URL validation by default (ADR-005 / M6).
 * External cloud URLs are ALWAYS rejected; LAN URLs require explicit allowLan opt-in.
 */
export function validateLoopbackSlmUrl(rawUrl, { allowLan = false } = {}) {
  if (!rawUrl || typeof rawUrl !== "string") {
    return { allowed: false, reason: "empty_url" };
  }
  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    return { allowed: false, reason: "invalid_url" };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { allowed: false, reason: "unsupported_protocol" };
  }
  const host = parsed.hostname.toLowerCase();
  if (LOOPBACK_HOSTS.has(host)) {
    return { allowed: true, kind: "loopback", url: parsed.toString() };
  }
  if (isLanHostname(host)) {
    if (allowLan) {
      return { allowed: true, kind: "lan-opt-in", url: parsed.toString() };
    }
    return { allowed: false, reason: "lan_requires_explicit_opt_in" };
  }
  return { allowed: false, reason: "external_cloud_url_blocked" };
}

export function redactSlmPayload(value, redactFn) {
  if (typeof value === "string") return redactFn(value);
  if (Array.isArray(value)) return value.map((v) => redactSlmPayload(v, redactFn));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = redactSlmPayload(v, redactFn);
    }
    return out;
  }
  return value;
}

/**
 * On-demand local SLM advisor (strictly off by default, zero execution authority).
 */
export async function adviseWithLocalSlm({
  enabled = false,
  url = "http://127.0.0.1:11434/v1/chat/completions",
  allowLan = false,
  model = "qwen2.5:1.5b",
  summary,
  candidates = [],
  memoryReport,
  fetchImpl = globalThis.fetch,
  redactFn = (s) => s,
  isProtectedFn,
} = {}) {
  if (!enabled) {
    return {
      schema: "spacejanitor.proposal.v1",
      ok: false,
      reason: "slm_disabled",
      proposals: [],
    };
  }

  const urlCheck = validateLoopbackSlmUrl(url, { allowLan });
  if (!urlCheck.allowed) {
    return {
      schema: "spacejanitor.proposal.v1",
      ok: false,
      reason: urlCheck.reason,
      proposals: [],
    };
  }

  if (memoryReport && typeof memoryReport.freeBytes === "number" && memoryReport.freeBytes < 2.5 * GIB) {
    return {
      schema: "spacejanitor.proposal.v1",
      ok: false,
      reason: "memory_pressure_self_guard",
      proposals: [],
    };
  }

  const safePayload = redactSlmPayload({ summary, candidates }, redactFn);
  let res;
  try {
    res = await fetchImpl(urlCheck.url, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(15000),
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model,
        temperature: 0.1,
        messages: [
          {
            role: "system",
            content:
              "You are SpaceJanitor's read-only local cleanup advisor. Respond with concise JSON: { explanation: string, proposals: [{ target, category, safety_tier, rationale }] }. Never suggest deleting protected credential or system paths.",
          },
          { role: "user", content: JSON.stringify(safePayload) },
        ],
      }),
    });
  } catch (err) {
    return {
      schema: "spacejanitor.proposal.v1",
      ok: false,
      reason: err instanceof Error ? err.message : "slm_fetch_failed",
      proposals: [],
    };
  }

  if (!res.ok) {
    return {
      schema: "spacejanitor.proposal.v1",
      ok: false,
      reason: `slm_http_${res.status}`,
      proposals: [],
    };
  }

  const data = await res.json();
  const content = data?.choices?.[0]?.message?.content || "";
  let parsed = { explanation: content, proposals: [] };
  try {
    const maybe = JSON.parse(content);
    if (maybe && typeof maybe === "object") parsed = maybe;
  } catch {
    // keep plain-text explanation fallback
  }

  const proposals = Array.isArray(parsed.proposals)
    ? parsed.proposals.map((p) => {
        const target = String(p?.target || "");
        const prot = isProtectedFn ? isProtectedFn(target) : { protected: false };
        return {
          target,
          category: String(p?.category || "unknown"),
          safety_tier: prot.protected ? "keep_protected" : String(p?.safety_tier || "review"),
          rationale: redactFn(String(p?.rationale || "")),
          protectedBlocked: Boolean(prot.protected),
        };
      })
    : [];

  return {
    schema: "spacejanitor.proposal.v1",
    ok: true,
    explanation: redactFn(String(parsed.explanation || "")),
    proposals,
    executionAuthority: "none",
  };
}
