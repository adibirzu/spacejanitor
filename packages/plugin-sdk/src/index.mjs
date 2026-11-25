import { isProtectedPath } from "../../core/src/index.mjs";

const VALID_CAPABILITIES = new Set([
  "rule-pack",
  "collector",
  "widget",
  "exporter",
]);

const PLUGIN_ID_RE = /^[a-z][a-z0-9-]{1,48}$/;

/**
 * Validate and normalize a SpaceJanitor plugin manifest (ADR-003).
 */
export function definePlugin(manifest) {
  if (!manifest || typeof manifest !== "object") {
    throw new TypeError("Plugin manifest must be an object.");
  }
  if (!PLUGIN_ID_RE.test(String(manifest.id || ""))) {
    throw new RangeError("Plugin id must match ^[a-z][a-z0-9-]{1,48}$.");
  }
  if (String(manifest.apiVersion || "") !== "1") {
    throw new RangeError('Plugin apiVersion must be "1".');
  }
  if (!Array.isArray(manifest.capabilities) || manifest.capabilities.length === 0) {
    throw new RangeError("Plugin must declare at least one capability.");
  }
  for (const cap of manifest.capabilities) {
    if (!VALID_CAPABILITIES.has(cap)) {
      throw new RangeError(`Unsupported plugin capability: ${String(cap)}`);
    }
  }
  return Object.freeze({
    id: manifest.id,
    version: String(manifest.version || "0.1.0"),
    apiVersion: "1",
    capabilities: Object.freeze([...manifest.capabilities]),
    rules: Object.freeze([...(manifest.rules || [])]),
    collectors: Object.freeze([...(manifest.collectors || [])]),
    widgets: Object.freeze([...(manifest.widgets || [])]),
    exporters: Object.freeze([...(manifest.exporters || [])]),
  });
}

/**
 * Validate every rule in a plugin against @spacejanitor/core immutable protected paths (FR-4.5).
 */
export function validatePluginRules(plugin, options = {}) {
  const allowedRules = [];
  const rejectedRules = [];

  for (const rule of plugin?.rules || []) {
    const paths = Array.isArray(rule?.paths) ? rule.paths : [];
    let blockedReason = "";
    for (const p of paths) {
      const check = isProtectedPath(p, options);
      if (check.protected) {
        blockedReason = check.reason;
        break;
      }
    }
    if (blockedReason) {
      rejectedRules.push({
        ruleId: String(rule?.id || "unknown"),
        reason: blockedReason,
      });
    } else {
      allowedRules.push(rule);
    }
  }

  return { allowedRules, rejectedRules };
}
