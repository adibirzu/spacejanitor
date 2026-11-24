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
    widgets: Object.freeze([...(manifest.widgets || [])]),
  });
}
