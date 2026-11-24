import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  SCHEMA_VERSIONS_EXT,
  collectDoctor,
  collectDisk as _collectDisk,
  collectTrash,
  collectOrphans,
  collectMemory as _collectMemory,
  collectBlockers,
  collectMcpAudit as _collectMcpAudit,
  collectCleanableCaches as _collectCleanableCaches,
  collectSummary as _collectSummary,
  normalizeReportEnvelope,
} from "./telemetry.mjs";
import {
  createRemediationPlan as _createRemediationPlan,
  verifyRemediationGate as _verifyRemediationGate,
} from "./remediation.mjs";
import {
  validateLoopbackSlmUrl,
  redactSlmPayload as _redactSlmPayload,
  adviseWithLocalSlm as _adviseWithLocalSlm,
} from "./slm.mjs";
import { formatToon } from "./toon.mjs";

export const SCHEMA_VERSIONS = SCHEMA_VERSIONS_EXT;

export const DEFAULT_PROTECTED_PATTERNS = Object.freeze({
  exactRoots: Object.freeze([
    "/",
    "/System/Library",
    "/System/Applications",
    "/usr",
    "/etc",
    "/private/etc",
    "/Applications",
    "/Library",
    "/bin",
    "/sbin",
    "/opt",
    "/Windows",
    "/Program Files",
    "/Program Files (x86)",
    "C:\\",
    "C:\\Windows",
    "C:\\Users",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
  ]),
  homeSubpaths: Object.freeze([
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".config",
    ".config/gh",
    ".docker",
    ".netrc",
    "Documents",
    "Desktop",
    "Library",
  ]),
  globPatterns: Object.freeze([
    "*.private.*",
    "*/.ssh/*",
    "*/.gnupg/*",
  ]),
});

function expandHome(rawPath, homeDir = os.homedir()) {
  if (!rawPath) return "";
  if (rawPath === "~") return homeDir;
  if (rawPath.startsWith("~/") || rawPath.startsWith("~\\")) {
    return path.join(homeDir, rawPath.slice(2));
  }
  return rawPath;
}

function isAbsoluteInput(expanded) {
  return path.isAbsolute(expanded) || /^[A-Za-z]:[\\/]/.test(expanded);
}

function resolveRealWithAncestor(absPath) {
  const parts = [];
  let curr = absPath;
  while (curr && !fs.existsSync(curr)) {
    const parent = path.dirname(curr);
    if (parent === curr) break;
    parts.unshift(path.basename(curr));
    curr = parent;
  }
  let base = curr;
  if (curr && fs.existsSync(curr)) {
    try {
      base = fs.realpathSync(curr);
    } catch {
      base = curr;
    }
  }
  return parts.length > 0 ? path.join(base, ...parts) : base;
}

function normalizePath(rawPath, homeDir = os.homedir(), { resolveSymlinks = true } = {}) {
  const expanded = expandHome(String(rawPath).trim(), homeDir);
  if (!expanded) return "";
  const resolved = path.resolve(expanded);
  const real = resolveSymlinks ? resolveRealWithAncestor(resolved) : resolved;
  return real.replace(/\\/g, "/").replace(/\/+$/, "") || "/";
}

function pathKey(normPath, caseInsensitive) {
  return caseInsensitive ? normPath.toLowerCase() : normPath;
}

function isSameOrChild(cand, root, caseInsensitive) {
  const c = pathKey(cand, caseInsensitive);
  const r = pathKey(root, caseInsensitive);
  if (r === "/") return c === "/";
  return c === r || c.startsWith(`${r}/`);
}

function globToRegExp(globPattern) {
  const escaped = globPattern
    .replace(/\\/g, "/")
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i");
}

/**
 * Determine whether a candidate path is protected by built-in invariants or custom rules.
 * Built-in protected paths override all cleanup or plugin rules.
 */
export function isProtectedPath(candidatePath, options = {}) {
  const raw = String(candidatePath || "").trim();
  if (!raw) {
    return { protected: true, reason: "empty_path" };
  }
  const homeDir = options.homeDir || os.homedir();
  const expanded = expandHome(raw, homeDir);
  if (!isAbsoluteInput(expanded)) {
    return { protected: true, reason: "relative_path_rejected" };
  }

  const caseInsensitive =
    options.caseInsensitive ?? (process.platform === "darwin" || process.platform === "win32");
  const normalizedHome = normalizePath(homeDir, homeDir);
  const homeParent = normalizePath(path.dirname(normalizedHome), homeDir, { resolveSymlinks: false });
  const cand = normalizePath(raw, homeDir);
  if (!cand) {
    return { protected: true, reason: "empty_path" };
  }

  if (
    pathKey(cand, caseInsensitive) === "/" ||
    pathKey(cand, caseInsensitive) === pathKey(normalizedHome, caseInsensitive) ||
    pathKey(cand, caseInsensitive) === pathKey(homeParent, caseInsensitive) ||
    /^[a-z]:\/?$/i.test(cand)
  ) {
    return { protected: true, reason: "protected_root" };
  }

  for (const root of DEFAULT_PROTECTED_PATTERNS.exactRoots) {
    const normRoot = normalizePath(root, homeDir, { resolveSymlinks: false });
    if (normRoot === "/" || /^[a-z]:\/?$/i.test(normRoot)) continue;
    if (isSameOrChild(cand, normRoot, caseInsensitive)) {
      return { protected: true, reason: `protected_system:${root}` };
    }
  }

  for (const sub of DEFAULT_PROTECTED_PATTERNS.homeSubpaths) {
    const full = normalizePath(path.join(normalizedHome, sub), normalizedHome);
    if (isSameOrChild(cand, full, caseInsensitive)) {
      return { protected: true, reason: `protected_credential_store:~/${sub}` };
    }
  }

  for (const exact of options.exactPaths || []) {
    const normExact = normalizePath(exact, normalizedHome);
    if (normExact === "/" || pathKey(normExact, caseInsensitive) === pathKey(normalizedHome, caseInsensitive)) {
      if (pathKey(cand, caseInsensitive) === pathKey(normExact, caseInsensitive)) {
        return { protected: true, reason: `protected_exact:${exact}` };
      }
    } else if (isSameOrChild(cand, normExact, caseInsensitive)) {
      return { protected: true, reason: `protected_exact:${exact}` };
    }
  }

  for (const dyn of options.dynamicProtectedPaths || []) {
    const normDyn = normalizePath(dyn, normalizedHome);
    if (normDyn && normDyn !== "/" && pathKey(normDyn, caseInsensitive) !== pathKey(normalizedHome, caseInsensitive)) {
      if (isSameOrChild(cand, normDyn, caseInsensitive)) {
        return { protected: true, reason: `protected_dynamic:${dyn}` };
      }
    }
  }

  const allGlobs = [
    ...DEFAULT_PROTECTED_PATTERNS.globPatterns,
    ...(options.globPatterns || []),
  ];
  const base = path.posix.basename(cand);
  for (const pat of allGlobs) {
    const re = globToRegExp(pat);
    if (re.test(cand) || re.test(base)) {
      return { protected: true, reason: `protected_glob:${pat}` };
    }
  }

  return { protected: false, reason: "" };
}

function buildSecretMatchers() {
  const vendorPrefixes = [
    ["sk", "ant", "[A-Za-z0-9_-]{8,}"].join("-"),
    ["sk", "proj", "[A-Za-z0-9_-]{8,}"].join("-"),
    ["sk", "live", "[A-Za-z0-9]{10,}"].join("_"),
    ["sk", "test", "[A-Za-z0-9]{10,}"].join("_"),
    ["sk", "[A-Za-z0-9]{16,}"].join("-"),
    ["ghp", "[A-Za-z0-9]{12,}"].join("_"),
    ["github", "pat", "[A-Za-z0-9_]{12,}"].join("_"),
    ["glpat", "[A-Za-z0-9_-]{12,}"].join("-"),
    ["AKIA", "[0-9A-Z]{16}"].join(""),
    ["xox[baprs]", "[0-9A-Za-z-]{10,}"].join("-"),
  ];
  return {
    flagRe:
      /(--(?:[a-z0-9-]*?(?:api-?key|token|secret|password|key)|access-token|client-secret)|-(?:t|p))(?:\s+|=)(?:"([^"]*)"|'([^']*)'|([^\s'"]+))/gi,
    headerRe: /\b(Authorization:\s*(?:Bearer|Basic)|X-Api-Key:|X-Auth-Token:|Cookie:)\s*([^\n\r"']+)/gi,
    bearerRe: /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi,
    urlCredsRe: /([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^\s/@:]+):([^\s/@]+)@/g,
    urlQueryRe: /([?&](?:api_key|apikey|token|access_token|secret|password|key)=)([^&\s'"]+)/gi,
    envRe: /(\b[A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|PASS|AUTH)[A-Z0-9_]*=)(?:"([^"]*)"|'([^']*)'|([^\s'"]+))/g,
    vendorRe: new RegExp(`(?:${vendorPrefixes.join("|")})`, "g"),
  };
}

const SECRET_MATCHERS = buildSecretMatchers();

/**
 * Redact CLI credential arguments, HTTP headers, URL credentials/query params,
 * inline env vars, bearer tokens, and known API key shapes before reporting.
 */
export function redactSecrets(input) {
  if (typeof input !== "string" || !input) return "";
  return input
    .replace(SECRET_MATCHERS.urlCredsRe, "$1<REDACTED>:<REDACTED>@")
    .replace(SECRET_MATCHERS.urlQueryRe, "$1<REDACTED>")
    .replace(SECRET_MATCHERS.flagRe, "$1=<REDACTED>")
    .replace(SECRET_MATCHERS.headerRe, "$1 <REDACTED>")
    .replace(SECRET_MATCHERS.bearerRe, "$1 <REDACTED>")
    .replace(SECRET_MATCHERS.envRe, "$1<REDACTED>")
    .replace(SECRET_MATCHERS.vendorRe, "<REDACTED>");
}

export {
  collectDoctor,
  collectTrash,
  collectOrphans,
  collectBlockers,
  validateLoopbackSlmUrl,
  formatToon,
  normalizeReportEnvelope,
};

export function collectCleanableCaches(options = {}) {
  return _collectCleanableCaches({ ...options, isProtectedFn: isProtectedPath });
}

export function collectDisk(options = {}) {
  return _collectDisk({ ...options, isProtectedFn: isProtectedPath });
}

export function collectMemory(options = {}) {
  return _collectMemory({ ...options, redactFn: redactSecrets });
}

export function collectMcpAudit(options = {}) {
  return _collectMcpAudit({ ...options, redactFn: redactSecrets });
}

export function collectSummary(options = {}) {
  return _collectSummary({ ...options, isProtectedFn: isProtectedPath, redactFn: redactSecrets });
}

export function createRemediationPlan(candidates = [], options = {}) {
  return _createRemediationPlan(candidates, { ...options, isProtectedFn: isProtectedPath });
}

export function verifyRemediationGate(options = {}) {
  return _verifyRemediationGate({ ...options, isProtectedFn: isProtectedPath });
}

export function redactSlmPayload(value) {
  return _redactSlmPayload(value, redactSecrets);
}

export function adviseWithLocalSlm(options = {}) {
  return _adviseWithLocalSlm({ ...options, redactFn: redactSecrets, isProtectedFn: isProtectedPath });
}
