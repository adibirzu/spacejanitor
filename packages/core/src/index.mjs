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
  collectSummary as _collectSummary,
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
  exactRoots: Object.freeze(["/", "/System", "/Windows", "C:\\Windows"]),
  homeSubpaths: Object.freeze([
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".config/gh",
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

function normalizePath(rawPath, homeDir = os.homedir()) {
  const expanded = expandHome(String(rawPath).trim(), homeDir);
  if (!expanded) return "";
  return path.resolve(expanded).replace(/\\/g, "/");
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
  const homeDir = options.homeDir || os.homedir();
  const normalizedHome = normalizePath(homeDir, homeDir);
  const cand = normalizePath(candidatePath, homeDir);
  if (!cand) {
    return { protected: true, reason: "empty_path" };
  }

  if (cand === "/" || cand === normalizedHome) {
    return { protected: true, reason: "protected_root" };
  }

  for (const root of DEFAULT_PROTECTED_PATTERNS.exactRoots) {
    const normRoot = normalizePath(root, homeDir);
    if (normRoot === "/") continue;
    if (cand === normRoot || cand.startsWith(`${normRoot}/`)) {
      return { protected: true, reason: `protected_system:${root}` };
    }
  }

  for (const sub of DEFAULT_PROTECTED_PATTERNS.homeSubpaths) {
    const full = normalizePath(path.join(homeDir, sub), homeDir);
    if (cand === full || cand.startsWith(`${full}/`)) {
      return { protected: true, reason: `protected_credential_store:~/${sub}` };
    }
  }

  for (const exact of options.exactPaths || []) {
    const normExact = normalizePath(exact, homeDir);
    if (normExact === "/" || normExact === normalizedHome) {
      if (cand === normExact) {
        return { protected: true, reason: `protected_exact:${exact}` };
      }
    } else if (cand === normExact || cand.startsWith(`${normExact}/`)) {
      return { protected: true, reason: `protected_exact:${exact}` };
    }
  }

  for (const dyn of options.dynamicProtectedPaths || []) {
    const normDyn = normalizePath(dyn, homeDir);
    if (normDyn && normDyn !== "/" && normDyn !== normalizedHome) {
      if (cand === normDyn || cand.startsWith(`${normDyn}/`)) {
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
    ["sk", "live", "[A-Za-z0-9]{10,}"].join("_"),
    ["sk", "test", "[A-Za-z0-9]{10,}"].join("_"),
    ["ghp", "[A-Za-z0-9]{16,}"].join("_"),
    ["github", "pat", "[A-Za-z0-9_]{16,}"].join("_"),
    ["AKIA", "[0-9A-Z]{16}"].join(""),
    ["xox[baprs]", "[0-9A-Za-z-]{10,}"].join("-"),
  ];
  return {
    flagRe: /(--(?:api-key|token|secret|password|auth-token))(?:\s+|=)([^\s'"]+)/gi,
    bearerRe: /\b(Bearer)\s+[A-Za-z0-9._~+/=-]{12,}/gi,
    vendorRe: new RegExp(`(?:${vendorPrefixes.join("|")})`, "g"),
  };
}

const SECRET_MATCHERS = buildSecretMatchers();

/**
 * Redact CLI credential arguments, bearer tokens, and known API key shapes before reporting.
 */
export function redactSecrets(input) {
  if (typeof input !== "string" || !input) return "";
  return input
    .replace(SECRET_MATCHERS.flagRe, "$1=<REDACTED>")
    .replace(SECRET_MATCHERS.bearerRe, "$1 <REDACTED>")
    .replace(SECRET_MATCHERS.vendorRe, "<REDACTED>");
}

export { collectDoctor, collectTrash, collectOrphans, collectBlockers, validateLoopbackSlmUrl, formatToon };

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
