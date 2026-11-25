import {
  SCHEMA_VERSIONS_EXT,
  collectDoctor,
  collectDisk as _collectDisk,
  collectTrash,
  collectOrphans,
  inspectWorktree,
  removeLinkedWorktree,
  classifyExecutableConfigKey,
  collectMemory as _collectMemory,
  collectBlockers,
  collectMcpAudit as _collectMcpAudit,
  collectCleanableCaches as _collectCleanableCaches,
  collectSummary as _collectSummary,
  normalizeReportEnvelope,
} from "./telemetry.mjs";
import {
  findProtectedDescendant as _findProtectedDescendant,
  createRemediationPlan as _createRemediationPlan,
  verifyRemediationGate as _verifyRemediationGate,
} from "./remediation.mjs";
import {
  validateLoopbackSlmUrl,
  redactSlmPayload as _redactSlmPayload,
  adviseWithLocalSlm as _adviseWithLocalSlm,
} from "./slm.mjs";
import { formatToon } from "./toon.mjs";
import { redactSecrets, redactArgv } from "./redact.mjs";
import { DEFAULT_PROTECTED_PATTERNS, isProtectedPath } from "./protect.mjs";

export const SCHEMA_VERSIONS = SCHEMA_VERSIONS_EXT;

export { DEFAULT_PROTECTED_PATTERNS, isProtectedPath };
export { redactSecrets, redactArgv };

export {
  inspectWorktree,
  removeLinkedWorktree,
  classifyExecutableConfigKey,
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

export function findProtectedDescendant(dirPath, options = {}) {
  return _findProtectedDescendant(dirPath, { ...options, isProtectedFn: isProtectedPath });
}
