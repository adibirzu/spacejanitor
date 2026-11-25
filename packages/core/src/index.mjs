import {
  SCHEMA_VERSIONS_EXT,
  collectDoctor,
  collectDisk as _collectDisk,
  collectTrash,
  collectOrphans,
  ORPHAN_SCAN_WARNING,
  ORPHAN_SCAN_DISABLED_MESSAGE,
  collectMemory as _collectMemory,
  collectBlockers,
  collectMcpAudit as _collectMcpAudit,
  collectCleanableCaches as _collectCleanableCaches,
  collectSummary as _collectSummary,
  normalizeReportEnvelope,
} from "./telemetry.mjs";
import {
  validateLoopbackSlmUrl,
  redactSlmPayload as _redactSlmPayload,
  adviseWithLocalSlm as _adviseWithLocalSlm,
} from "./slm.mjs";
import { formatToon } from "./toon.mjs";
import { redactSecrets, redactArgv } from "./redact.mjs";
import { findProtectedDescendant, isProtectedPath, protectPaths } from "./protect.mjs";
import {
  SjGateError,
  activeSjBinary,
  configureSjBinary,
  resolveSjBinary,
  runSj,
  runSjSync,
  sjBinaryProblem,
} from "./sjGate.mjs";

export const SCHEMA_VERSIONS = SCHEMA_VERSIONS_EXT;

export { findProtectedDescendant, isProtectedPath, protectPaths };
export { SjGateError, activeSjBinary, configureSjBinary, resolveSjBinary, runSj, runSjSync, sjBinaryProblem };
export { redactSecrets, redactArgv };

export {
  collectDoctor,
  collectTrash,
  collectOrphans,
  ORPHAN_SCAN_WARNING,
  ORPHAN_SCAN_DISABLED_MESSAGE,
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

export function redactSlmPayload(value) {
  return _redactSlmPayload(value, redactSecrets);
}

export function adviseWithLocalSlm(options = {}) {
  return _adviseWithLocalSlm({ ...options, redactFn: redactSecrets, isProtectedFn: isProtectedPath });
}
