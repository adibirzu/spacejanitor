const SHELL_META_RE = /[;|&$`<>\n\r\0]/;

export const ALLOWLISTED_IPC_METHODS = new Set([
  "summary",
  "doctor",
  "disk",
  "memory",
  "blockers",
  "orphans",
  "trash",
  "mcp-audit",
  "plan_reap",
  "execute_reap",
  "plan_cleanup",
  "execute_cleanup",
  "slm_get_config",
  "slm_update_config",
  "slm_explain",
]);

export function validateIpcMethod(method: string): boolean {
  return typeof method === "string" && ALLOWLISTED_IPC_METHODS.has(method);
}

export function validateTargetPath(rawPath: unknown): { valid: boolean; reason?: string; value?: string } {
  if (typeof rawPath !== "string") {
    return { valid: false, reason: "path_must_be_string" };
  }
  const trimmed = rawPath.trim();
  if (!trimmed) {
    return { valid: false, reason: "empty_path" };
  }
  if (SHELL_META_RE.test(trimmed)) {
    return { valid: false, reason: "shell_metacharacters_rejected" };
  }
  return { valid: true, value: trimmed };
}

export function isSafeNavigationUrl(rawUrl: string): boolean {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) return false;
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return false;
  }
  if (parsed.protocol === "file:") return true;
  if (
    parsed.protocol === "http:" &&
    (parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost")
  ) {
    return true;
  }
  return false;
}
