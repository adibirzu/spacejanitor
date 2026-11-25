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
]);

export function validateIpcMethod(method: string): boolean {
  return typeof method === "string" && ALLOWLISTED_IPC_METHODS.has(method);
}

export function sanitizeIpcParams(rawParams: unknown): Record<string, unknown> {
  if (!rawParams || typeof rawParams !== "object") return {};
  const params = { ...(rawParams as Record<string, unknown>) };
  delete params.configDirs;
  delete params.homeDir;
  delete params.isProtectedFn;
  delete params.redactFn;
  // orphan scanning is a main-process setting; a renderer can never opt itself in
  delete params.includeOrphans;
  return params;
}

export function isAuthorizedSenderFrame(
  frameUrl: string | undefined,
  allowedEntry: { devUrl?: string; indexPath?: string }
): boolean {
  if (!frameUrl || typeof frameUrl !== "string") return false;
  let parsed: URL;
  try {
    parsed = new URL(frameUrl);
  } catch {
    return false;
  }
  if (allowedEntry.devUrl) {
    try {
      const devParsed = new URL(allowedEntry.devUrl);
      return parsed.origin === devParsed.origin;
    } catch {
      return false;
    }
  }
  if (allowedEntry.indexPath && parsed.protocol === "file:") {
    const normalizedFrame = decodeURIComponent(parsed.pathname).replace(/\\/g, "/");
    const normalizedExpected = allowedEntry.indexPath.replace(/\\/g, "/");
    return normalizedFrame === normalizedExpected || normalizedFrame === `/${normalizedExpected}`;
  }
  return false;
}

export function validateTargetPath(rawPath: unknown): { valid: boolean; reason?: string; value?: string } {
  if (typeof rawPath !== "string") {
    return { valid: false, reason: "path_must_be_string" };
  }
  const trimmed = rawPath.trim();
  if (!trimmed) {
    return { valid: false, reason: "empty_path" };
  }
  if (trimmed.startsWith("-")) {
    return { valid: false, reason: "option_like_path_rejected" };
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
