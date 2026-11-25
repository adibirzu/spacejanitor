/**
 * Secret redaction shared by the core index, telemetry collectors and SLM payload filter.
 * Lives in its own module so telemetry can default to it (fail closed) without a circular import.
 */
const NAME_WORDS =
  "api[_-]?key|access[_-]?key|private[_-]?key|token|secret|passw(?:or)?d|passwd|pwd|pass|auth(?:orization)?|credentials?|bearer|cookie|signature|sig|session|pat|key";

function buildSecretMatchers() {
  const j = (...parts) => parts.join("");
  const vendorPrefixes = [
    j("sk", "-ant-", "[A-Za-z0-9_-]{8,}"),
    j("sk", "-proj-", "[A-Za-z0-9_-]{8,}"),
    j("sk", "_live_", "[A-Za-z0-9]{10,}"),
    j("sk", "_test_", "[A-Za-z0-9]{10,}"),
    j("sk", "-[A-Za-z0-9]{16,}"),
    j("gh", "[pousr]_[A-Za-z0-9]{12,}"),
    j("github", "_pat_", "[A-Za-z0-9_]{12,}"),
    j("glpat", "-[A-Za-z0-9_-]{12,}"),
    j("AK", "IA[0-9A-Z]{16}"),
    j("AS", "IA[0-9A-Z]{16}"),
    j("xox[baprs]", "-[0-9A-Za-z-]{10,}"),
    j("np", "m_[A-Za-z0-9]{20,}"),
    j("AI", "za[0-9A-Za-z_-]{30,}"),
    j("h", "f_[A-Za-z0-9]{20,}"),
    j("S", "G\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"),
    j("ey", "J[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]*"),
  ];
  const pemBegin = ["-----BEGIN", " [A-Z ]*PRIVATE", " KEY-----"].join("");
  const pemEnd = ["-----END", " [A-Z ]*PRIVATE", " KEY-----"].join("");
  return {
    pemRe: new RegExp(`${pemBegin}[\\s\\S]*?(?:${pemEnd}|$)`, "g"),
    urlCredsRe: /([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)[^\s/@?#"']+@/g,
    urlQueryRe: new RegExp(`([?&;][A-Za-z0-9_.-]*(?:${NAME_WORDS})=)[^&\\s'"]+`, "gi"),
    flagRe: new RegExp(
      `(--[a-z0-9-]*?(?:${NAME_WORDS})|-(?:t|p))(?:\\s+|=)(?:"[^"]*"|'[^']*'|[^\\s'"]+)`,
      "gi"
    ),
    userFlagRe: /(^|\s)(-u|--user|--proxy-user)(?:\s+|=)(?:"[^"]*"|'[^']*'|\S*:\S+)/g,
    // "Name: value" (HTTP header / YAML) consumes the rest of the line, so "Bearer x" and "token x" are covered.
    headerRe: new RegExp(
      `\\b([A-Za-z0-9_-]*(?:${NAME_WORDS})s?)(\\s*:\\s*)(?!<REDACTED>)[^\\n\\r"']+`,
      "gi"
    ),
    bearerRe: /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi,
    assignRe: new RegExp(
      `\\b([A-Za-z0-9_.-]*(?:${NAME_WORDS})s?)(\\s*=\\s*)(?:"[^"]*"|'[^']*'|[^\\s'"&;]+)`,
      "gi"
    ),
    vendorRe: new RegExp(`(?:${vendorPrefixes.join("|")})`, "g"),
  };
}

const M = buildSecretMatchers();

/**
 * Redact CLI credential arguments, HTTP headers, URL credentials/query params,
 * inline assignments, bearer tokens, PEM private keys, JWTs and known API key shapes.
 */
export function redactSecrets(input) {
  if (typeof input !== "string" || !input) return "";
  return input
    .replace(M.pemRe, "<REDACTED>")
    .replace(M.urlCredsRe, "$1<REDACTED>@")
    .replace(M.urlQueryRe, "$1<REDACTED>")
    .replace(M.userFlagRe, "$1$2 <REDACTED>")
    .replace(M.flagRe, (_m, flag) => `${flag}=<REDACTED>`)
    .replace(M.headerRe, "$1$2<REDACTED>")
    .replace(M.bearerRe, "$1 <REDACTED>")
    .replace(M.assignRe, "$1$2<REDACTED>")
    .replace(M.vendorRe, "<REDACTED>");
}
