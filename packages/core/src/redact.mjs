/**
 * Secret redaction shared by the core index, telemetry collectors and SLM payload filter.
 * Lives in its own module so telemetry can default to it (fail closed) without a circular import.
 */
const NAME_WORDS =
  "api[_-]?key|access[_-]?key|private[_-]?key|jwt|token|secret|passw(?:or)?d|passwd|pwd|pass|auth(?:orization)?|credentials?|bearer|cookie|signature|sig|session|pat|key";

function buildSecretMatchers() {
  const j = (...parts) => parts.join("");
  const vendorPrefixes = [
    j("sk", "-ant-", "[A-Za-z0-9_-]{8,}"),
    j("sk", "-proj-", "[A-Za-z0-9_-]{8,}"),
    j("sk", "_live_", "[A-Za-z0-9]{10,}"),
    j("sk", "_test_", "[A-Za-z0-9]{10,}"),
    j("sk", "-or-v1-", "[A-Za-z0-9]{16,}"),
    j("gs", "k_[A-Za-z0-9]{20,}"),
    j("nt", "n_[A-Za-z0-9]{20,}"),
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
    // userinfo runs to the LAST "@" of the authority (a password may itself contain "@")
    urlCredsRe: /([a-zA-Z][a-zA-Z0-9+.-]{0,31}:\/\/)[^\s/?#"']*@/g,
    urlQueryRe: new RegExp(`([?&;][A-Za-z0-9_.-]{0,64}(?:${NAME_WORDS}|code)=)[^&\\s'"]+`, "gi"),
    flagRe: new RegExp(
      `(-{1,2}[a-z0-9_-]{0,64}?(?:${NAME_WORDS})|-(?:t|p))(?:\\s+|=)(?:"[^"]*"|'[^']*'|[^\\s'"]+)`,
      "gi"
    ),
    userFlagRe: /(^|\s)(-u|--user|--proxy-user)(?:\s+|=)(?:"[^"]*"|'[^']*'|\S*:\S+)/g,
    // "Name: value" (HTTP header / YAML) consumes the rest of the line, so "Bearer x" and "token x" are covered.
    headerRe: new RegExp(
      `\\b([A-Za-z0-9_-]{0,64}(?:${NAME_WORDS})s?)(["']?\\s*:\\s*)(?!<REDACTED>)(?:"[^"]*"|'[^']*'|[^\\n\\r"']+)`,
      "gi"
    ),
    bearerRe: /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi,
    assignRe: new RegExp(
      `\\b([A-Za-z0-9_.-]{0,64}(?:${NAME_WORDS})s?)(["']?\\s*=\\s*)(?:"[^"]*"|'[^']*'|[^\\s'"&;]+)`,
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
    // attached short-flag credentials inside any string, token by token (shell strings, lone argv)
    .replace(/(^|\s)(-[ptu]\S+)/gi, (m, ws, tok) =>
      isAttachedShortCredential(tok) ? `${ws}${tok.slice(0, 2)}<REDACTED>` : m
    )
    // NAME=-pSECRET (env-style prefix, no whitespace before the flag), also right after a quote
    .replace(/(^|[\s'"])([A-Za-z_][A-Za-z0-9_]*=)(-[ptu]\S+)/g, (m, lead, name, tok) =>
      isAttachedShortCredential(tok) ? `${lead}${name}${tok.slice(0, 2)}<REDACTED>` : m
    )
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

// Words that merely START with p/t/u after a single dash and are ordinary flags, not credentials.
const KNOWN_SHORT_WORDS = new Set([
  "-transport", "-timeout", "-tls", "-tlsverify", "-url", "-update", "-path", "-port", "-tags", "-test",
  "-time", "-target", "-type", "-text", "-tree", "-pthread", "-print", "-prune", "-perm", "-user",
]);

/**
 * "-pSECRET" (mysql), "-tTOKEN", "-uadmin:SECRET", "-p-dashedSecret": an attached single-letter
 * credential flag. "-p=…"/"-p" alone are handled elsewhere; single-dash credential flag NAMES
 * (-token, -api-key) and well-known flag words (-timeout, -port, ...) are not values.
 */
function isAttachedShortCredential(tok) {
  const m = /^-([ptu])([^\s=].*)$/i.exec(tok);
  if (!m) return false;
  if (SINGLE_DASH_CRED_FLAG_RE.test(tok)) return false;
  return !KNOWN_SHORT_WORDS.has(tok.split("=")[0].toLowerCase());
}

const USER_FLAG_RE = /^(?:-u|--user|--proxy-user)$/i;
const CRED_FLAG_RE = new RegExp(`^(?:-{1,2}[a-z0-9_-]{0,64}?(?:${NAME_WORDS})|-t|-p)$`, "i");
// single-dash long flags (-token, -api-key, -Password): the credential word must start the flag or follow
// a delimiter, otherwise "-pSecretValue" (mysql attached password) would look like a flag name
const SINGLE_DASH_CRED_FLAG_RE = new RegExp(`^-(?:[a-z0-9]{1,32}[-_]){0,8}(?:${NAME_WORDS})$`, "i");
const CRED_FLAG_EQ_RE = new RegExp(
  `^(-(?:t|p|u)|--user|--proxy-user|-{1,2}[a-z0-9_-]{0,64}?(?:${NAME_WORDS}))=[\\s\\S]*$`,
  "i"
);
const CRED_ASSIGN_ARG_RE = new RegExp(`^([A-Za-z0-9_.-]{0,64}(?:${NAME_WORDS})s?)=[\\s\\S]*$`, "i");

/**
 * Redact an argv array while keeping argument boundaries. Decisions are made per ELEMENT, before any
 * joining, so a credential value containing spaces can never leak its tail:
 *  - a credential flag (incl. -u/--user, -p, -t) consumes the whole next element, or the whole
 *    remainder of a `--flag=value` element;
 *  - a `NAME=value` element with a credential-looking name is replaced whole;
 *  - any other element that contains whitespace/quotes/braces AND trips the generic redactor
 *    (JSON blobs, `user=a password="b c"` strings, ...) is replaced WHOLE, because partial
 *    pattern redaction of free text is exactly what leaks the tail.
 */
export function redactArgv(args) {
  const out = [];
  const list = Array.isArray(args) ? args.map(String) : [];
  for (let i = 0; i < list.length; i++) {
    const a = list[i];
    // attached short-flag credentials: -pSECRET (mysql), -tTOKEN, -uadmin:SECRET. Treated as
    // credential-bearing on purpose; false positives such as -p8080 are acceptable.
    if (isAttachedShortCredential(a)) {
      out.push(`${a.slice(0, 2)}<REDACTED>`);
      continue;
    }
    if (
      (a.startsWith("--") ? CRED_FLAG_RE.test(a) : a === "-t" || a === "-p" || SINGLE_DASH_CRED_FLAG_RE.test(a)) ||
      USER_FLAG_RE.test(a)
    ) {
      out.push(a);
      if (i + 1 < list.length && !list[i + 1].startsWith("--")) {
        out.push("<REDACTED>");
        i++;
      }
      continue;
    }
    const eq = a.match(CRED_FLAG_EQ_RE);
    if (eq) {
      out.push(`${eq[1]}=<REDACTED>`);
      continue;
    }
    const asg = !a.startsWith("-") && a.match(CRED_ASSIGN_ARG_RE);
    if (asg) {
      out.push(`${asg[1]}=<REDACTED>`);
      continue;
    }
    const generic = redactSecrets(a);
    if (generic !== a && /[\s"'{}\[\]]/.test(a)) {
      out.push("<REDACTED>");
      continue;
    }
    out.push(generic);
  }
  return out;
}
