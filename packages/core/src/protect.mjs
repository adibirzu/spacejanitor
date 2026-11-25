import fs from "node:fs";
import os from "node:os";
import path from "node:path";

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
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    "/lib",
    "/lib64",
    "/root",
    "/var/root",
    "/var/db",
    "/private/var/root",
    "/private/var/db",
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
  // Protected as the directory itself only (children are governed by the other rules).
  exactOnlyRoots: Object.freeze([
    "/System",
    "/Users",
    "/home",
    "/var",
    "/private",
    "/Volumes",
    "/mnt",
    "/srv",
    "/tmp",
  ]),
  // Account roots whose children belong to some other user unless they sit under the current home.
  foreignHomeRoots: Object.freeze(["/Users", "/home", "C:/Users"]),
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
    ".azure",
    ".oci",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".gitconfig",
    ".local/share/keyrings",
    ".password-store",
    ".1password",
    ".mozilla",
    ".terraform.d",
    ".claude",
    ".codex",
    ".zshrc",
    ".bashrc",
    ".bash_profile",
    ".zprofile",
    ".profile",
    "Pictures",
    "Movies",
    "Music",
    "AppData",
    "OneDrive",
  ]),
  globPatterns: Object.freeze([
    "*.private.*",
    "*/.ssh/*",
    "*/.gnupg/*",
    "*.pem",
    "*.p12",
    "*.pfx",
    "*.kdbx",
    "*.key",
    "*/.env",
    "*/.env.*",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
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
 * Matching is case-insensitive on every platform and checks both the symlink-resolved and the
 * lexical form of the candidate, so neither a symlink nor a case variant can slip past the denylist.
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

  // Fail closed: ignore any caller attempt to make matching case-sensitive.
  const ci = true;
  const normalizedHome = normalizePath(homeDir, homeDir);
  const lexicalHome = normalizePath(homeDir, homeDir, { resolveSymlinks: false });
  const homes = [...new Set([normalizedHome, lexicalHome])];
  const homeParent = normalizePath(path.dirname(normalizedHome), homeDir, { resolveSymlinks: false });
  const realCand = normalizePath(raw, homeDir);
  if (!realCand) {
    return { protected: true, reason: "empty_path" };
  }
  const cands = [...new Set([realCand, normalizePath(raw, homeDir, { resolveSymlinks: false })])];
  const eq = (a, b) => pathKey(a, ci) === pathKey(b, ci);
  const anyUnder = (root) => cands.some((c) => isSameOrChild(c, root, ci));
  const rootForms = (rootPath, base) => [
    ...new Set([
      normalizePath(rootPath, base),
      normalizePath(rootPath, base, { resolveSymlinks: false }),
    ]),
  ];

  for (const c of cands) {
    if (
      c === "/" ||
      homes.some((h) => eq(c, h)) ||
      eq(c, homeParent) ||
      /^[a-z]:\/?$/i.test(c) ||
      // every ancestor of the home directory is a home-root candidate
      homes.some((h) => isSameOrChild(h, c, ci))
    ) {
      return { protected: true, reason: "protected_root" };
    }
  }

  for (const root of DEFAULT_PROTECTED_PATTERNS.exactRoots) {
    const forms = rootForms(root, homeDir);
    if (forms.every((f) => f === "/" || /^[a-z]:\/?$/i.test(f))) continue;
    if (forms.some((f) => f !== "/" && !/^[a-z]:\/?$/i.test(f) && anyUnder(f))) {
      return { protected: true, reason: `protected_system:${root}` };
    }
  }

  for (const root of DEFAULT_PROTECTED_PATTERNS.exactOnlyRoots) {
    if (rootForms(root, homeDir).some((f) => cands.some((c) => eq(c, f)))) {
      return { protected: true, reason: `protected_system_root:${root}` };
    }
  }

  // Other accounts' homes are never ours to clean.
  for (const root of DEFAULT_PROTECTED_PATTERNS.foreignHomeRoots) {
    const forms = rootForms(root, homeDir);
    for (const c of cands) {
      const inForeignRoot = forms.some((f) => f !== "/" && isSameOrChild(c, f, ci));
      if (inForeignRoot && !homes.some((h) => isSameOrChild(c, h, ci))) {
        return { protected: true, reason: `protected_foreign_home:${root}` };
      }
    }
  }

  for (const sub of DEFAULT_PROTECTED_PATTERNS.homeSubpaths) {
    for (const h of homes) {
      const forms = [
        ...new Set([
          normalizePath(path.join(h, sub), h),
          normalizePath(path.join(h, sub), h, { resolveSymlinks: false }),
        ]),
      ];
      if (forms.some((f) => anyUnder(f))) {
        return { protected: true, reason: `protected_credential_store:~/${sub}` };
      }
    }
  }

  for (const exact of options.exactPaths || []) {
    const normExact = normalizePath(exact, normalizedHome);
    if (normExact === "/" || eq(normExact, normalizedHome)) {
      if (cands.some((c) => eq(c, normExact))) {
        return { protected: true, reason: `protected_exact:${exact}` };
      }
    } else if (anyUnder(normExact)) {
      return { protected: true, reason: `protected_exact:${exact}` };
    }
  }

  for (const dyn of options.dynamicProtectedPaths || []) {
    const normDyn = normalizePath(dyn, normalizedHome);
    if (normDyn && normDyn !== "/" && !eq(normDyn, normalizedHome)) {
      if (anyUnder(normDyn)) {
        return { protected: true, reason: `protected_dynamic:${dyn}` };
      }
    }
  }

  const allGlobs = [
    ...DEFAULT_PROTECTED_PATTERNS.globPatterns,
    ...(options.globPatterns || []),
  ];
  for (const c of cands) {
    const base = path.posix.basename(c);
    for (const pat of allGlobs) {
      const re = globToRegExp(pat);
      if (re.test(c) || re.test(base)) {
        return { protected: true, reason: `protected_glob:${pat}` };
      }
    }
  }

  return { protected: false, reason: "" };
}
