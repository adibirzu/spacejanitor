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
    "/System",
    "/.nofollow",
    "/.vol",
    "/.resolve",
    "/.file",
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
    "C:\\Program Files",
    "C:\\Program Files (x86)",
  ]),
  // Protected as the directory itself only (children are governed by the other rules).
  exactOnlyRoots: Object.freeze([
    "/Users",
    "/home",
    "/var",
    "/private",
    "/Volumes",
    "/mnt",
    "/srv",
    "/tmp",
    "C:/Users",
  ]),
  // Account roots whose children belong to some other user unless they sit under the current home.
  foreignHomeRoots: Object.freeze(["/Users", "/home", "C:/Users"]),
  // Explicit cache carve-outs inside otherwise blanket-protected home subtrees (Library, AppData).
  // Only these exact subtrees (and their children) may be offered for cleanup; every other path under
  // the blanket entry stays denied. Keep in sync with crates/sj-core/src/protect.rs.
  homeAllowSubpaths: Object.freeze([
    "Library/Caches/Homebrew",
    "Library/Caches/pip",
    "Library/Caches/pnpm",
    "AppData/Local/npm-cache",
    "AppData/Local/pip/Cache",
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
    "id_dsa*",
    "*.vmdk",
    "*.qcow2",
    "*.vhdx",
    "*.vdi",
    "*.raw",
    "*.img",
    "*/.sj-stage-*",
    // credential directories at any depth (mirrors the segment rule in crates/sj-core/src/protect.rs)
    "*/.ssh",
    "*/.gnupg",
    "*/.gnupg/*",
    "*/.aws",
    "*/.aws/*",
    "*/.kube",
    "*/.kube/*",
    "*/.config/gh",
    "*/.config/gh/*",
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

const DATA_VOLUME_RE = /^\/system\/volumes\/data(?=\/|$)/i;
const WIN_DRIVE_RE = /^[A-Za-z]:[\\/]/;

// Resolve a path the way the OS does: components left to right, a symlink is replaced by its
// target before a following ".." is applied (so "link/.." is the parent of the link TARGET).
// Nonexistent tails are appended lexically.
function resolveOsStyle(absPath, { strict = false } = {}) {
  const root = path.parse(absPath).root;
  const comps = absPath.slice(root.length).split(/[\\/]+/);
  let cur = root;
  let exists = true;
  for (const comp of comps) {
    if (!comp || comp === ".") continue;
    if (comp === "..") {
      cur = path.dirname(cur);
      continue;
    }
    const next = path.join(cur, comp);
    if (exists) {
      let present = true;
      try {
        fs.lstatSync(next);
      } catch {
        present = false;
        exists = false;
      }
      if (present) {
        try {
          cur = (fs.realpathSync.native || fs.realpathSync)(next);
        } catch {
          // dangling or looping symlink: the OS target is unknowable, so a candidate fails closed
          if (strict) throw new Error("unresolvable_path");
          cur = next;
        }
        continue;
      }
    }
    cur = next;
  }
  return cur;
}

function normalizePath(rawPath, homeDir = os.homedir(), { resolveSymlinks = true, strict = false } = {}) {
  const expanded = expandHome(String(rawPath).trim(), homeDir);
  if (!expanded) return "";
  let out;
  if (WIN_DRIVE_RE.test(expanded) && path.sep !== "\\") {
    // Windows-style absolute path on a POSIX host: normalise textually, never join with cwd.
    out = path.posix.normalize(expanded.replace(/\\/g, "/"));
  } else {
    const abs = path.isAbsolute(expanded) ? expanded : path.resolve(expanded);
    out = resolveSymlinks ? resolveOsStyle(abs, { strict }) : path.resolve(abs);
  }
  out = out.replace(/\\/g, "/").replace(/\/+$/, "") || "/";
  // macOS APFS Data volume is the same tree as "/": strip the alias (mirrors sj-core protect.rs).
  while (DATA_VOLUME_RE.test(out)) out = out.replace(DATA_VOLUME_RE, "") || "/";
  return out || "/";
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
  try {
    return evaluateProtection(candidatePath, options);
  } catch {
    // Fail closed: any unexpected error while judging a path means "protected".
    return { protected: true, reason: "protection_check_error" };
  }
}

function evaluateProtection(candidatePath, options = {}) {
  const raw = String(candidatePath || "").trim();
  if (/[\u0000-\u001f\u007f]/.test(raw)) {
    return { protected: true, reason: "control_character_in_path" };
  }
  if (!raw) {
    return { protected: true, reason: "empty_path" };
  }
  const homeDir = options.homeDir || os.homedir();
  const expanded = expandHome(raw, homeDir);
  if (!isAbsoluteInput(expanded)) {
    return { protected: true, reason: "relative_path_rejected" };
  }

  // A drive-letter path means nothing to a POSIX kernel (it is relative to the cwd), so it cannot be
  // judged lexically: fail closed unless the caller explicitly asks for Windows semantics.
  if (WIN_DRIVE_RE.test(expanded) && path.sep !== "\\" && !options.windowsSemantics) {
    return { protected: true, reason: "windows_path_on_posix_rejected" };
  }

  // Fail closed: ignore any caller attempt to make matching case-sensitive.
  const ci = true;
  const normalizedHome = normalizePath(homeDir, homeDir);
  const lexicalHome = normalizePath(homeDir, homeDir, { resolveSymlinks: false });
  const homes = [...new Set([normalizedHome, lexicalHome])];
  const homeParent = normalizePath(path.dirname(normalizedHome), homeDir, { resolveSymlinks: false });
  const realCand = normalizePath(raw, homeDir, { strict: true });
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
    // Root-level dot entries are filesystem aliases (/.nofollow, /.vol, /.resolve, ...): never a target.
    if (c.startsWith("/.")) {
      return { protected: true, reason: "protected_alias_root" };
    }
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
        // Carve-out: allowed only if EVERY form of the candidate (real and lexical) sits under an
        // allow-listed subtree. Allow roots are built textually from the home (never by resolving the
        // leaf), so a symlink inside an allowed cache cannot launder a sensitive target.
        const allowRoots = DEFAULT_PROTECTED_PATTERNS.homeAllowSubpaths
          .filter((a) => a.startsWith(`${sub}/`))
          .flatMap((a) => homes.map((hh) => `${hh}/${a}`.toLowerCase()));
        const allowed =
          allowRoots.length > 0 &&
          cands.every((c) => allowRoots.some((r) => isSameOrChild(c, r, true)));
        if (allowed) continue;
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
