#!/usr/bin/env node
/**
 * SpaceJanitor OSS Hygiene Gate
 *
 * Scans workspace text files for accidental leakage of:
 *   - non-placeholder absolute user home paths (/Users/<user>, /home/<user>, C:\Users\<user>)
 *   - CGNAT / RFC1918 private IP addresses (outside loopback & RFC 5737 doc ranges)
 *   - common API key / token prefixes
 *   - optional external private blocklist terms (--extra-blocklist or OSS_HYGIENE_BLOCKLIST)
 */

import fs from "node:fs";
import path from "node:path";

const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "out",
  "target",
  "coverage",
  ".turbo",
]);

const SKIP_EXTS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".icns",
  ".woff",
  ".woff2",
  ".ttf",
  ".zip",
  ".gz",
  ".dmg",
  ".exe",
  ".msi",
  ".deb",
  ".rpm",
  ".AppImage",
]);

const ALLOWED_PLACEHOLDER_USERS = new Set([
  "alice",
  "bob",
  "developer",
  "user",
  "example",
  "runner",
  "runneradmin",
  "ubuntu",
  "vscode",
  "node",
  "appuser",
  "username",
]);

function buildCredentialPatterns() {
  return [
    { name: "stripe-live-key", re: new RegExp(["sk", "live", "[A-Za-z0-9]{12,}"].join("_")) },
    { name: "stripe-test-key", re: new RegExp(["sk", "test", "[A-Za-z0-9]{12,}"].join("_")) },
    { name: "github-classic-pat", re: new RegExp(["ghp", "[A-Za-z0-9]{20,}"].join("_")) },
    { name: "github-fine-pat", re: new RegExp(["github", "pat", "[A-Za-z0-9_]{20,}"].join("_")) },
    { name: "aws-access-key", re: new RegExp(["AKIA", "[0-9A-Z]{16}"].join("")) },
    { name: "slack-token", re: new RegExp(["xox[baprs]", "[0-9A-Za-z-]{10,}"].join("-")) },
    {
      name: "private-key-header",
      re: new RegExp(["-----BEGIN ", "(?:RSA |EC |OPENSSH |PGP )?", "PRIVATE KEY-----"].join("")),
    },
  ];
}

const CREDENTIAL_PATTERNS = buildCredentialPatterns();
const HOME_POSIX_RE = /(?<![A-Za-z0-9_])\/(?:Users|home)\/([A-Za-z0-9._-]+)/g;
const HOME_WIN_RE = /C:\\+Users\\+([A-Za-z0-9._-]+)/gi;
const IPV4_RE = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;

function isPrivateOrCgnatIp(a, b, c, d) {
  if (a > 255 || b > 255 || c > 255 || d > 255) return null;
  if (a === 127) return null; // loopback
  // RFC 5737 TEST-NET ranges are explicitly allowed for documentation
  if (a === 192 && b === 0 && c === 2) return null;
  if (a === 198 && b === 51 && c === 100) return null;
  if (a === 203 && b === 0 && c === 113) return null;

  if (a === 10) return "rfc1918-10";
  if (a === 192 && b === 168) return "rfc1918-192.168";
  if (a === 172 && b >= 16 && b <= 31) return "rfc1918-172.16";
  if (a === 100 && b >= 64 && b <= 127) return "cgnat-100.64";
  return null;
}

function loadExtraBlocklist(filePath) {
  if (!filePath) return [];
  const raw = fs.readFileSync(filePath, "utf8");
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((term) => term.toLowerCase());
}

function walkFiles(rootDir) {
  const out = [];
  const stack = [rootDir];
  while (stack.length > 0) {
    const curr = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(curr, { withFileTypes: true });
    } catch {
      continue;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const ent of entries) {
      if (ent.isSymbolicLink()) continue;
      const full = path.join(curr, ent.name);
      if (ent.isDirectory()) {
        if (!SKIP_DIRS.has(ent.name)) stack.push(full);
        continue;
      }
      if (ent.isFile()) {
        const ext = path.extname(ent.name).toLowerCase();
        if (!SKIP_EXTS.has(ext)) out.push(full);
      }
    }
  }
  return out.sort();
}

export function scanRepository({
  rootDir = process.cwd(),
  extraBlocklist = [],
} = {}) {
  const findings = [];
  const files = walkFiles(rootDir);

  for (const absPath of files) {
    const relPath = path.relative(rootDir, absPath).replace(/\\/g, "/");
    let buf;
    try {
      buf = fs.readFileSync(absPath);
    } catch {
      continue;
    }
    if (buf.includes(0)) continue; // binary file
    const text = buf.toString("utf8");
    const lines = text.split(/\r?\n/);

    const isTestFile = relPath.includes("/test/") || relPath.endsWith(".test.mjs");

    lines.forEach((line, idx) => {
      const lineNo = idx + 1;

      for (const match of line.matchAll(HOME_POSIX_RE)) {
        const user = match[1].toLowerCase();
        if (!ALLOWED_PLACEHOLDER_USERS.has(user)) {
          findings.push({
            file: relPath,
            line: lineNo,
            rule: "non-placeholder-home-path",
            detail: match[0],
          });
        }
      }

      for (const match of line.matchAll(HOME_WIN_RE)) {
        const user = match[1].toLowerCase();
        if (!ALLOWED_PLACEHOLDER_USERS.has(user)) {
          findings.push({
            file: relPath,
            line: lineNo,
            rule: "non-placeholder-windows-home",
            detail: match[0],
          });
        }
      }

      for (const match of line.matchAll(IPV4_RE)) {
        const kind = isPrivateOrCgnatIp(
          Number(match[1]),
          Number(match[2]),
          Number(match[3]),
          Number(match[4])
        );
        if (kind) {
          findings.push({
            file: relPath,
            line: lineNo,
            rule: `private-ip-${kind}`,
            detail: match[0],
          });
        }
      }

      if (!isTestFile) {
        for (const cp of CREDENTIAL_PATTERNS) {
          if (cp.re.test(line)) {
            findings.push({
              file: relPath,
              line: lineNo,
              rule: `credential-${cp.name}`,
              detail: "[redacted-match]",
            });
          }
        }
      }

      if (extraBlocklist.length > 0) {
        const low = line.toLowerCase();
        for (const term of extraBlocklist) {
          if (low.includes(term)) {
            findings.push({
              file: relPath,
              line: lineNo,
              rule: "extra-blocklist",
              detail: `matched term (${term.length} chars)`,
            });
          }
        }
      }
    });
  }

  return { filesScanned: files.length, findings };
}

function parseCliArgs(argv) {
  let rootDir = process.cwd();
  let extraBlocklistPath = process.env.OSS_HYGIENE_BLOCKLIST || "";
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--root" && argv[i + 1]) {
      rootDir = path.resolve(argv[i + 1]);
      i += 1;
    } else if (arg === "--extra-blocklist" && argv[i + 1]) {
      extraBlocklistPath = path.resolve(argv[i + 1]);
      i += 1;
    }
  }
  return { rootDir, extraBlocklistPath };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);
if (isMain) {
  const { rootDir, extraBlocklistPath } = parseCliArgs(process.argv.slice(2));
  const extraBlocklist = loadExtraBlocklist(extraBlocklistPath);
  const res = scanRepository({ rootDir, extraBlocklist });
  if (res.findings.length > 0) {
    console.error(`OSS hygiene check FAILED (${res.findings.length} finding(s) across ${res.filesScanned} files):`);
    for (const f of res.findings) {
      console.error(`  - ${f.file}:${f.line} [${f.rule}] ${f.detail}`);
    }
    process.exit(1);
  }
  console.log(`OSS hygiene check PASSED (${res.filesScanned} files scanned, 0 leaks).`);
}
