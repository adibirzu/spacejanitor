#!/usr/bin/env node
// Release tag parsing for .github/workflows/release.yml. Accepts only vX.Y.Z and vX.Y.Z-rc.N.
// Usage: node scripts/release-tag.mjs <tag> --package-version <x.y.z>
// Prints `prerelease=true|false` and `base=<x.y.z>` (append to $GITHUB_OUTPUT if desired); exits 1 on a bad tag or mismatch.
import { fileURLToPath } from "node:url";

const NUM = "(0|[1-9][0-9]*)";
const TAG = new RegExp(`^v(${NUM}\\.${NUM}\\.${NUM})(?:-rc\\.([1-9][0-9]*))?$`);

export function parseReleaseTag(tag) {
  const m = typeof tag === "string" ? TAG.exec(tag) : null; // regex has no /m flag; $ only matches at the very end
  if (!m || tag.includes("\n")) return { ok: false, error: `tag ${JSON.stringify(tag)} must look like v1.2.3 or v1.2.3-rc.1` };
  const rc = m[5] === undefined ? null : Number(m[5]);
  return { ok: true, base: m[1], prerelease: rc !== null, rc };
}

export function checkTagAgainstVersion(tag, packageVersion) {
  const t = parseReleaseTag(tag);
  if (!t.ok) return t;
  if (t.base !== packageVersion) {
    return { ok: false, error: `tag ${tag} (base ${t.base}) does not match apps/desktop/package.json version ${packageVersion}` };
  }
  return t;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const tag = args[0];
  const i = args.indexOf("--package-version");
  const pkg = i >= 0 ? (args[i + 1] ?? "") : undefined; // flag present without a value must fail, not skip the check
  const r = pkg === undefined ? parseReleaseTag(tag) : checkTagAgainstVersion(tag, pkg);
  if (!r.ok) {
    console.error(`ERROR: ${r.error}`);
    process.exit(1);
  }
  console.log(`prerelease=${r.prerelease}`);
  console.log(`base=${r.base}`);
}
