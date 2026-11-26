"use strict";
/**
 * Electron pin guard.
 *
 * electron-builder packages the Electron named by `electronVersion` in electron-builder.yml, NOT the
 * `electron` devDependency. If the two drift (a Dependabot bump touches only package.json/lockfile)
 * the installers silently ship the old runtime. This module makes that drift a hard failure and can
 * prove, from the packaged binary itself, which Electron actually shipped.
 *
 *   node scripts/electron-pin.cjs check
 */
const fs = require("node:fs");
const path = require("node:path");

const SCAN_CHUNK_BYTES = 8 * 1024 * 1024;
const MARKER = /Electron\/(\d+\.\d+\.\d+)(?![\d.])/g;
const EXACT_SEMVER = /^\d+\.\d+\.\d+$/;

function parsePin(yamlText) {
  const m = /^electronVersion:\s*["']?([^"'\s#]+)["']?/m.exec(yamlText);
  return m ? m[1] : null;
}

function major(v) {
  return String(v).split(".")[0];
}

function checkPin({ pin, declared, installed }) {
  const problems = [];
  if (!pin) {
    problems.push("electron-builder.yml has no electronVersion pin");
    return problems;
  }
  if (!EXACT_SEMVER.test(pin)) problems.push(`electronVersion pin ${pin} is not an exact version`);
  if (!declared || !EXACT_SEMVER.test(declared)) {
    problems.push(`apps/desktop devDependency electron ${declared} must be an exact version (no ^ or ~)`);
  } else if (declared !== pin) {
    problems.push(`electronVersion pin ${pin} differs from declared electron ${declared}: installers would ship the pin`);
  }
  if (installed) {
    if (major(installed) !== major(pin)) problems.push(`installed electron ${installed} major differs from pin ${pin}`);
    else if (installed !== pin) problems.push(`installed electron ${installed} differs from pin ${pin} (run npm ci)`);
  }
  return problems;
}

function installedVersion(desktopDir) {
  try {
    const p = require.resolve("electron/package.json", { paths: [desktopDir] });
    return JSON.parse(fs.readFileSync(p, "utf8")).version;
  } catch {
    return null;
  }
}

function checkRepo(desktopDir) {
  const pin = parsePin(fs.readFileSync(path.join(desktopDir, "electron-builder.yml"), "utf8"));
  const pkg = JSON.parse(fs.readFileSync(path.join(desktopDir, "package.json"), "utf8"));
  const declared = pkg.devDependencies && pkg.devDependencies.electron;
  const installed = installedVersion(desktopDir);
  return { pin, declared, installed, problems: checkPin({ pin, declared, installed }) };
}

/** Distinct Electron/<x.y.z> markers in a file, scanned in chunks with overlap (files are 100+ MB). */
function scanBinaryVersions(file) {
  const found = new Set();
  const fd = fs.openSync(file, "r");
  try {
    const overlap = 64;
    const buf = Buffer.alloc(SCAN_CHUNK_BYTES + overlap);
    let carry = 0;
    for (;;) {
      const n = fs.readSync(fd, buf, carry, SCAN_CHUNK_BYTES, null);
      const total = carry + n;
      const text = buf.toString("latin1", 0, total);
      for (const m of text.matchAll(MARKER)) {
        // A match touching the end of a non-final read may be cut mid-version (42.11.1 of 42.11.16): the
        // retained overlap re-reads it whole in the next round, so only record it when the file ended.
        if (n === 0 || m.index + m[0].length < total) found.add(m[1]);
      }
      if (n === 0) break;
      carry = Math.min(overlap, total);
      buf.copy(buf, 0, total - carry, total);
    }
  } finally {
    fs.closeSync(fd);
  }
  return [...found];
}

function assertPackagedElectron(files, expected) {
  for (const file of files) {
    if (!fs.existsSync(file)) throw new Error(`packaged Electron binary missing: ${file}`);
    const versions = scanBinaryVersions(file);
    if (versions.length === 0) throw new Error(`no Electron version marker in ${file}`);
    if (versions.some((v) => v !== expected)) {
      throw new Error(`packaged ${path.basename(file)} reports Electron ${versions.join(",")}, expected ${expected}`);
    }
  }
}

module.exports = { SCAN_CHUNK_BYTES, parsePin, checkPin, checkRepo, installedVersion, scanBinaryVersions, assertPackagedElectron };

if (require.main === module) {
  if (process.argv[2] !== "check") {
    console.error("usage: electron-pin.cjs check");
    process.exit(2);
  }
  const res = checkRepo(path.resolve(__dirname, ".."));
  if (res.problems.length) {
    for (const p of res.problems) console.error(`electron-pin: ${p}`);
    process.exit(1);
  }
  console.log(`electron-pin: ok (pin ${res.pin}, declared ${res.declared}, installed ${res.installed || "not installed"})`);
}
