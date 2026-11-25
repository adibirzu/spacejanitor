"use strict";
/**
 * Post-pack gate (release workflow): the packaged app must contain the sj binary inside its own
 * resources (found by absolute path at runtime, never PATH), correct for the target.
 *   node scripts/verify-packaged-sj.cjs --platform linux|darwin|win32 --arch x64|arm64|universal [--smoke]
 */
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { assertSjBinary, exeName } = require("./sj-binary-check.cjs");

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}

function candidateBins(releaseDir, platform) {
  const out = [];
  for (const entry of fs.existsSync(releaseDir) ? fs.readdirSync(releaseDir, { withFileTypes: true }) : []) {
    if (!entry.isDirectory()) continue;
    const base = path.join(releaseDir, entry.name);
    if (platform === "darwin") {
      for (const app of fs.readdirSync(base, { withFileTypes: true })) {
        if (app.isDirectory() && app.name.endsWith(".app")) out.push(path.join(base, app.name, "Contents", "Resources", "bin", exeName(platform)));
      }
    } else if (entry.name.endsWith("-unpacked") || entry.name === "linux-unpacked" || entry.name === "win-unpacked") {
      out.push(path.join(base, "resources", "bin", exeName(platform)));
    }
  }
  return out;
}

function main() {
  const platform = arg("platform");
  const arch = arg("arch");
  if (!platform || !arch) throw new Error("usage: verify-packaged-sj.cjs --platform <p> --arch <a> [--smoke]");
  const releaseDir = path.resolve(__dirname, "..", "release");
  const wantDir = platform === "linux" ? (arch === "arm64" ? "linux-arm64-unpacked" : "linux-unpacked") : platform === "win32" ? (arch === "arm64" ? "win-arm64-unpacked" : "win-unpacked") : null;
  const bins = candidateBins(releaseDir, platform).filter((p) => !wantDir || p.includes(`${path.sep}${wantDir}${path.sep}`));
  if (bins.length === 0) throw new Error(`no packaged app resources found under ${releaseDir} for ${platform}-${arch}`);
  for (const bin of bins) {
    assertSjBinary(bin, platform, arch);
    console.log(`ok: ${bin}`);
    if (process.argv.includes("--smoke")) {
      const report = JSON.parse(execFileSync(bin, ["doctor", "--json"], { encoding: "utf8", timeout: 20000 }));
      if (report.schema !== "spacejanitor.doctor.v1" || report.engine !== "rust") throw new Error(`smoke: unexpected doctor output from ${bin}`);
      console.log(`smoke ok: sj ${report.version} ${report.os}/${report.arch}`);
    }
  }
}

main();
