"use strict";
/**
 * Electron >= 42 no longer downloads its binary in `postinstall`. Local runs (`npm start`) need it;
 * CI test jobs and electron-builder packaging do not (electron-builder fetches its own copy for the
 * pinned electronVersion), so ELECTRON_SKIP_BINARY_DOWNLOAD=1 keeps meaning "never download".
 */
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

function electronDir() {
  return path.dirname(require.resolve("electron/package.json", { paths: [path.resolve(__dirname, "..")] }));
}

function binaryInstalled() {
  const dir = electronDir();
  const pathTxt = path.join(dir, "path.txt");
  if (!fs.existsSync(pathTxt)) return false;
  return fs.existsSync(path.join(dir, "dist", fs.readFileSync(pathTxt, "utf8").trim()));
}

function ensureElectron({ env = process.env, run, installed = binaryInstalled } = {}) {
  if (env.ELECTRON_SKIP_BINARY_DOWNLOAD) return { action: "skipped" };
  if (installed()) return { action: "present" };
  (run || ((c) => {
    const r = spawnSync(process.execPath, [c], { stdio: "inherit" });
    if (r.status !== 0) throw new Error("electron binary download failed");
  }))(path.join(electronDir(), "install.js"));
  return { action: "downloaded" };
}

module.exports = { ensureElectron, binaryInstalled };

if (require.main === module) {
  const res = ensureElectron();
  console.log(`ensure-electron: ${res.action}`);
}
