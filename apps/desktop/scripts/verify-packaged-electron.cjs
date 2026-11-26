"use strict";
/**
 * Post-pack gate: prove from the packaged binary itself (not from config) which Electron shipped, and
 * optionally start the packaged app and probe it over the DevTools protocol.
 *   node scripts/verify-packaged-electron.cjs --platform darwin|linux|win32 [--probe]
 * Expected version = the electron-builder.yml pin.
 */
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { parsePin, assertPackagedElectron } = require("./electron-pin.cjs");

const desktopDir = path.resolve(__dirname, "..");
const releaseDir = path.join(desktopDir, "release");

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}

function macApps() {
  const out = [];
  for (const e of fs.existsSync(releaseDir) ? fs.readdirSync(releaseDir, { withFileTypes: true }) : []) {
    if (!e.isDirectory()) continue;
    for (const a of fs.readdirSync(path.join(releaseDir, e.name), { withFileTypes: true })) {
      if (a.isDirectory() && a.name.endsWith(".app")) out.push(path.join(releaseDir, e.name, a.name));
    }
  }
  return out;
}

/** Binaries that carry the Electron version marker, one set per packaged app. */
function electronBinaries(platform) {
  if (platform === "darwin") {
    return macApps().map((app) => path.join(app, "Contents", "Frameworks", "Electron Framework.framework", "Versions", "A", "Electron Framework"));
  }
  const out = [];
  for (const e of fs.existsSync(releaseDir) ? fs.readdirSync(releaseDir, { withFileTypes: true }) : []) {
    if (!e.isDirectory() || !e.name.endsWith("-unpacked")) continue;
    const dir = path.join(releaseDir, e.name);
    const files = fs.readdirSync(dir, { withFileTypes: true }).filter((f) => f.isFile()).map((f) => ({ p: path.join(dir, f.name), size: fs.statSync(path.join(dir, f.name)).size }));
    files.sort((a, b) => b.size - a.size);
    if (files.length && files[0].size > 50 * 1024 * 1024) out.push(files[0].p);
  }
  return out;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function probe(app, expected) {
  const exe = path.join(app, "Contents", "MacOS", fs.readdirSync(path.join(app, "Contents", "MacOS"))[0]);
  const port = 9300 + Math.floor(Math.random() * 500);
  const child = spawn(exe, [`--remote-debugging-port=${port}`], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ELECTRON_ENABLE_LOGGING: "1" } });
  let log = "";
  let exited = null;
  child.stdout.on("data", (d) => (log += d));
  child.stderr.on("data", (d) => (log += d));
  child.on("exit", (c, s) => (exited = { c, s }));
  const result = {};
  try {
    let targets;
    for (let i = 0; i < 60 && !exited; i++) {
      try {
        targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
        if (targets.find((t) => t.type === "page")) break;
      } catch { /* not up yet */ }
      await sleep(500);
    }
    const page = targets && targets.find((t) => t.type === "page");
    if (!page) throw new Error(`no window created; output:\n${log}`);
    const version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
    result.runtime = version.Browser;
    if (!String(version["User-Agent"]).includes(`Electron/${expected}`)) throw new Error(`runtime reports ${version["User-Agent"]}, expected Electron/${expected}`);
    const ws = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
    let id = 0;
    const pend = new Map();
    ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && pend.has(m.id)) { pend.get(m.id)(m); pend.delete(m.id); } };
    const ev = (expression) => new Promise((r) => { const i = ++id; pend.set(i, r); ws.send(JSON.stringify({ id: i, method: "Runtime.evaluate", params: { expression, awaitPromise: true, returnByValue: true } })); }).then((m) => m.result && m.result.result && m.result.result.value);
    await sleep(2500);
    result.preload = await ev("typeof window.spaceJanitor");
    if (result.preload !== "object") throw new Error("preload bridge window.spaceJanitor missing");
    result.isolated = await ev("typeof require + '/' + typeof process");
    if (result.isolated !== "undefined/undefined") throw new Error(`renderer is not isolated: ${result.isolated}`);
    result.doctorSource = await ev("window.spaceJanitor.getDoctor().then(r => r.source + ':' + r.ready).catch(e => 'ERR ' + e.message)");
    if (result.doctorSource !== "sj-core:true") throw new Error(`bundled sj gate did not answer doctor: ${result.doctorSource}`);
    await sleep(3000);
    if (exited) throw new Error(`app exited early: ${JSON.stringify(exited)}\n${log}`);
    ws.close();
    result.alive = true;
  } finally {
    try {
      const v = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
      const ws2 = new WebSocket(v.webSocketDebuggerUrl);
      await new Promise((r) => (ws2.onopen = r));
      ws2.send(JSON.stringify({ id: 1, method: "Browser.close" }));
    } catch { /* already gone */ }
    for (let i = 0; i < 20 && !exited; i++) await sleep(500);
    if (!exited) child.kill("SIGKILL");
  }
  result.exit = exited;
  if (/Uncaught|FATAL|Unhandled/i.test(log)) throw new Error(`uncaught error in app output:\n${log}`);
  return result;
}

async function main() {
  const platform = arg("platform");
  if (!platform) throw new Error("usage: verify-packaged-electron.cjs --platform <p> [--probe]");
  const expected = parsePin(fs.readFileSync(path.join(desktopDir, "electron-builder.yml"), "utf8"));
  if (!expected) throw new Error("no electronVersion pin in electron-builder.yml");
  const bins = electronBinaries(platform);
  if (bins.length === 0) throw new Error(`no packaged Electron binary found under ${releaseDir} for ${platform}`);
  assertPackagedElectron(bins, expected);
  for (const b of bins) console.log(`packaged Electron ${expected} confirmed in binary: ${b}`);
  if (process.argv.includes("--probe")) {
    if (platform !== "darwin") throw new Error("--probe is implemented for darwin only");
    const res = await probe(macApps()[0], expected);
    console.log(`packaged app probe ok: ${JSON.stringify(res)}`);
  }
}

main().catch((e) => { console.error(`verify-packaged-electron: ${e.message}`); process.exit(1); });
