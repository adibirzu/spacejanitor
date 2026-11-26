import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const pin = require("../../scripts/electron-pin.cjs");

const repoRoot = path.resolve(__dirname, "../../../..");
const desktopDir = path.join(repoRoot, "apps/desktop");

function tmp(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sj-pin-"));
}

test("electron pin: parsePin reads the electronVersion line of electron-builder.yml", () => {
  assert.equal(pin.parsePin('appId: x\nelectronVersion: "42.11.16"\nasar: true\n'), "42.11.16");
  assert.equal(pin.parsePin("electronVersion: 42.11.16 # note\n"), "42.11.16");
  assert.equal(pin.parsePin("appId: x\n"), null);
});

test("electron pin: checkPin fails when pin, declared dependency or installed electron differ", () => {
  assert.deepEqual(pin.checkPin({ pin: "42.11.16", declared: "42.11.16", installed: "42.11.16" }), []);
  assert.match(pin.checkPin({ pin: "35.7.5", declared: "42.11.16", installed: "42.11.16" }).join("\n"), /pin 35\.7\.5.*declared electron 42\.11\.16/);
  assert.match(pin.checkPin({ pin: "42.11.16", declared: "42.11.16", installed: "35.7.5" }).join("\n"), /major/);
  assert.match(pin.checkPin({ pin: "42.11.16", declared: "^42.11.16", installed: "42.11.16" }).join("\n"), /exact/);
  assert.match(pin.checkPin({ pin: null, declared: "42.11.16", installed: "42.11.16" }).join("\n"), /electronVersion/);
  // installed may legitimately be absent (not installed yet); that alone is not a pin mismatch
  assert.deepEqual(pin.checkPin({ pin: "42.11.16", declared: "42.11.16", installed: null }), []);
});

test("electron pin: this repo's pin, declared dependency and installed electron agree", () => {
  const res = pin.checkRepo(desktopDir);
  assert.deepEqual(res.problems, [], res.problems.join("; "));
});

test("electron pin: scanBinaryVersions finds the Electron/<version> marker inside a binary", () => {
  const dir = tmp();
  try {
    const f = path.join(dir, "bin");
    fs.writeFileSync(f, Buffer.concat([Buffer.alloc(70000, 1), Buffer.from("Mozilla/5.0 Electron/42.11.16 Safari"), Buffer.alloc(70000, 2)]));
    assert.deepEqual(pin.scanBinaryVersions(f), ["42.11.16"]);
    fs.writeFileSync(f, Buffer.alloc(100, 0));
    assert.deepEqual(pin.scanBinaryVersions(f), []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("electron pin: scanBinaryVersions finds a marker straddling the read-chunk boundary", () => {
  const dir = tmp();
  try {
    const f = path.join(dir, "big");
    const chunk = pin.SCAN_CHUNK_BYTES as number;
    const marker = Buffer.from("Electron/42.11.16");
    const buf = Buffer.alloc(chunk * 2, 7);
    marker.copy(buf, chunk - 5);
    fs.writeFileSync(f, buf);
    assert.deepEqual(pin.scanBinaryVersions(f), ["42.11.16"]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("electron pin: assertPackagedElectron rejects a packaged binary of another version", () => {
  const dir = tmp();
  try {
    const f = path.join(dir, "Electron Framework");
    fs.writeFileSync(f, Buffer.from("xx Electron/35.7.5 yy"));
    assert.throws(() => pin.assertPackagedElectron([f], "42.11.16"), /35\.7\.5.*42\.11\.16/);
    fs.writeFileSync(f, Buffer.from("xx Electron/42.11.16 yy"));
    assert.doesNotThrow(() => pin.assertPackagedElectron([f], "42.11.16"));
    assert.throws(() => pin.assertPackagedElectron([path.join(dir, "missing")], "42.11.16"), /missing/);
    fs.writeFileSync(f, Buffer.from("nothing here"));
    assert.throws(() => pin.assertPackagedElectron([f], "42.11.16"), /no Electron version/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("electron pin: ensure-electron skips cleanly when ELECTRON_SKIP_BINARY_DOWNLOAD is set", () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const ensure = require("../../scripts/ensure-electron.cjs");
  const calls = { v: [] as string[] };
  const r = ensure.ensureElectron({ env: { ELECTRON_SKIP_BINARY_DOWNLOAD: "1" }, run: (c: string) => calls.v.push(c), installed: () => false });
  assert.equal(r.action, "skipped");
  assert.equal(calls.v.length, 0);
  const r2 = ensure.ensureElectron({ env: {}, run: (c: string) => calls.v.push(c), installed: () => true });
  assert.equal(r2.action, "present");
  const r3 = ensure.ensureElectron({ env: {}, run: (c: string) => calls.v.push(c), installed: () => false });
  assert.equal(r3.action, "downloaded");
  assert.equal(calls.v.length, 1);
});

test("electron pin: CI checks the pin on every desktop job and probes a packaged app; release verifies the packaged version", () => {
  const ci = fs.readFileSync(path.join(repoRoot, ".github/workflows/ci.yml"), "utf8");
  assert.match(ci, /electron-pin\.cjs check/);
  assert.match(ci, /desktop-package-smoke:/);
  assert.match(ci, /verify-packaged-electron\.cjs/);
  const wf = fs.readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8");
  const matrix = wf.slice(wf.indexOf("desktop-installer-matrix:"), wf.indexOf("publish-release:"));
  assert.match(matrix, /verify-packaged-electron\.cjs --platform \$\{\{ matrix\.sj_platform \}\}/);
  assert.ok(matrix.indexOf("verify-packaged-electron.cjs") > matrix.indexOf("electron-builder --config"), "verify runs after packing");
});

test("electron pin: desktop package.json exposes start and electron:ensure scripts", () => {
  const p = JSON.parse(fs.readFileSync(path.join(desktopDir, "package.json"), "utf8"));
  assert.match(p.scripts.start, /ensure-electron\.cjs/);
  assert.match(p.scripts["electron:ensure"], /ensure-electron\.cjs/);
});
