import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveSjBinary, SjBridge } from "../src/sjBridge";

test("resolves sj binary with fallback order and falls back gracefully to node-fallback", async () => {
  const resolved = resolveSjBinary({
    resourcesPath: "/nonexistent/resources",
    cwd: "/nonexistent/cwd",
    existsSync: () => false,
  });
  assert.equal(resolved, null);

  const bridge = new SjBridge({
    binaryPath: null,
  });
  const doc = await bridge.invoke("doctor");
  assert.equal(doc.schema, "spacejanitor.doctor.v1");
  assert.equal(doc.source, "node-fallback");
});

test("#2: prevents binary planting from arbitrary cwd target/ directory", () => {
  const evilCwd = "/tmp/evil-cwd";
  const exe = process.platform === "win32" ? "sj.exe" : "sj";
  const plantedPath = path.resolve(evilCwd, "target", "release", exe);
  const resolved = resolveSjBinary({
    resourcesPath: "/nonexistent/resources",
    cwd: evilCwd,
    isPackaged: false,
    existsSync: (p) => p === plantedPath,
  });
  assert.notEqual(resolved, plantedPath);
});

test("#3: handles non-executable (EACCES) binaryPath without crashing and falls back to node-fallback", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-eacces-"));
  try {
    const stub = path.join(tmpDir, "sj");
    fs.writeFileSync(stub, "#!/bin/sh\necho ok\n", "utf8");
    fs.chmodSync(stub, 0o644);
    const bridge = new SjBridge({ binaryPath: stub });
    const doc = await bridge.invoke("doctor");
    assert.equal(doc.schema, "spacejanitor.doctor.v1");
    assert.equal(doc.source, "node-fallback");
    bridge.dispose();
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
