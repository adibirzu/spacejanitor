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

test("R2-B7: redacts secrets in mcp-audit/memory output coming back from the Rust sidecar", async () => {
  if (process.platform === "win32") return;
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-redact-"));
  try {
    const stub = path.join(tmpDir, "sj");
    const payload = JSON.stringify({
      schema: "spacejanitor.mcp_audit.v1",
      servers: [{ name: "x", command: "node", argsRedacted: "--token leakySecretVal99 https://u:leakyPass99@h/x?sig=leakySig99" }],
    });
    fs.writeFileSync(stub, `#!/bin/sh\nif [ "$1" = "serve-stdio" ]; then exit 1; fi\necho '${payload}'\n`, { mode: 0o755 });
    const bridge = new SjBridge({ binaryPath: stub });
    const res = await bridge.invoke("mcp-audit");
    const text = JSON.stringify(res);
    for (const s of ["leakySecretVal99", "leakyPass99", "leakySig99"]) {
      assert.equal(text.includes(s), false, `leaked ${s}`);
    }
    bridge.dispose();
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
