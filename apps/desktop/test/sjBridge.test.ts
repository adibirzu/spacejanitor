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
      servers: [{ name: "x", command: "node", argsRedacted: `--token leakySecretVal99 https://${["u", "leakyPass99"].join(":")}@h/x?sig=leakySig99` }],
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

test("gate: resolver never consults PATH, relative paths or non-executables", () => {
  const exe = process.platform === "win32" ? "sj.exe" : "sj";
  const onPath = path.join("/usr/local/evil-bin", exe);
  const saved = process.env.PATH;
  process.env.PATH = `/usr/local/evil-bin${path.delimiter}${saved ?? ""}`;
  try {
    const found = resolveSjBinary({
      resourcesPath: "/nonexistent/resources",
      isPackaged: false,
      existsSync: (p) => p === onPath,
      isExecutable: () => true,
      repoRoot: "/nonexistent/repo",
      env: {},
    });
    assert.equal(found, null);
  } finally {
    process.env.PATH = saved;
  }
  const bundled = path.join("/res", "bin", exe);
  assert.equal(
    resolveSjBinary({ resourcesPath: "/res", existsSync: (p) => p === bundled, isExecutable: () => false, env: {}, repoRoot: "/x" }),
    null,
    "a bundled but non-executable sj must not be used"
  );
  assert.equal(
    resolveSjBinary({ resourcesPath: "", isPackaged: false, existsSync: () => true, isExecutable: () => true, env: { SPACEJANITOR_SJ_BIN: "sj" }, repoRoot: "/x" }),
    path.join("/x", "target", "release", exe),
    "a relative env override is ignored"
  );
});

test("gate: a packaged app without its bundled sj never falls back to env or repo candidates; NO_SJ disables sj", () => {
  const exe = process.platform === "win32" ? "sj.exe" : "sj";
  const everything = { existsSync: () => true, isExecutable: () => true, repoRoot: "/x" };
  assert.equal(
    resolveSjBinary({ ...everything, resourcesPath: "/res", isPackaged: true, existsSync: (p) => p !== path.join("/res", "bin", exe), env: { SPACEJANITOR_SJ_BIN: "/evil/sj" } }),
    null
  );
  assert.equal(resolveSjBinary({ ...everything, resourcesPath: "/res", isPackaged: false, env: { SPACEJANITOR_NO_SJ: "1" } }), null);
});

test("gate: SjBridge pins the core gate to its own absolute binary; no binary means core fails closed", () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const core = require("@spacejanitor/core");
  const bridge = new SjBridge({ binaryPath: null });
  try {
    assert.equal(core.activeSjBinary(), null);
    assert.equal(core.isProtectedPath("/tmp/anything").protected, true);
    assert.equal(bridge.remediationAvailable().available, false);
    assert.equal(bridge.remediationAvailable().reason, "sj_unavailable");
  } finally {
    core.configureSjBinary(undefined);
  }
});

test("R10-B34: a hanging Rust sj makes the orphan report fail closed (sj_timeout, no candidates), never a Node answer", async () => {
  if (process.platform === "win32") return;
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sj-bridge-timeout-")));
  const prev = process.env.SPACEJANITOR_SJ_TIMEOUT_MS;
  try {
    const fake = path.join(base, "sj");
    fs.writeFileSync(fake, "#!/bin/sh\nsleep 5\n", { mode: 0o755 });
    process.env.SPACEJANITOR_SJ_TIMEOUT_MS = "300";
    const bridge = new SjBridge({ binaryPath: fake });
    const res = (await bridge.invoke("orphans", { targetPath: base, includeOrphans: true })) as { error?: string; candidates: unknown[] };
    bridge.dispose();
    assert.equal(res.error, "sj_timeout");
    assert.deepEqual(res.candidates, []);
  } finally {
    if (prev === undefined) delete process.env.SPACEJANITOR_SJ_TIMEOUT_MS;
    else process.env.SPACEJANITOR_SJ_TIMEOUT_MS = prev;
    fs.rmSync(base, { recursive: true, force: true });
  }
});
