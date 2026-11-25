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
  const prevNoSj = process.env.SPACEJANITOR_NO_SJ;
  try {
    delete process.env.SPACEJANITOR_NO_SJ; // this case pins a hanging binary explicitly
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
    if (prevNoSj !== undefined) process.env.SPACEJANITOR_NO_SJ = prevNoSj;
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("trust: the desktop resolver rejects symlinked, world-writable and directory sj even when packaged", () => {
  if (process.platform === "win32") return;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-bridge-trust-"));
  try {
    const mk = (name: string, mode: number) => {
      const res = path.join(dir, name);
      fs.mkdirSync(path.join(res, "bin"), { recursive: true });
      return res;
    };
    const resolve = (resourcesPath: string) => resolveSjBinary({ resourcesPath, isPackaged: true, env: {} });

    const good = mk("good", 0o755);
    fs.writeFileSync(path.join(good, "bin", "sj"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    assert.equal(resolve(good), path.join(good, "bin", "sj"));

    const sym = mk("sym", 0o755);
    fs.writeFileSync(path.join(sym, "evil.sh"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    fs.symlinkSync(path.join(sym, "evil.sh"), path.join(sym, "bin", "sj"));
    assert.equal(resolve(sym), null, "symlinked sj");

    const ww = mk("ww", 0o777);
    fs.writeFileSync(path.join(ww, "bin", "sj"), "#!/bin/sh\nexit 0\n");
    fs.chmodSync(path.join(ww, "bin", "sj"), 0o777);
    assert.equal(resolve(ww), null, "world-writable sj");

    const gw = mk("gw", 0o775);
    fs.writeFileSync(path.join(gw, "bin", "sj"), "#!/bin/sh\nexit 0\n");
    fs.chmodSync(path.join(gw, "bin", "sj"), 0o775);
    assert.equal(resolve(gw), null, "group-writable sj");

    const asDir = mk("asdir", 0o755);
    fs.mkdirSync(path.join(asDir, "bin", "sj"), { mode: 0o755 });
    assert.equal(resolve(asDir), null, "directory at <resources>/bin/sj");

    const open = mk("open", 0o777);
    fs.chmodSync(path.join(open, "bin"), 0o777);
    fs.writeFileSync(path.join(open, "bin", "sj"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    assert.equal(resolve(open), null, "world-writable parent directory");

    // a bridge pinned to a rejected binary fails closed in core as well
    const bridge = new SjBridge({ binaryPath: path.join(ww, "bin", "sj") });
    try {
      assert.equal(bridge.remediationAvailable().available, false);
    } finally {
      bridge.dispose();
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      require("@spacejanitor/core").configureSjBinary(undefined);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("trust: an explicit binaryPath is vetted too, so read-only spawns never run a world-writable or symlinked sj", async () => {
  if (process.platform === "win32") return;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-bridge-explicit-"));
  try {
    const marker = path.join(dir, "RAN");
    const body = `#!/bin/sh\necho ran >> "${marker}"\necho '{"schema":"spacejanitor.doctor.v1"}'\n`;
    const ww = path.join(dir, "ww-sj");
    fs.writeFileSync(ww, body);
    fs.chmodSync(ww, 0o777);
    const real = path.join(dir, "real-sj");
    fs.writeFileSync(real, body, { mode: 0o755 });
    const link = path.join(dir, "link-sj");
    fs.symlinkSync(real, link);
    for (const p of [ww, link]) {
      const bridge = new SjBridge({ binaryPath: p });
      const doc = await bridge.invoke("doctor");
      bridge.dispose();
      assert.equal(doc.source, "node-fallback", p);
      assert.equal(fs.existsSync(marker), false, `${p} must never be executed`);
    }
  } finally {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    require("@spacejanitor/core").configureSjBinary(undefined);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
