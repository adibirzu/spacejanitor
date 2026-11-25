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

test("R10-B34: a hanging Rust sj makes the orphan proof fail closed and say so (no silent Node fallback)", async () => {
  if (process.platform === "win32") return;
  const { execFileSync } = await import("node:child_process");
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sj-bridge-timeout-")));
  const prev = process.env.SPACEJANITOR_SJ_TIMEOUT_MS;
  try {
    const g = (cwd: string, ...a: string[]) =>
      execFileSync("git", ["-c", "user.email=t@e.com", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...a], { cwd, encoding: "utf8" });
    const origin = path.join(base, "origin.git");
    const repo = path.join(base, "repo");
    fs.mkdirSync(repo);
    g(base, "init", "--bare", "-b", "main", origin);
    g(repo, "init", "-b", "main");
    fs.writeFileSync(path.join(repo, "a.txt"), "a");
    g(repo, "add", ".");
    g(repo, "commit", "-m", "init");
    g(repo, "remote", "add", "origin", origin);
    g(repo, "push", "-u", "origin", "main");
    const wt = path.join(base, "wt");
    g(repo, "worktree", "add", "-b", "feat", wt);
    g(wt, "push", "-u", "origin", "feat");
    const fake = path.join(base, "sj");
    fs.writeFileSync(fake, "#!/bin/sh\nsleep 5\n", { mode: 0o755 });
    process.env.SPACEJANITOR_SJ_TIMEOUT_MS = "300";
    const bridge = new SjBridge({ binaryPath: fake });
    const res = (await bridge.invoke("orphans", { targetPath: repo, includeOrphans: true })) as {
      rustProof?: string;
      candidates: Array<{ path: string; safeToPrune: boolean }>;
    };
    bridge.dispose();
    assert.equal(res.rustProof, "timed_out");
    assert.ok(res.candidates.length > 0);
    for (const c of res.candidates) assert.equal(c.safeToPrune, false);
  } finally {
    if (prev === undefined) delete process.env.SPACEJANITOR_SJ_TIMEOUT_MS;
    else process.env.SPACEJANITOR_SJ_TIMEOUT_MS = prev;
    fs.rmSync(base, { recursive: true, force: true });
  }
});
