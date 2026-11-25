import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  collectOrphans,
  configureSjBinary,
  findProtectedDescendant,
  isProtectedPath,
  resolveSjBinary,
  runSjSync,
} from "../src/index.mjs";

const REPO_ROOT = path.resolve(new URL("../../..", import.meta.url).pathname);
const exe = process.platform === "win32" ? "sj.exe" : "sj";
const REAL_SJ = [path.join(REPO_ROOT, "target", "release", exe), path.join(REPO_ROOT, "target", "debug", exe)].find((p) =>
  fs.existsSync(p)
);
const NO_SJ = process.env.SPACEJANITOR_NO_SJ === "1";
const HAVE_SJ = Boolean(REAL_SJ) && !NO_SJ;

const vectors = JSON.parse(
  fs.readFileSync(new URL("../../../crates/sj-core/tests/fixtures/protect_vectors.json", import.meta.url), "utf8")
);
const descendantVectors = JSON.parse(
  fs.readFileSync(new URL("../../../crates/sj-core/tests/fixtures/descendant_vectors.json", import.meta.url), "utf8")
);

function withBinary(binaryPath, fn) {
  // These cases pin an explicit binary, so they must not be masked by an ambient SPACEJANITOR_NO_SJ=1
  // (NO_SJ itself is covered by its own test below).
  const prior = process.env.SPACEJANITOR_NO_SJ;
  delete process.env.SPACEJANITOR_NO_SJ;
  configureSjBinary(binaryPath);
  try {
    return fn();
  } finally {
    configureSjBinary(undefined);
    if (prior === undefined) delete process.env.SPACEJANITOR_NO_SJ;
    else process.env.SPACEJANITOR_NO_SJ = prior;
  }
}

function fakeSj(dir, body) {
  const p = path.join(dir, "sj");
  fs.writeFileSync(p, `#!/bin/sh\n${body}\n`, "utf8");
  fs.chmodSync(p, 0o755);
  return p;
}

test("gate: a missing sj binary fails closed (every path is protected)", () => {
  withBinary(null, () => {
    for (const p of ["/Users/alice/.cache/vite", "/tmp/anything", "/Users/alice/.ssh/id"]) {
      const v = isProtectedPath(p, { homeDir: "/Users/alice" });
      assert.equal(v.protected, true, p);
      assert.equal(v.reason, "sj_unavailable");
    }
    assert.equal(findProtectedDescendant(os.tmpdir()).protected, true);
  });
});

test("gate: a nonexistent or relative sj path is never used", () => {
  withBinary("/nonexistent/sj", () => assert.equal(isProtectedPath("/tmp/x").protected, true));
  withBinary("sj", () => assert.equal(isProtectedPath("/tmp/x").protected, true));
});

test("gate: SPACEJANITOR_NO_SJ=1 disables sj discovery and fails closed", () => {
  assert.equal(resolveSjBinary({ env: { SPACEJANITOR_NO_SJ: "1", SPACEJANITOR_SJ_BIN: REAL_SJ || "/bin/sh" } }), null);
  const prior = process.env.SPACEJANITOR_NO_SJ;
  process.env.SPACEJANITOR_NO_SJ = "1";
  configureSjBinary(REAL_SJ || "/bin/sh");
  try {
    assert.equal(isProtectedPath("/tmp/x").reason, "sj_unavailable");
  } finally {
    configureSjBinary(undefined);
    if (prior === undefined) delete process.env.SPACEJANITOR_NO_SJ;
    else process.env.SPACEJANITOR_NO_SJ = prior;
  }
});

test("gate: resolution never consults PATH", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-path-"));
  try {
    fakeSj(dir, "exit 0");
    const found = resolveSjBinary({ env: { PATH: dir }, resourcesPath: "", repoRoot: "/nonexistent" });
    assert.equal(found, null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("gate: bundled resources/bin/sj wins over the env override", { skip: process.platform === "win32" }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-res-"));
  try {
    fs.mkdirSync(path.join(dir, "bin"));
    const bundled = fakeSj(path.join(dir, "bin"), "exit 0");
    const other = fakeSj(fs.mkdtempSync(path.join(os.tmpdir(), "sj-env-")), "exit 0");
    assert.equal(resolveSjBinary({ resourcesPath: dir, env: { SPACEJANITOR_SJ_BIN: other } }), bundled);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("gate: non-executable, unparseable, wrong-schema, short and timed-out sj output all fail closed", { skip: process.platform === "win32" }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-fake-"));
  try {
    const noexec = path.join(dir, "noexec");
    fs.writeFileSync(noexec, "#!/bin/sh\necho hi\n");
    fs.chmodSync(noexec, 0o644);
    withBinary(noexec, () => assert.equal(isProtectedPath("/tmp/x").reason, "sj_unavailable"));

    const garbage = fakeSj(dir, "echo not-json");
    withBinary(garbage, () => assert.match(isProtectedPath("/tmp/x").reason, /^sj_unparseable/));

    const wrongSchema = fakeSj(dir, `echo '{"schema":"other.v1","results":[{"path":"/tmp/x","protected":false,"reason":""}]}'`);
    withBinary(wrongSchema, () => assert.match(isProtectedPath("/tmp/x").reason, /^sj_unparseable/));

    const lying = fakeSj(dir, `echo '{"schema":"spacejanitor.protect.v1","results":[{"path":"/tmp/OTHER","protected":false,"reason":""}]}'`);
    withBinary(lying, () => assert.match(isProtectedPath("/tmp/x").reason, /^sj_unparseable/));

    const nonBool = fakeSj(dir, `echo '{"schema":"spacejanitor.protect.v1","results":[{"path":"/tmp/x","protected":"no","reason":""}]}'`);
    withBinary(nonBool, () => assert.equal(isProtectedPath("/tmp/x").protected, true));

    const failing = fakeSj(dir, "exit 3");
    withBinary(failing, () => assert.match(isProtectedPath("/tmp/x").reason, /^sj_exit_3/));

    const slow = fakeSj(dir, "sleep 5");
    withBinary(slow, () => assert.equal(isProtectedPath("/tmp/x", { timeoutMs: 200 }).reason, "sj_timeout"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("gate: the verdict comes from sj, not from a JS denylist (sj says protected for a path the old JS accepted)", { skip: process.platform === "win32" }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-fake-"));
  try {
    const bin = fakeSj(
      dir,
      `echo '{"schema":"spacejanitor.protect.v1","results":[{"path":"/Users/alice/.cache/vite","protected":true,"reason":"from_sj"}]}'`
    );
    withBinary(bin, () => {
      const v = isProtectedPath("/Users/alice/.cache/vite", { homeDir: "/Users/alice" });
      assert.deepEqual(v, { protected: true, reason: "from_sj" });
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("gate: empty or non-string candidates are protected without spawning sj", () => {
  assert.equal(isProtectedPath("").protected, true);
  assert.equal(isProtectedPath(undefined).protected, true);
  assert.equal(isProtectedPath("   ").protected, true);
});

test("gate: no sj means orphan/worktree proofs are unavailable and nothing is offered as safe", async () => {
  configureSjBinary(null);
  try {
    const r = await collectOrphans({ targetPath: os.tmpdir() });
    assert.equal(r.schema, "spacejanitor.orphans.v1");
    assert.equal(r.error, "sj_unavailable");
    assert.deepEqual(r.candidates, []);
  } finally {
    configureSjBinary(undefined);
  }
});

test("gate: runSjSync reports sj_unavailable when nothing is configured", () => {
  withBinary(null, () => assert.throws(() => runSjSync(["doctor", "--json"]), /sj_unavailable/));
});

test("gate: shared protect vectors are decided by the Rust sj binary", { skip: !HAVE_SJ || process.platform === "win32" }, () => {
  withBinary(REAL_SJ, () => {
    const opts = { homeDir: vectors.home };
    for (const p of vectors.protected) assert.equal(isProtectedPath(p, opts).protected, true, `expected protected: ${p}`);
    for (const p of vectors.unprotected) assert.equal(isProtectedPath(p, opts).protected, false, `expected unprotected: ${p}`);
  });
});

test("gate: shared descendant vectors are decided by the Rust sj binary", { skip: !HAVE_SJ || process.platform === "win32" }, () => {
  withBinary(REAL_SJ, () => {
    for (const c of descendantVectors.cases) {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), "sj-desc-"));
      try {
        const home = path.join(root, "home");
        const project = path.join(root, "project");
        fs.mkdirSync(home);
        fs.mkdirSync(project);
        for (const e of c.entries) {
          if (e.startsWith("link:")) fs.symlinkSync("/", path.join(project, e.slice(5)));
          else if (e.endsWith("/")) fs.mkdirSync(path.join(project, e), { recursive: true });
          else {
            fs.mkdirSync(path.dirname(path.join(project, e)), { recursive: true });
            fs.writeFileSync(path.join(project, e), "x");
          }
        }
        assert.equal(findProtectedDescendant(project, { homeDir: home }).protected, c.protected, c.name);
      } finally {
        fs.rmSync(root, { recursive: true, force: true });
      }
    }
  });
});
