import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  activeSjBinary,
  collectOrphans,
  configureSjBinary,
  findProtectedDescendant,
  isProtectedPath,
  protectPaths,
  resolveSjBinary,
  runSjSync,
  sjBinaryProblem,
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
    const r = await collectOrphans({ targetPath: os.tmpdir(), includeOrphans: true });
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

test("gate: shared protect vectors are decided by the Rust sj binary (every platform)", { skip: !HAVE_SJ }, () => {
  withBinary(REAL_SJ, () => {
    const opts = { homeDir: vectors.home };
    for (const p of vectors.protected) assert.equal(isProtectedPath(p, opts).protected, true, `expected protected: ${p}`);
    for (const p of vectors.unprotected) assert.equal(isProtectedPath(p, opts).protected, false, `expected unprotected: ${p}`);
    if (process.platform !== "win32") {
      for (const p of vectors.posix_host_protected) assert.equal(isProtectedPath(p, opts).protected, true, `expected protected on POSIX: ${p}`);
    }
  });
});

test("gate: custom exactPaths, dynamicProtectedPaths and globPatterns reach the Rust gate", { skip: !HAVE_SJ }, () => {
  withBinary(REAL_SJ, () => {
    const o = {
      homeDir: "/Users/alice",
      exactPaths: ["/data/keep"],
      dynamicProtectedPaths: ["/work/active"],
      globPatterns: ["*.secret-ish"],
    };
    for (const p of ["/data/keep/sub", "/work/active/src", "/Users/alice/a.secret-ish"]) {
      assert.equal(isProtectedPath(p, o).protected, true, p);
    }
    assert.equal(isProtectedPath("/data/other", o).protected, false);
  });
});

test("gate: NUL and control characters are refused before sj is even spawned", () => {
  withBinary(null, () => {
    for (const p of ["/Users/alice/.cache/a\u0000b", "/Users/alice/.cache/a\nb"]) {
      assert.equal(isProtectedPath(p).reason, "control_character_in_path");
    }
  });
});

test("gate: tilde + planted symlink + '..' is judged on the OS-resolved path (R6-B20)", { skip: !HAVE_SJ || process.platform === "win32" }, () => {
  withBinary(REAL_SJ, () => {
    const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sj-r6b20-")));
    try {
      const home = path.join(base, "home");
      for (const d of ["Library/Caches/pnpm", "Library/Mail", ".ssh/sub", ".cache/npm"]) fs.mkdirSync(path.join(home, d), { recursive: true });
      fs.symlinkSync("/", path.join(home, "Library", "Caches", "pnpm", "to-root"));
      fs.symlinkSync(path.join(home, ".ssh", "sub"), path.join(home, ".cache", "npm", "to-ssh-sub"));
      const o = { homeDir: home };
      for (const c of ["~/Library/Caches/pnpm/to-root/..", "~/.cache/npm/to-ssh-sub/.."]) {
        assert.equal(isProtectedPath(c, o).protected, true, c);
      }
      assert.equal(isProtectedPath("~/.cache/npm", o).protected, false);
      assert.equal(isProtectedPath("relative/path", o).protected, true);
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
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

// ---- sj binary trust checks (cross-family review blocker 3) ----
const posixOnly = { skip: process.platform === "win32" };

function mkBin(dir, name, mode = 0o755, body = "#!/bin/sh\nexit 0\n") {
  const p = path.join(dir, name);
  fs.writeFileSync(p, body);
  fs.chmodSync(p, mode);
  return p;
}

test("trust: sjBinaryProblem rejects symlinks, directories, group/world-writable files and foreign owners", posixOnly, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-trust-"));
  try {
    const good = mkBin(dir, "good");
    assert.equal(sjBinaryProblem(good), null);
    const link = path.join(dir, "link");
    fs.symlinkSync(good, link);
    assert.equal(sjBinaryProblem(link), "sj_binary_is_symlink");
    assert.equal(sjBinaryProblem(mkBin(dir, "ww", 0o777)), "sj_binary_writable_by_others");
    assert.equal(sjBinaryProblem(mkBin(dir, "gw", 0o775)), "sj_binary_writable_by_others");
    assert.equal(sjBinaryProblem(mkBin(dir, "noexec", 0o644)), "sj_binary_not_executable");
    const sub = path.join(dir, "adir");
    fs.mkdirSync(sub, { mode: 0o755 });
    assert.equal(sjBinaryProblem(sub), "sj_binary_not_a_file");
    assert.equal(sjBinaryProblem(path.join(dir, "missing")), "sj_binary_missing");
    assert.equal(sjBinaryProblem("relative/sj"), "sj_binary_not_absolute");
    // owned by someone else (neither the current user nor root)
    assert.equal(sjBinaryProblem(good, { uid: process.getuid() + 12345 }), "sj_binary_foreign_owner");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("trust: a world-writable parent directory (no sticky bit) disqualifies the binary", posixOnly, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-trust-"));
  try {
    const open = path.join(dir, "open");
    fs.mkdirSync(open);
    fs.chmodSync(open, 0o777);
    const bin = mkBin(open, "sj");
    assert.equal(sjBinaryProblem(bin), "sj_binary_parent_writable_by_others");
    const sticky = path.join(dir, "sticky");
    fs.mkdirSync(sticky);
    fs.chmodSync(sticky, 0o1777);
    assert.equal(sjBinaryProblem(mkBin(sticky, "sj")), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("trust: resolveSjBinary and the active gate never use a rejected binary", posixOnly, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-trust-"));
  try {
    fs.mkdirSync(path.join(dir, "bin"));
    const real = mkBin(path.join(dir, "bin"), "real");
    const link = path.join(dir, "bin", "sj");
    fs.symlinkSync(real, link);
    assert.equal(resolveSjBinary({ resourcesPath: dir, env: {}, repoRoot: "/nonexistent" }), null, "symlinked bundled sj");
    fs.rmSync(link);
    mkBin(path.join(dir, "bin"), "sj", 0o777);
    assert.equal(resolveSjBinary({ resourcesPath: dir, env: {}, repoRoot: "/nonexistent" }), null, "world-writable bundled sj");
    assert.equal(resolveSjBinary({ resourcesPath: "", env: { SPACEJANITOR_SJ_BIN: path.join(dir, "bin", "sj") }, repoRoot: "/nonexistent" }), null);
    withBinary(path.join(dir, "bin", "sj"), () => {
      assert.equal(activeSjBinary(), null);
      assert.equal(isProtectedPath("/tmp/x").protected, true);
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("gate: protectPaths asks sj once for a whole batch and fails closed for every path without sj", { skip: !HAVE_SJ }, () => {
  withBinary(REAL_SJ, () => {
    const out = protectPaths(["/Users/alice/.ssh/id_x", "/Users/alice/.cache/vite", "/Users/alice/vault/a.kdbx"], { homeDir: "/Users/alice" });
    assert.deepEqual(out.map((r) => r.protected), [true, false, true]);
    assert.deepEqual(out.map((r) => r.path), ["/Users/alice/.ssh/id_x", "/Users/alice/.cache/vite", "/Users/alice/vault/a.kdbx"]);
  });
  withBinary(null, () => {
    const out = protectPaths(["/a", "/b"]);
    assert.deepEqual(out.map((r) => [r.protected, r.reason]), [[true, "sj_unavailable"], [true, "sj_unavailable"]]);
  });
});
