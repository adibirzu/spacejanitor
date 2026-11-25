import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  ORPHAN_SCAN_WARNING,
  collectOrphans,
  collectSummary,
  inspectWorktree,
  redactSecrets,
  removeLinkedWorktree,
} from "../src/index.mjs";

const CLI = new URL("../../cli/bin/spacejanitor.mjs", import.meta.url).pathname;

/** A `git` shim first on PATH that records every spawn: proves whether git was started at all. */
function withGitShim(fn) {
  return async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-gitshim-"));
    const bin = path.join(dir, "bin");
    fs.mkdirSync(bin);
    const marker = path.join(dir, "GIT_SPAWNED");
    fs.writeFileSync(path.join(bin, "git"), `#!/bin/sh\necho "$@" >> "${marker}"\nexit 1\n`, { mode: 0o755 });
    const savedPath = process.env.PATH;
    process.env.PATH = `${bin}${path.delimiter}${savedPath}`;
    try {
      await fn({ dir, marker, shimPath: process.env.PATH });
    } finally {
      process.env.PATH = savedPath;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  };
}
const skipWin = { skip: process.platform === "win32" };

test("orphan scanning is OFF by default: collectOrphans reports 'not scanned' and spawns no git", skipWin, withGitShim(async ({ dir, marker }) => {
  const repo = path.join(dir, "repo");
  fs.mkdirSync(path.join(repo, ".git"), { recursive: true });
  const report = await collectOrphans({ targetPath: repo });
  assert.equal(report.scanned, false);
  assert.equal(report.notScannedReason, "orphan_scan_disabled_by_default");
  assert.deepEqual(report.candidates, []);
  assert.ok(String(report.message).includes("disabled by default"));
  assert.equal(fs.existsSync(marker), false, "git must not be spawned");
  // opt-in really reaches git, with a warning available to show
  const on = await collectOrphans({ targetPath: repo, includeOrphans: true });
  assert.equal(on.scanned, true);
  assert.equal(fs.existsSync(marker), true);
  assert.match(ORPHAN_SCAN_WARNING, /runs git inside repositories found on disk/);
  assert.match(ORPHAN_SCAN_WARNING, /experimental/);
}));

test("collectSummary spawns no git by default and marks orphans as not scanned", skipWin, withGitShim(async ({ dir, marker }) => {
  const summary = await collectSummary({ targetPath: dir, configDirs: [], homeDir: dir });
  assert.equal(summary.orphans.scanned, false);
  assert.equal(summary.orphans.notScannedReason, "orphan_scan_disabled_by_default");
  assert.equal(fs.existsSync(marker), false, `git was spawned: ${fs.existsSync(marker) ? fs.readFileSync(marker, "utf8") : ""}`);
}));

test("inspectWorktree and removeLinkedWorktree refuse to run git unless opted in", skipWin, withGitShim(async ({ dir, marker }) => {
  const wt = path.join(dir, "wt");
  fs.mkdirSync(wt);
  fs.writeFileSync(path.join(wt, ".git"), `gitdir: ${path.join(dir, "g")}\n`);
  const proof = await inspectWorktree(wt);
  assert.equal(proof.safeToPrune, false);
  assert.equal(proof.proofStatus, "not_scanned");
  const rm = await removeLinkedWorktree(wt);
  assert.equal(rm.ok, false);
  assert.equal(rm.error, "orphan_scanning_disabled");
  assert.equal(fs.existsSync(marker), false);
}));

test("CLI: summary and orphans spawn no git by default; --include-orphans opts in and warns", skipWin, withGitShim(async ({ dir, marker, shimPath }) => {
  const run = (args, extraEnv = {}) =>
    spawnSync(process.execPath, [CLI, ...args], {
      encoding: "utf8",
      timeout: 60000,
      env: { ...process.env, PATH: shimPath, SPACEJANITOR_NO_SJ: "1", HOME: dir, ...extraEnv },
    });
  const s = run(["summary", "--path", dir, "--json"]);
  assert.equal(s.status, 0, s.stderr);
  const sj = JSON.parse(s.stdout);
  assert.equal(sj.orphans.scanned, false);
  const o = run(["orphans", "--path", dir, "--json"]);
  assert.equal(o.status, 0, o.stderr);
  const oj = JSON.parse(o.stdout);
  assert.equal(oj.scanned, false);
  assert.equal(oj.notScannedReason, "orphan_scan_disabled_by_default");
  assert.equal(fs.existsSync(marker), false, "git was spawned by default CLI usage");
  const on = run(["orphans", "--path", dir, "--include-orphans", "--json"]);
  assert.match(on.stderr, /runs git inside repositories found on disk/);
  assert.equal(fs.existsSync(marker), true);
}));

test("R11/R12: an attached short-flag credential after NAME= (any quoting/separator) is redacted", () => {
  for (const s of [
    "OPTS=-pLEAK90secret mysql db", "sh -c 'OPTS=-uadmin:LEAK91pw mysql'", "X=-tLEAK92tok run",
    'OPTS="-pLEAK93q"', "OPTS='-pLEAK94q'", "a=b,OPTS=-pLEAK95c", "--opts=-pLEAK96x", "--opts='-pLEAK97y'",
  ]) {
    const out = redactSecrets(s);
    assert.ok(!/LEAK9\d/.test(out), `leak: ${s} => ${out}`);
  }
  assert.equal(redactSecrets("OPTS=-timeout mysql"), "OPTS=-timeout mysql");
});

test("R12-B38: default text output says 'not scanned', never a numeric 0 (summary and orphans, with and without Rust sj)", skipWin, withGitShim(async ({ dir, shimPath }) => {
  const sjBin = path.resolve(new URL("../../../target/release/sj", import.meta.url).pathname);
  const modes = [{ SPACEJANITOR_NO_SJ: "1" }, fs.existsSync(sjBin) ? { SPACEJANITOR_NO_SJ: "", SPACEJANITOR_SJ_BIN: sjBin } : null].filter(Boolean);
  for (const extra of modes) {
    const run = (args) =>
      spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", timeout: 60000, env: { ...process.env, PATH: shimPath, HOME: dir, ...extra } });
    const summary = run(["summary", "--path", dir]);
    assert.equal(summary.status, 0, summary.stderr);
    assert.match(summary.stdout, /orphans: not scanned \(disabled by default\)/, summary.stdout);
    assert.doesNotMatch(summary.stdout, /orphans: 0/);
    const orphans = run(["orphans", "--path", dir]);
    assert.equal(orphans.status, 0, orphans.stderr);
    assert.match(orphans.stdout, /not scanned \(disabled by default\)/, orphans.stdout);
    assert.doesNotMatch(orphans.stdout, /candidates: 0/);
  }
}));

test("R12: doctor's only git call is `git --version` (no git command touches a repository by default)", skipWin, withGitShim(async ({ dir, marker, shimPath }) => {
  const r = spawnSync(process.execPath, [CLI, "doctor", "--json"], {
    encoding: "utf8",
    timeout: 60000,
    env: { ...process.env, PATH: shimPath, HOME: dir, SPACEJANITOR_NO_SJ: "1" },
  });
  assert.equal(r.status, 0, r.stderr);
  const calls = fs.existsSync(marker) ? fs.readFileSync(marker, "utf8").split("\n").filter(Boolean) : [];
  for (const c of calls) assert.equal(c.trim(), "--version", `unexpected git call: ${c}`);
}));
