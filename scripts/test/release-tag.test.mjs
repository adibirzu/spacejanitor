import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { parseReleaseTag, checkTagAgainstVersion } from "../release-tag.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

test("parseReleaseTag accepts final and -rc.N tags only", () => {
  assert.deepEqual(parseReleaseTag("v0.1.0"), { ok: true, base: "0.1.0", prerelease: false, rc: null });
  assert.deepEqual(parseReleaseTag("v0.1.0-rc.1"), { ok: true, base: "0.1.0", prerelease: true, rc: 1 });
  assert.deepEqual(parseReleaseTag("v12.0.31-rc.12"), { ok: true, base: "12.0.31", prerelease: true, rc: 12 });
});

test("parseReleaseTag rejects everything else", () => {
  for (const bad of [
    "v0.1.0-rcx", "v0.1.0-rc", "v0.1.0-rc.", "v0.1.0-rc.1.2", "v0.1.0-rc.01", "v0.1.0-beta", "v0.1.0-beta.1",
    "v0.1.0-RC.1", "v0.1", "v1", "0.1.0", "V0.1.0", "v01.1.0", "v0.1.0+build", "v0.1.0-rc.1\n", " v0.1.0", "refs/tags/v0.1.0", "", "v0.1.0-rc.1-rc.2",
  ]) {
    assert.equal(parseReleaseTag(bad).ok, false, `should reject ${JSON.stringify(bad)}`);
  }
  assert.equal(parseReleaseTag(undefined).ok, false);
});

test("checkTagAgainstVersion compares the tag minus -rc.N with the package version", () => {
  assert.equal(checkTagAgainstVersion("v0.1.0-rc.1", "0.1.0").ok, true);
  assert.equal(checkTagAgainstVersion("v0.1.0", "0.1.0").ok, true);
  assert.equal(checkTagAgainstVersion("v0.2.0", "0.1.0").ok, false);
  assert.equal(checkTagAgainstVersion("v0.2.0-rc.1", "0.1.0").ok, false);
  assert.equal(checkTagAgainstVersion("v0.1.0-rcx", "0.1.0").ok, false);
  assert.equal(checkTagAgainstVersion("v0.1.0-beta", "0.1.0").ok, false);
  assert.equal(checkTagAgainstVersion("v0.1.0-rc.1", "0.1.0-rc.1").ok, false);
});

test("CLI exits non-zero with a message on a bad tag and prints prerelease on a good one", () => {
  const script = path.join(root, "scripts/release-tag.mjs");
  const good = execFileSync("node", [script, "v0.1.0-rc.2", "--package-version", "0.1.0"], { encoding: "utf8" });
  assert.match(good, /prerelease=true/);
  assert.match(execFileSync("node", [script, "v0.1.0", "--package-version", "0.1.0"], { encoding: "utf8" }), /prerelease=false/);
  const bad = spawnSync("node", [script, "v0.1.0-beta", "--package-version", "0.1.0"], { encoding: "utf8" });
  assert.notEqual(bad.status, 0);
  assert.match(bad.stderr, /ERROR/);
  const noValue = spawnSync("node", [script, "v0.1.0", "--package-version"], { encoding: "utf8" });
  assert.notEqual(noValue.status, 0, "--package-version without a value must not silently pass");
  assert.notEqual(spawnSync("node", [script, "v0.2.0", "--package-version", "0.1.0"], { encoding: "utf8" }).status, 0);
});

test("release.yml: strict tag triggers, script-based version check, prerelease flag, still skipped on dry run", () => {
  const wf = fs.readFileSync(path.join(root, ".github/workflows/release.yml"), "utf8");
  const head = wf.slice(0, wf.indexOf("workflow_dispatch:"));
  assert.match(head, /- "v\[0-9\]\+\.\[0-9\]\+\.\[0-9\]\+"/);
  assert.match(head, /- "v\[0-9\]\+\.\[0-9\]\+\.\[0-9\]\+-rc\.\[0-9\]\+"/);
  assert.doesNotMatch(head, /v\*\.\*\.\*/);
  assert.match(wf, /node scripts\/release-tag\.mjs "\$GITHUB_REF_NAME" --package-version/);
  assert.doesNotMatch(wf, /TAG_VER/);
  const publish = wf.slice(wf.indexOf("Publish GitHub Release on tag push"));
  assert.match(publish, /prerelease: \$\{\{ contains\(github\.ref_name, '-rc\.'\) \}\}/);
  assert.match(publish, /inputs\.dry_run != true/);
  assert.match(publish, /github\.event_name == 'push'/);
});

test("ci.yml runs the script tests on pull requests", () => {
  const ci = fs.readFileSync(path.join(root, ".github/workflows/ci.yml"), "utf8");
  assert.match(ci, /node --test scripts\/test\/\*\.test\.mjs/);
});
