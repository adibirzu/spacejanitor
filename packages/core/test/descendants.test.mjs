import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createRemediationPlan, findProtectedDescendant, verifyRemediationGate } from "../src/index.mjs";

const vectors = JSON.parse(
  fs.readFileSync(new URL("../../../crates/sj-core/tests/fixtures/descendant_vectors.json", import.meta.url), "utf8")
);

function build(project, entries) {
  fs.mkdirSync(project, { recursive: true });
  for (const e of entries) {
    if (e.startsWith("link:")) fs.symlinkSync("/", path.join(project, e.slice(5)));
    else if (e.endsWith("/")) fs.mkdirSync(path.join(project, e), { recursive: true });
    else {
      fs.mkdirSync(path.dirname(path.join(project, e)), { recursive: true });
      fs.writeFileSync(path.join(project, e), "x");
    }
  }
}

for (const c of vectors.cases) {
  test(`R7-B22 shared descendant vector: ${c.name}`, { skip: process.platform === "win32" && c.name.includes("symlink") }, () => {
    const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sj-r7b22-")));
    try {
      const home = path.join(base, "home");
      fs.mkdirSync(home);
      const project = path.join(base, "project");
      build(project, c.entries);
      const found = findProtectedDescendant(project, { homeDir: home });
      assert.equal(found.protected, c.protected, JSON.stringify(found));

      // end to end through the gate: plan + authorize must agree
      const plan = createRemediationPlan([{ id: "p", path: project, bytes: 1, kind: "dir" }], { homeDir: home });
      assert.equal(plan.items.length, c.protected ? 0 : 1, "planning must block a candidate with a protected descendant");
      assert.equal(plan.blockedItems.length, c.protected ? 1 : 0);
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });
}

test("R7-B22: a descendant that becomes protected AFTER planning is caught at authorization", () => {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sj-r7b22b-")));
  try {
    const home = path.join(base, "home");
    fs.mkdirSync(home);
    const project = path.join(base, "project");
    build(project, ["src/", "src/main.rs"]);
    const plan = createRemediationPlan([{ id: "p", path: project, bytes: 1, kind: "dir" }], { homeDir: home });
    assert.equal(plan.items.length, 1);
    fs.mkdirSync(path.join(project, ".ssh"));
    fs.writeFileSync(path.join(project, ".ssh", "id_ed25519"), "k");
    const check = verifyRemediationGate({ plan, planSha256: plan.planSha256, phrase: plan.confirmationPhrase, homeDir: home });
    assert.equal(check.allowed, false);
    assert.match(check.reason, /protected_descendant|protected_target/);
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("R7-B22: an unreadable or oversized subtree fails closed", { skip: process.platform === "win32" }, () => {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sj-r7b22c-")));
  try {
    const home = path.join(base, "home");
    fs.mkdirSync(home);
    const project = path.join(base, "project");
    build(project, ["a/", "a/f1", "a/f2", "a/f3"]);
    assert.equal(findProtectedDescendant(project, { homeDir: home, maxEntries: 2 }).protected, true);
    fs.chmodSync(path.join(project, "a"), 0o000);
    try {
      if (process.getuid && process.getuid() !== 0) {
        assert.equal(findProtectedDescendant(project, { homeDir: home }).protected, true);
      }
    } finally {
      fs.chmodSync(path.join(project, "a"), 0o755);
    }
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});
