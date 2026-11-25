import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { executePlanItems } from "../src/executor";
import { RemediationCandidate, RemediationGate } from "../src/remediationGate";

function makeTree(root: string, rel: string, files: string[]): string {
  const dir = path.join(root, rel);
  fs.mkdirSync(dir, { recursive: true });
  for (const f of files) {
    fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
    fs.writeFileSync(path.join(dir, f), "x");
  }
  return dir;
}

function setup(): { base: string; home: string; trash: string; gate: RemediationGate } {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sj-exec-")));
  const home = path.join(base, "home");
  const trash = path.join(home, ".Trash");
  fs.mkdirSync(trash, { recursive: true });
  return { base, home, trash, gate: new RemediationGate({ homeDir: home }) };
}

const deps = (home: string, extra: Record<string, unknown> = {}) => ({
  homeDir: home,
  isInsideOsTrash: (p: string) => p.startsWith(path.join(home, ".Trash")),
  trashItem: async () => {
    throw new Error("unexpected trashItem");
  },
  removeWorktree: async () => {
    throw new Error("unexpected removeWorktree");
  },
  ...extra,
});

test("R8-B26: happy path removes Trash directory entry by entry", async () => {
  const { base, home, trash, gate } = setup();
  try {
    const d = makeTree(trash, "proj", ["src/a.rs", "b.txt"]);
    const cands: RemediationCandidate[] = [{ id: "p", path: d, bytes: 2, kind: "dir" }];
    gate.registerApprovedCandidates(cands);
    const plan = gate.createDryRunPlan(cands);
    const auth = gate.authorizeExecute({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
    assert.equal(auth.allowed, true);
    const res = await executePlanItems(auth.plan!, auth.identities!, deps(home));
    assert.deepEqual(res.removed, [d]);
    assert.equal(fs.existsSync(d), false);
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("R8-B26: a protected file injected between authorization and deletion blocks the item and nothing in it is deleted", async () => {
  const { base, home, trash, gate } = setup();
  try {
    const d1 = makeTree(trash, "one", ["a.txt"]);
    const d2 = makeTree(trash, "two", ["src/main.rs", "keep.txt"]);
    const cands: RemediationCandidate[] = [
      { id: "1", path: d1, bytes: 1, kind: "dir" },
      { id: "2", path: d2, bytes: 1, kind: "dir" },
    ];
    gate.registerApprovedCandidates(cands);
    const plan = gate.createDryRunPlan(cands);
    const auth = gate.authorizeExecute({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
    assert.equal(auth.allowed, true);
    const res = await executePlanItems(
      auth.plan!,
      auth.identities!,
      deps(home, {
        // runs while item 1 is "awaiting": a protected .env appears in item 2's directory
        afterItem: (it: { path: string }) => {
          if (it.path === d1) fs.writeFileSync(path.join(d2, ".env"), "SECRET=1");
        },
      })
    );
    assert.deepEqual(res.removed, [d1]);
    assert.equal(res.failed.length, 1);
    assert.match(res.failed[0].error, /protected_descendant|protected_target/);
    assert.equal(fs.existsSync(path.join(d2, ".env")), true, ".env must survive");
    assert.equal(fs.existsSync(path.join(d2, "keep.txt")), true, "nothing in the blocked item is deleted");
    assert.equal(fs.existsSync(path.join(d2, "src", "main.rs")), true);
    assert.equal(res.executed, false);
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("R8-B26: identity mismatch (directory replaced by a symlink or another inode after planning) fails closed", async () => {
  const { base, home, trash, gate } = setup();
  try {
    const victim = makeTree(base, "victim", ["precious.txt"]);
    const d = makeTree(trash, "swap", ["a.txt"]);
    const cands: RemediationCandidate[] = [{ id: "s", path: d, bytes: 1, kind: "dir" }];
    gate.registerApprovedCandidates(cands);
    const plan = gate.createDryRunPlan(cands);
    const auth = gate.authorizeExecute({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
    fs.rmSync(d, { recursive: true });
    fs.symlinkSync(victim, d);
    const res = await executePlanItems(auth.plan!, auth.identities!, deps(home));
    assert.deepEqual(res.removed, []);
    assert.match(res.failed[0].error, /identity_mismatch|symlink/);
    assert.equal(fs.existsSync(path.join(victim, "precious.txt")), true);
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("R8-B26: a protected entry that appears after the pre-check but before the directory is removed survives (rmdir is non-recursive)", async () => {
  const { base, home, trash, gate } = setup();
  try {
    const d = makeTree(trash, "race", ["a.txt", "sub/b.txt"]);
    const cands: RemediationCandidate[] = [{ id: "r", path: d, bytes: 1, kind: "dir" }];
    gate.registerApprovedCandidates(cands);
    const plan = gate.createDryRunPlan(cands);
    const auth = gate.authorizeExecute({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
    const res = await executePlanItems(
      auth.plan!,
      auth.identities!,
      deps(home, {
        beforeUnlink: (() => {
          let fired = false;
          return () => {
            if (!fired) {
              fired = true;
              fs.writeFileSync(path.join(d, ".env"), "late");
            }
          };
        })(),
      })
    );
    assert.equal(res.executed, false);
    assert.equal(fs.existsSync(path.join(d, ".env")), true, "late .env must survive");
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});
