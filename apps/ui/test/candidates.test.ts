import assert from "node:assert/strict";
import test from "node:test";
import { buildCandidateLists } from "../src/candidates.js";

const base = { bytes: 1, kind: "dir" as const };

test("selectable list holds only items the gate accepts; caches and protected items are shown blocked with a reason", () => {
  const lists = buildCandidateLists({
    cleanableCaches: [{ id: "c1", path: "/h/.cache/npm", ...base, selectable: false, blockedReason: "not_planned_by_sj: caches" }],
    trash: {
      candidates: [
        { id: "t1", path: "/h/.Trash/a", ...base, selectable: true },
        { id: "t2", path: "/h/.Trash/v.kdbx", ...base, selectable: false, blockedReason: "protected_key_ext:*.kdbx" },
        { id: "t3", path: "/h/.Trash/legacy", ...base },
      ],
    },
    orphans: { candidates: [{ id: "o1", path: "/w/wt", kind: "git-worktree", safeToPrune: true, selectable: true }, { id: "o2", path: "/w/x", kind: "git-worktree", safeToPrune: false }] },
  });
  assert.deepEqual(lists.selectable.map((c) => c.id), ["t1", "o1"]);
  assert.deepEqual(lists.blocked.map((c) => [c.id, c.blockedReason]), [
    ["c1", "not_planned_by_sj: caches"],
    ["t2", "protected_key_ext:*.kdbx"],
    ["t3", "not_checked_by_gate"],
  ]);
});

test("un-annotated items (older host) are not offered: the UI never guesses what the gate would accept", () => {
  const lists = buildCandidateLists({
    cleanableCaches: [{ id: "c1", path: "/h/.cache/npm", ...base }],
    trash: { candidates: [{ id: "t1", path: "/h/.Trash/a", ...base }] },
    orphans: { candidates: [] },
  });
  assert.deepEqual(lists.selectable, []);
  assert.equal(lists.blocked.length, 2);
  assert.ok(lists.blocked.every((c) => c.blockedReason));
});

test("protected flagged items are blocked even if marked selectable", () => {
  const lists = buildCandidateLists({
    trash: { candidates: [{ id: "t1", path: "/h/.Trash/a", ...base, selectable: true, protected: true, protectedReason: "protected_root" }] },
  });
  assert.deepEqual(lists.selectable, []);
  assert.equal(lists.blocked[0].blockedReason, "protected_root");
});
