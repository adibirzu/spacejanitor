import assert from "node:assert/strict";
import test from "node:test";
import { annotateSummary, approvedFromSummary } from "../src/candidateAnnotations";

type Verdict = { path: string; protected: boolean; reason: string };
const protectFn = (blocked: Record<string, string>) => (paths: string[]): Verdict[] =>
  paths.map((p) => ({ path: p, protected: p in blocked, reason: blocked[p] || "" }));

function summary() {
  return {
    cleanableCaches: [{ id: "c1", path: "/h/.cache/npm", bytes: 5, kind: "dir" }],
    trash: {
      candidates: [
        { id: "t1", path: "/h/.Trash/junk.bin", bytes: 3, kind: "file" },
        { id: "t2", path: "/h/.Trash/vault.kdbx", bytes: 9, kind: "file" },
      ],
    },
    orphans: {
      candidates: [
        { id: "o1", path: "/w/wt1", kind: "git-worktree", safeToPrune: true },
        { id: "o2", path: "/w/wt2", kind: "git-worktree", safeToPrune: false },
      ],
    },
  } as Record<string, unknown>;
}

test("UI candidates and the gate agree: caches are never selectable, sj-protected items are blocked with sj's reason", () => {
  const out = annotateSummary(summary(), protectFn({ "/h/.Trash/vault.kdbx": "protected_key_ext:*.kdbx" })) as ReturnType<typeof summary>;
  const caches = out.cleanableCaches as Array<{ selectable: boolean; blockedReason: string }>;
  assert.equal(caches[0].selectable, false);
  assert.match(caches[0].blockedReason, /^not_planned_by_sj/);
  const trash = (out.trash as { candidates: Array<{ id: string; selectable: boolean; blockedReason?: string }> }).candidates;
  assert.equal(trash.find((t) => t.id === "t1")!.selectable, true);
  assert.equal(trash.find((t) => t.id === "t2")!.selectable, false);
  assert.equal(trash.find((t) => t.id === "t2")!.blockedReason, "protected_key_ext:*.kdbx");
  const orphans = (out.orphans as { candidates: Array<{ id: string; selectable?: boolean }> }).candidates;
  assert.equal(orphans.find((o) => o.id === "o1")!.selectable, true);
});

test("only selectable trash/orphan items are approved for planning; caches and protected items never are", () => {
  const out = annotateSummary(summary(), protectFn({ "/h/.Trash/vault.kdbx": "protected_key_ext:*.kdbx" }));
  assert.deepEqual(approvedFromSummary(out).map((c) => c.id).sort(), ["o1", "t1"]);
});

test("fail closed: when sj cannot judge, nothing is selectable or approved", () => {
  const failing = (paths: string[]): Verdict[] => paths.map((p) => ({ path: p, protected: true, reason: "sj_unavailable" }));
  const out = annotateSummary(summary(), failing);
  assert.deepEqual(approvedFromSummary(out), []);
  const throwing = () => {
    throw new Error("boom");
  };
  assert.deepEqual(approvedFromSummary(annotateSummary(summary(), throwing)), []);
});

test("a summary without candidates is passed through unchanged", () => {
  const empty = { trash: {}, orphans: { scanned: false } } as Record<string, unknown>;
  assert.deepEqual(approvedFromSummary(annotateSummary(empty, protectFn({}))), []);
});

test("plan flow: the gate refuses a cache even if a renderer asks for it, and plans only the accepted trash item", async () => {
  const { RemediationGate } = await import("../src/remediationGate");
  const sjPlan = {
    schema: "spacejanitor.proposal.v1",
    mode: "dry-run",
    mutated: false,
    plan_sha256: "a".repeat(64),
    items: [{ id: "item_t1", kind: "trash_item", path: "/h/.Trash/junk.bin", bytes: 3, snapshot: {} }],
    protected_exclusions: [],
    selection: { paths: ["/h/.Trash/junk.bin"], ids: ["item_t1"], unmatched: [], selection_sha256: "c".repeat(64) },
  };
  const gate = new RemediationGate({ runSj: async () => sjPlan, planRoot: "/h" });
  const annotated = annotateSummary(summary(), protectFn({ "/h/.Trash/vault.kdbx": "protected_key_ext:*.kdbx" }));
  gate.registerApprovedCandidates(approvedFromSummary(annotated));
  await assert.rejects(() => gate.createDryRunPlan([{ id: "c1", path: "/h/.cache/npm", bytes: 5, kind: "dir" }]), /unapproved_candidate/);
  await assert.rejects(() => gate.createDryRunPlan([{ id: "t2", path: "/h/.Trash/vault.kdbx", bytes: 9, kind: "file" }]), /unapproved_candidate/);
  const plan = await gate.createDryRunPlan([{ id: "t1", path: "/h/.Trash/junk.bin", bytes: 3, kind: "file" }]);
  assert.deepEqual(plan.items.map((i) => i.path), ["/h/.Trash/junk.bin"]);
});

test("annotation uses the same rule options as the plan: protectWithRules forwards exact/dynamic/glob to sj", async () => {
  const fs = await import("node:fs");
  const path = await import("node:path");
  const repoRoot = path.resolve(__dirname, "../../../..");
  const exe = process.platform === "win32" ? "sj.exe" : "sj";
  const sjBin = ["release", "debug"].map((p) => path.join(repoRoot, "target", p, exe)).find((p) => fs.existsSync(p));
  if (!sjBin || process.env.SPACEJANITOR_NO_SJ === "1") return;
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const core = require("@spacejanitor/core");
  const { protectWithRules } = await import("../src/candidateAnnotations");
  core.configureSjBinary(sjBin);
  try {
    const rules = { exactPaths: ["/data/keep"], dynamicProtectedPaths: ["/work/active"], globPatterns: ["*.vaultx"] };
    const paths = ["/data/keep/a", "/work/active/b", "/data/c.vaultx", "/data/other"];
    assert.deepEqual(protectWithRules(rules)(paths).map((r) => r.protected), [true, true, true, false]);
    assert.deepEqual(protectWithRules({})(paths).map((r) => r.protected), [false, false, false, false]);
  } finally {
    core.configureSjBinary(undefined);
  }
});
