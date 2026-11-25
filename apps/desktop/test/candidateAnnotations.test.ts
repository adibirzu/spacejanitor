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

test("R4: a verified standalone orphan clone (kind git-repo from sj) stays an orphan through annotation, plan and execute; opt-in off refuses it", async () => {
  const crypto = await import("node:crypto");
  const { RemediationGate } = await import("../src/remediationGate");
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const core = require("@spacejanitor/core");
  const clone = "/w/standalone_clone";
  const linked = "/w/wt_linked";
  // exactly what the host sees: sj's orphans report normalised by core (is_worktree false => git-repo)
  const orphansReport = core.normalizeReportEnvelope({
    schema: "spacejanitor.orphans.v1",
    root: "/w",
    safe_to_prune: [
      { path: clone, is_worktree: false, bytes: 7 },
      { path: linked, is_worktree: true, bytes: 5 },
    ],
    blocked: [],
  });
  assert.equal(orphansReport.candidates.find((c: { path: string }) => c.path === clone).kind, "git-repo");
  const annotated = annotateSummary({ trash: { candidates: [] }, orphans: orphansReport }, protectFn({}));
  const approved = approvedFromSummary(annotated);
  assert.deepEqual(approved.map((a) => [a.path, a.kind]).sort(), [[clone, "git-worktree"], [linked, "git-worktree"]]);

  // a fake sj that plans orphan items only when --include-orphans is passed (as the real one does)
  const sha = (x: string) => crypto.createHash("sha256").update(x).digest("hex");
  const calls: string[][] = [];
  const items = [clone, linked].map((p) => ({ id: `item_${sha(p).slice(0, 6)}`, kind: "orphan_worktree", path: p, bytes: 3, snapshot: { rev: 1 } }));
  const run = async (args: string[]) => {
    calls.push(args);
    const withOrphans = args.includes("--include-orphans");
    const planned = withOrphans ? items : [];
    const selects: string[] = [];
    args.forEach((a, i) => a === "--select" && selects.push(args[i + 1]));
    const matched = planned.filter((i) => selects.includes(i.path)).sort((a, b) => a.path.localeCompare(b.path));
    if (args.includes("--execute")) {
      return { mode: "executed", selection_sha256: args[args.indexOf("--selection-sha256") + 1], executed_items: matched, failed_items: [] };
    }
    return {
      schema: "spacejanitor.proposal.v1",
      mode: "dry-run",
      mutated: false,
      plan_sha256: "a".repeat(64),
      items: planned,
      protected_exclusions: [],
      selection: {
        paths: matched.map((m) => m.path),
        ids: matched.map((m) => m.id),
        unmatched: selects.filter((p) => !matched.some((m) => m.path === p)),
        selection_sha256: sha(JSON.stringify(matched)),
      },
    };
  };

  // opt-in ON: --include-orphans is sent (and no --include-trash: nothing trash was selected), both clones planned
  const on = new RemediationGate({ runSj: run, planRoot: "/w", orphanScanEnabled: () => true });
  on.registerApprovedCandidates(approved);
  const plan = await on.createDryRunPlan(approved);
  assert.deepEqual(plan.items.map((i) => i.path).sort(), [clone, linked]);
  assert.ok(calls[0].includes("--include-orphans") && !calls[0].includes("--include-trash"), calls[0].join(" "));
  const res = await on.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
  assert.equal(res.executed, true);
  assert.ok(calls[1].includes("--include-orphans") && calls[1].includes("--execute"));

  // opt-in OFF: the same selection is not planned, sj is not even asked, and execution is refused
  calls.length = 0;
  const off = new RemediationGate({ runSj: run, planRoot: "/w", orphanScanEnabled: () => false });
  off.registerApprovedCandidates(approved);
  const offPlan = await off.createDryRunPlan(approved);
  assert.equal(offPlan.items.length, 0);
  assert.deepEqual(offPlan.blockedItems.map((b) => b.reason), ["not_in_sj_plan", "not_in_sj_plan"]);
  assert.equal(calls.length, 0);
  assert.equal((await off.run({ planSha256: offPlan.planSha256, phrase: offPlan.confirmationPhrase })).error, "empty_or_missing_plan");

  // defense in depth: a candidate registered with the raw sj kind is still treated as an orphan by the gate
  calls.length = 0;
  const raw = new RemediationGate({ runSj: run, planRoot: "/w", orphanScanEnabled: () => true });
  raw.registerApprovedCandidates([{ id: "x", path: clone, bytes: 1, kind: "git-repo" as unknown as "file" }]);
  const rawPlan = await raw.createDryRunPlan([{ id: "x", path: clone, bytes: 1, kind: "file" }]);
  assert.equal(rawPlan.items.length, 1);
  assert.ok(calls[0].includes("--include-orphans"));
});

test("R4: no other candidate kind is downgraded to file: only trash rows keep file/dir, every orphan row is a git-worktree", () => {
  const summary = {
    trash: { candidates: [{ id: "t1", path: "/h/.Trash/a", bytes: 1, kind: "dir" }, { id: "t2", path: "/h/.Trash/b", bytes: 1, kind: "file" }] },
    orphans: {
      candidates: [
        { id: "o1", path: "/w/a", kind: "git-repo", safeToPrune: true },
        { id: "o2", path: "/w/b", kind: "git-worktree", safeToPrune: true },
        { id: "o3", path: "/w/c", kind: "something-new", safeToPrune: true },
      ],
    },
  } as Record<string, unknown>;
  const approved = approvedFromSummary(annotateSummary(summary, protectFn({})));
  const kinds = Object.fromEntries(approved.map((a) => [a.id, a.kind]));
  assert.deepEqual(kinds, { t1: "dir", t2: "file", o1: "git-worktree", o2: "git-worktree", o3: "git-worktree" });
});
