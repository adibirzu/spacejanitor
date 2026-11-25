import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { RemediationGate, RunSj } from "../src/remediationGate";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const core = require("@spacejanitor/core");

const SHA = "a".repeat(64);

function item(p: string, id = `item_${p.length}`, kind = "trash_item", bytes = 10) {
  return {
    id,
    kind,
    path: p,
    bytes,
    tier: "tier1",
    safety_reasons: ["os_trash_item"],
    snapshot: { entry_type: "file", size: bytes },
  };
}

function sjPlan(items: ReturnType<typeof item>[], extra: Record<string, unknown> = {}, sha = SHA) {
  return {
    schema: "spacejanitor.proposal.v1",
    mode: "dry-run",
    mutated: false,
    plan_sha256: sha,
    total_reclaimable_bytes: items.reduce((a, i) => a + i.bytes, 0),
    items,
    protected_exclusions: [],
    ...extra,
  };
}

/** A scripted stand-in for the sj binary: records every call and answers from `handler`. */
function fakeSj(handler: (args: string[]) => unknown): { run: RunSj; calls: string[][] } {
  const calls: string[][] = [];
  const run: RunSj = async (args) => {
    calls.push(args);
    const out = handler(args);
    if (out instanceof Error) throw out;
    return out as Record<string, unknown>;
  };
  return { run, calls };
}

const cand = (p: string, bytes = 1, kind: "file" | "dir" | "git-worktree" = "file") => ({ id: p, path: p, bytes, kind });

test("plan comes from sj: item sizes/kinds/sha are sj's, renderer values are ignored", async () => {
  const sj = fakeSj(() => sjPlan([item("/h/.Trash/a", "item_a", "trash_item", 77)]));
  const gate = new RemediationGate({ runSj: sj.run, planRoot: "/h/work" });
  gate.registerApprovedCandidates([cand("/h/.Trash/a", 1)]);
  const plan = await gate.createDryRunPlan([cand("/h/.Trash/a", 999999)]);
  assert.equal(plan.planSha256, SHA);
  assert.equal(plan.items.length, 1);
  assert.equal(plan.items[0].bytes, 77);
  assert.equal(plan.totalBytes, 77);
  assert.equal(plan.confirmationPhrase, "CONFIRM-AAAAAAAA");
  assert.deepEqual(sj.calls[0].slice(0, 3), ["plan", "/h/work", "--json"]);
});

test("candidates sj does not plan are blocked with sj's own exclusion reason (what old JS accepted)", async () => {
  const sj = fakeSj(() =>
    sjPlan([], { protected_exclusions: [{ path: "/h/proj", reason: "protected_descendant:protected_key_ext:*.pem" }] })
  );
  const gate = new RemediationGate({ runSj: sj.run, planRoot: "/h" });
  gate.registerApprovedCandidates([cand("/h/proj", 5, "dir"), cand("/h/other", 5, "dir")]);
  const plan = await gate.createDryRunPlan([cand("/h/proj", 5, "dir"), cand("/h/other", 5, "dir")]);
  assert.equal(plan.items.length, 0);
  assert.equal(plan.blockedItems.find((b) => b.path === "/h/proj")?.reason, "protected_descendant:protected_key_ext:*.pem");
  assert.equal(plan.blockedItems.find((b) => b.path === "/h/other")?.reason, "not_in_sj_plan");
});

test("missing sj fails closed: no plan, no execution, nothing deleted", async () => {
  const sj = fakeSj(() => new core.SjGateError("sj_unavailable"));
  const gate = new RemediationGate({ runSj: sj.run, planRoot: "/h" });
  gate.registerApprovedCandidates([cand("/h/.Trash/a")]);
  await assert.rejects(() => gate.createDryRunPlan([cand("/h/.Trash/a")]), /sj_unavailable/);
  const res = await gate.run({ planSha256: SHA, phrase: "CONFIRM-AAAAAAAA" });
  assert.equal(res.executed, false);
  assert.equal(res.error, "no_active_dry_run_plan");
  assert.equal(sj.calls.some((c) => c.includes("--execute")), false);
});

test("unparseable or malformed sj plans are refused (fail closed)", async () => {
  const bad: unknown[] = [
    { schema: "other.v1" },
    sjPlan([item("/h/a")], { mutated: true }),
    sjPlan([item("/h/a")], { mode: "executed" }),
    sjPlan([item("/h/a")], {}, "not-a-sha"),
    sjPlan([item("/h/a")], { items: "nope" }),
    { ...sjPlan([item("/h/a")]), items: [{ id: "x", path: 7 }] },
  ];
  for (const raw of bad) {
    const gate = new RemediationGate({ runSj: fakeSj(() => raw).run, planRoot: "/h" });
    gate.registerApprovedCandidates([cand("/h/a")]);
    await assert.rejects(() => gate.createDryRunPlan([cand("/h/a")]), /sj_unparseable/, JSON.stringify(raw).slice(0, 60));
  }
});

test("only main-process-approved candidates may be planned", async () => {
  const sj = fakeSj(() => sjPlan([item("/h/a")]));
  const gate = new RemediationGate({ runSj: sj.run, planRoot: "/h" });
  await assert.rejects(() => gate.createDryRunPlan([cand("/h/a")]), /unapproved_candidate/);
  assert.equal(sj.calls.length, 0);
});

test("execute: wrong sha, wrong phrase, expiry, reuse and concurrent runs are refused before sj is asked to delete", async () => {
  const exec = (args: string[]) =>
    args.includes("--execute")
      ? { schema: "spacejanitor.proposal.v1", mode: "executed", mutated: true, plan_sha256: SHA, executed_item: item("/h/.Trash/a", "item_a") }
      : sjPlan([item("/h/.Trash/a", "item_a")]);
  const sj = fakeSj(exec);
  const gate = new RemediationGate({ runSj: sj.run, planRoot: "/h" });
  gate.registerApprovedCandidates([cand("/h/.Trash/a")]);
  const plan = await gate.createDryRunPlan([cand("/h/.Trash/a")], 1000);
  assert.equal((await gate.run({ planSha256: "b".repeat(64), phrase: plan.confirmationPhrase, nowMs: 1001 })).error, "plan_sha256_mismatch");
  assert.equal((await gate.run({ planSha256: SHA, phrase: "CONFIRM-NOPE", nowMs: 1001 })).error, "confirmation_phrase_mismatch");
  assert.equal((await gate.run({ planSha256: SHA, phrase: plan.confirmationPhrase, nowMs: plan.expiresAtMs + 1 })).error, "confirmation_token_expired");
  assert.equal(sj.calls.some((c) => c.includes("--execute")), false);

  const ok = await gate.run({ planSha256: SHA, phrase: plan.confirmationPhrase, nowMs: 1001 });
  assert.equal(ok.executed, true);
  assert.deepEqual(ok.removed, ["/h/.Trash/a"]);
  const reuse = await gate.run({ planSha256: SHA, phrase: plan.confirmationPhrase, nowMs: 1002 });
  assert.equal(reuse.error, "no_active_dry_run_plan", "a consumed plan cannot be replayed");
});

test("a failed or cancelled cleanup can be retried: sj's digest is content-addressed, so re-planning the same items works again", async () => {
  const a = item("/h/.Trash/a", "item_a");
  let fail = true;
  const sj = fakeSj((args) => {
    if (!args.includes("--execute")) return sjPlan([a]);
    if (fail) return new core.SjGateError("sj_exit_2");
    return { schema: "spacejanitor.proposal.v1", mode: "executed", mutated: true, plan_sha256: SHA, executed_item: a };
  });
  const gate = new RemediationGate({ runSj: sj.run, planRoot: "/h" });
  gate.registerApprovedCandidates([cand(a.path)]);
  const p1 = await gate.createDryRunPlan([cand(a.path)]);
  assert.equal((await gate.run({ planSha256: p1.planSha256, phrase: p1.confirmationPhrase })).executed, false);
  fail = false;
  const p2 = await gate.createDryRunPlan([cand(a.path)]);
  assert.equal(p2.planSha256, p1.planSha256, "same leftovers hash to the same sj digest");
  const res = await gate.run({ planSha256: p2.planSha256, phrase: p2.confirmationPhrase });
  assert.equal(res.executed, true);
});

test("a plan that changed since confirmation aborts EVERY item, not just the first", async () => {
  const items = [item("/h/.Trash/a", "item_a"), item("/h/.Trash/b", "item_b")];
  let phase = 0;
  const sj = fakeSj((args) => {
    if (args.includes("--execute")) return new Error("must not execute");
    phase += 1;
    // confirmed plan has both items; by execution time sj reports a different set (new digest)
    return phase === 1 ? sjPlan(items) : sjPlan(items, {}, "d".repeat(64));
  });
  const gate = new RemediationGate({ runSj: sj.run, planRoot: "/h" });
  gate.registerApprovedCandidates(items.map((i) => cand(i.path)));
  const plan = await gate.createDryRunPlan(items.map((i) => cand(i.path)));
  const res = await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
  assert.equal(res.executed, false);
  assert.deepEqual(res.removed, []);
  assert.deepEqual(
    (res.failed as Array<{ error: string }>).map((f) => f.error),
    ["plan_changed_since_confirmation", "plan_changed_since_confirmation"]
  );
  assert.equal(sj.calls.some((c) => c.includes("--execute")), false);
});

test("execute: every deletion is an sj --execute call bound to the fresh plan sha and item id", async () => {
  const items = [item("/h/.Trash/a", "item_a"), item("/h/.Trash/b", "item_b")];
  let remaining = [...items];
  const sj = fakeSj((args) => {
    if (!args.includes("--execute")) return sjPlan(remaining, {}, remaining.length === 2 ? SHA : "c".repeat(64));
    const id = args[args.indexOf("--item") + 1];
    const sha = args[args.indexOf("--plan-sha256") + 1];
    assert.equal(sha, remaining.length === 2 ? SHA : "c".repeat(64), "sha must be the freshly planned one");
    const done = remaining.find((i) => i.id === id)!;
    remaining = remaining.filter((i) => i.id !== id);
    return { schema: "spacejanitor.proposal.v1", mode: "executed", mutated: true, plan_sha256: sha, executed_item: done };
  });
  const gate = new RemediationGate({ runSj: sj.run, planRoot: "/h" });
  gate.registerApprovedCandidates(items.map((i) => cand(i.path)));
  const plan = await gate.createDryRunPlan(items.map((i) => cand(i.path)));
  const res = await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
  assert.equal(res.executed, true);
  assert.deepEqual(res.removed, ["/h/.Trash/a", "/h/.Trash/b"]);
  const execCalls = sj.calls.filter((c) => c.includes("--execute"));
  assert.equal(execCalls.length, 2);
  for (const c of execCalls) assert.ok(c.includes("--confirm"));
});

test("execute: an item that changed since the plan, or an sj rejection, is reported failed and never retried", async () => {
  const a = item("/h/.Trash/a", "item_a");
  const changed = { ...a, snapshot: { entry_type: "file", size: 999 } };
  // plan with the original snapshot, then let sj report a changed one at execute time
  let phase = 0;
  const sj = fakeSj((args) => {
    if (args.includes("--execute")) return new core.SjGateError("sj_exit_2");
    phase += 1;
    return sjPlan([phase === 1 ? a : changed]);
  });
  const gate = new RemediationGate({ runSj: sj.run, planRoot: "/h" });
  gate.registerApprovedCandidates([cand(a.path)]);
  const plan = await gate.createDryRunPlan([cand(a.path)]);
  const res = await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
  assert.equal(res.executed, false);
  assert.equal((res.failed as Array<{ error: string }>)[0].error, "item_changed_since_plan");
  assert.equal(sj.calls.some((c) => c.includes("--execute")), false);

  const sj3 = fakeSj((args) => (args.includes("--execute") ? new core.SjGateError("sj_exit_2") : sjPlan([a])));
  const gate3 = new RemediationGate({ runSj: sj3.run, planRoot: "/h" });
  gate3.registerApprovedCandidates([cand(a.path)]);
  const plan3 = await gate3.createDryRunPlan([cand(a.path)]);
  const res3 = await gate3.run({ planSha256: plan3.planSha256, phrase: plan3.confirmationPhrase });
  assert.equal(res3.executed, false);
  assert.deepEqual(res3.removed, []);
  assert.equal((res3.failed as Array<{ error: string }>)[0].error, "sj_exit_2");
  assert.equal(sj3.calls.filter((c) => c.includes("--execute")).length, 1);
});

test("execute: sj missing/timing out/garbage mid-run refuses the destructive step", async () => {
  for (const reason of ["sj_unavailable", "sj_timeout", "sj_unparseable"]) {
    const a = item("/h/.Trash/a", "item_a");
    let planned = false;
    const sj = fakeSj((args) => {
      if (!planned) {
        planned = true;
        return sjPlan([a]);
      }
      return new core.SjGateError(reason);
    });
    const gate = new RemediationGate({ runSj: sj.run, planRoot: "/h" });
    gate.registerApprovedCandidates([cand(a.path)]);
    const plan = await gate.createDryRunPlan([cand(a.path)]);
    const res = await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
    assert.equal(res.executed, false, reason);
    assert.deepEqual(res.removed, [], reason);
    assert.equal((res.failed as Array<{ error: string }>)[0].error, reason);
  }
});

test("execute: an sj result that does not confirm the item is not counted as removed", async () => {
  const a = item("/h/.Trash/a", "item_a");
  const sj = fakeSj((args) =>
    args.includes("--execute") ? { schema: "spacejanitor.proposal.v1", mode: "dry-run", mutated: false } : sjPlan([a])
  );
  const gate = new RemediationGate({ runSj: sj.run, planRoot: "/h" });
  gate.registerApprovedCandidates([cand(a.path)]);
  const plan = await gate.createDryRunPlan([cand(a.path)]);
  const res = await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
  assert.equal(res.executed, false);
  assert.deepEqual(res.removed, []);
});

test("no JavaScript gate logic remains: core no longer exports a denylist, plan builder, descendant walker or worktree proof", () => {
  for (const name of ["DEFAULT_PROTECTED_PATTERNS", "createRemediationPlan", "verifyRemediationGate", "inspectWorktree", "removeLinkedWorktree", "classifyExecutableConfigKey"]) {
    assert.equal(core[name], undefined, `core must not export ${name}`);
  }
  assert.equal(fs.existsSync(path.join(__dirname, "../../src/worktreeGuard.ts")), false);
  assert.equal(fs.existsSync(path.join(__dirname, "../../src/worktreeGuard.js")), false);
});

// ---- integration against the real Rust binary ----
const exeName = process.platform === "win32" ? "sj.exe" : "sj";
const repoRoot = path.resolve(__dirname, "../../../..");
const REAL_SJ = ["release", "debug"].map((p) => path.join(repoRoot, "target", p, exeName)).find((p) => fs.existsSync(p));
const integrationSkip = !REAL_SJ || process.env.SPACEJANITOR_NO_SJ === "1" || process.platform === "win32";

test("integration: the real sj plans and removes an OS-Trash item; a protected-descendant tree is refused", { skip: integrationSkip }, async () => {
  const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sj-gate-home-")));
  const trash = process.platform === "darwin" ? path.join(home, ".Trash") : path.join(home, ".local", "share", "Trash", "files");
  try {
    fs.mkdirSync(trash, { recursive: true });
    fs.writeFileSync(path.join(trash, "junk.bin"), "x".repeat(64));
    fs.mkdirSync(path.join(trash, "proj"));
    fs.writeFileSync(path.join(trash, "proj", ".env.production"), "SECRET=1");
    core.configureSjBinary(REAL_SJ);
    const runReal: RunSj = (args, opts) => core.runSj(args, { ...opts, homeDir: home });
    const gate = new RemediationGate({ runSj: runReal, planRoot: home, homeDir: home });
    const cands = [cand(path.join(trash, "junk.bin"), 1), cand(path.join(trash, "proj"), 1, "dir")];
    gate.registerApprovedCandidates(cands);
    const plan = await gate.createDryRunPlan(cands);
    assert.deepEqual(plan.items.map((i) => path.basename(i.path)), ["junk.bin"]);
    assert.ok(plan.blockedItems.some((b) => b.path.endsWith("proj")), "tree holding .env.production must be blocked by sj");
    const res = await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
    assert.equal(res.executed, true, JSON.stringify(res));
    assert.equal(fs.existsSync(path.join(trash, "junk.bin")), false);
    assert.equal(fs.existsSync(path.join(trash, "proj", ".env.production")), true, "protected tree must survive");
  } finally {
    core.configureSjBinary(undefined);
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("orphan worktrees are planned and executed only with the main-process opt-in (default OFF: no --include-orphans)", async () => {
  for (const enabled of [false, true]) {
    const a = item("/h/.Trash/a", "item_a");
    const sj = fakeSj((args) =>
      args.includes("--execute")
        ? { schema: "spacejanitor.proposal.v1", mode: "executed", mutated: true, plan_sha256: SHA, executed_item: a }
        : sjPlan([a])
    );
    const gate = new RemediationGate({ runSj: sj.run, planRoot: "/h", orphanScanEnabled: () => enabled });
    gate.registerApprovedCandidates([cand(a.path)]);
    const plan = await gate.createDryRunPlan([cand(a.path)]);
    await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
    assert.ok(sj.calls.length >= 3);
    for (const c of sj.calls) assert.equal(c.includes("--include-orphans"), enabled, c.join(" "));
  }
});

test("sj stderr and error text are redacted before they leave the main process (execute result and errors)", async () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { urlWith } = require("../../../../packages/core/test/_fixtures.mjs");
  const secretUrl = urlWith("https", "alice", "superSecretPass99", "git.example.com/r.git");
  const tokenFlag = ["--token", "tokSecret99"].join("=");
  const stderr = `error: git remote ${secretUrl} ${tokenFlag} failed`;
  const a = item("/h/.Trash/a", "item_a");
  const sj = fakeSj((args) => {
    if (!args.includes("--execute")) return sjPlan([a]);
    const e = new core.SjGateError("sj_exit_2");
    (e as unknown as { stderr: string }).stderr = stderr;
    return e;
  });
  const gate = new RemediationGate({ runSj: sj.run, planRoot: "/h" });
  gate.registerApprovedCandidates([cand(a.path)]);
  const plan = await gate.createDryRunPlan([cand(a.path)]);
  const res = await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
  const text = JSON.stringify(res);
  for (const leak of ["superSecretPass99", "tokSecret99"]) assert.equal(text.includes(leak), false, `leaked ${leak}: ${text}`);
  assert.match((res.failed as Array<{ error: string }>)[0].error, /^sj_exit_2/);

  // a plain Error carrying a secret (not an SjGateError) is redacted as well
  const sj2 = fakeSj((args) => (args.includes("--execute") ? new Error(`boom ${secretUrl} ${["--password", "pwSecret77"].join("=")}`) : sjPlan([a])));
  const gate2 = new RemediationGate({ runSj: sj2.run, planRoot: "/h" });
  gate2.registerApprovedCandidates([cand(a.path)]);
  const plan2 = await gate2.createDryRunPlan([cand(a.path)]);
  const res2 = await gate2.run({ planSha256: plan2.planSha256, phrase: plan2.confirmationPhrase });
  const text2 = JSON.stringify(res2);
  for (const leak of ["superSecretPass99", "pwSecret77"]) assert.equal(text2.includes(leak), false, `leaked ${leak}: ${text2}`);
});
