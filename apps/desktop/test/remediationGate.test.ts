import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { RemediationGate, RunSj } from "../src/remediationGate";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const core = require("@spacejanitor/core");

const sha = (x: string) => crypto.createHash("sha256").update(x).digest("hex");

interface FakeItem {
  id: string;
  kind: string;
  path: string;
  bytes: number;
  tier: string;
  snapshot: { rev: number };
}

/**
 * A scripted stand-in for the Rust sj plan/execute protocol: it keeps an in-memory trash, hashes the
 * whole plan and any selection exactly like sj does conceptually (selection digest over the sorted,
 * de-duplicated selected items including their identity snapshot), and refuses an execute whose
 * selection digest does not match the freshly built plan.
 */
function sjWorld(paths: string[]) {
  const items = new Map<string, FakeItem>();
  for (const p of paths) {
    items.set(p, { id: `item_${sha(p).slice(0, 6)}`, kind: "trash_item", path: p, bytes: 10, tier: "tier1", snapshot: { rev: 1 } });
  }
  const calls: string[][] = [];
  const executedPaths: string[] = [];
  const all = () => [...items.values()].sort((a, b) => a.path.localeCompare(b.path));
  const select = (wanted: string[]) => {
    const uniq = [...new Set(wanted)].sort();
    const matched = uniq.map((p) => items.get(p)).filter((i): i is FakeItem => Boolean(i));
    return { matched, unmatched: uniq.filter((p) => !items.has(p)) };
  };
  const selSha = (matched: FakeItem[]) => sha(`spacejanitor.selection.v1\n${JSON.stringify(matched)}`);
  const run: RunSj = async (args) => {
    calls.push(args);
    const selects: string[] = [];
    args.forEach((a, i) => {
      if (a === "--select") selects.push(args[i + 1]);
    });
    const plan: Record<string, unknown> = {
      schema: "spacejanitor.proposal.v1",
      mode: "dry-run",
      mutated: false,
      plan_sha256: sha(JSON.stringify(all())),
      total_reclaimable_bytes: 0,
      items: all(),
      protected_exclusions: [],
    };
    const { matched, unmatched } = select(selects);
    if (!args.includes("--execute")) {
      if (selects.length) {
        plan.selection = { paths: matched.map((m) => m.path), ids: matched.map((m) => m.id), unmatched, selection_sha256: selSha(matched) };
      }
      return plan;
    }
    const token = args[args.indexOf("--selection-sha256") + 1];
    if (!args.includes("--confirm") || !token || selects.length === 0) throw new core.SjGateError("sj_exit_2");
    if (unmatched.length || selSha(matched) !== token) {
      const e = new core.SjGateError("sj_exit_2");
      (e as unknown as { stderr: string }).stderr = "selection_sha256 mismatch";
      throw e;
    }
    for (const m of matched) {
      items.delete(m.path);
      executedPaths.push(m.path);
    }
    return {
      schema: "spacejanitor.proposal.v1",
      mode: "executed",
      mutated: matched.length > 0,
      selection_sha256: token,
      executed_items: matched,
      failed_items: [],
    };
  };
  return {
    run,
    calls,
    executedPaths,
    has: (p: string) => items.has(p),
    touch: (p: string) => {
      items.get(p)!.snapshot.rev += 1;
    },
  };
}

const cand = (p: string, bytes = 1, kind: "file" | "dir" | "git-worktree" = "file") => ({ id: p, path: p, bytes, kind });
const A = "/h/.Trash/a.bin";
const B = "/h/.Trash/b.bin";
const C = "/h/.Trash/c.bin";

async function gateFor(world: ReturnType<typeof sjWorld>, extra: ConstructorParameters<typeof RemediationGate>[0] = {}) {
  const gate = new RemediationGate({ runSj: world.run, planRoot: "/h", ...extra });
  gate.registerApprovedCandidates([cand(A), cand(B), cand(C)]);
  return gate;
}

test("plan: sizes, kinds and the confirmation token come from sj; the token is sj's selection digest, not the whole-plan digest", async () => {
  const world = sjWorld([A, B, C]);
  const gate = await gateFor(world);
  const plan = await gate.createDryRunPlan([cand(A, 99999)]);
  assert.equal(plan.items[0].bytes, 10);
  assert.equal(plan.totalBytes, 10);
  assert.match(plan.planSha256, /^[0-9a-f]{64}$/);
  assert.equal(plan.confirmationPhrase, `CONFIRM-${plan.planSha256.slice(0, 8).toUpperCase()}`);
  const sentToSj = world.calls[0];
  assert.deepEqual(sentToSj.slice(0, 3), ["plan", "/h", "--json"]);
  assert.deepEqual(sentToSj.slice(3), ["--include-trash", "--select", A]);
});

test("B-R2-1: the token for A cannot execute A+B or B (nothing is deleted), and each selection has its own token", async () => {
  const world = sjWorld([A, B, C]);
  const gate = await gateFor(world);
  const p1 = await gate.createDryRunPlan([cand(A)]);
  const p2 = await gate.createDryRunPlan([cand(A), cand(B)]);
  assert.notEqual(p1.planSha256, p2.planSha256, "A and A+B must not share a token");
  assert.notEqual(p1.confirmationPhrase, p2.confirmationPhrase);
  // the user confirmed p1 in the modal, but the active plan is now A+B: the old token is refused
  const stale = await gate.run({ planSha256: p1.planSha256, phrase: p1.confirmationPhrase });
  assert.equal(stale.executed, false);
  assert.equal(stale.error, "plan_sha256_mismatch");
  assert.deepEqual(world.executedPaths, []);
  assert.ok(world.has(A) && world.has(B) && world.has(C));

  const p3 = await gate.createDryRunPlan([cand(B)]);
  assert.notEqual(p3.planSha256, p1.planSha256);
  assert.equal((await gate.run({ planSha256: p1.planSha256, phrase: p1.confirmationPhrase })).error, "plan_sha256_mismatch");
  assert.deepEqual(world.executedPaths, []);
});

test("B-R2-1: reordered and duplicated selections hash identically", async () => {
  const world = sjWorld([A, B, C]);
  const gate = await gateFor(world);
  const p1 = await gate.createDryRunPlan([cand(A), cand(B)]);
  const p2 = await gate.createDryRunPlan([cand(B), cand(A), cand(B)]);
  assert.equal(p1.planSha256, p2.planSha256);
  assert.deepEqual(p2.items.map((i) => i.path), [A, B]);
});

test("B-R2-1: the matching token executes exactly the confirmed selection, in one sj call carrying the same selection and digest", async () => {
  const world = sjWorld([A, B, C]);
  const gate = await gateFor(world);
  const plan = await gate.createDryRunPlan([cand(C), cand(A)]);
  const res = await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
  assert.equal(res.executed, true);
  assert.deepEqual(res.removed, [A, C]);
  assert.ok(world.has(B), "the unselected item survives");
  const exec = world.calls.filter((c) => c.includes("--execute"));
  assert.equal(exec.length, 1);
  assert.deepEqual(
    exec[0].slice(exec[0].indexOf("--select")),
    ["--select", A, "--select", C, "--execute", "--confirm", "--selection-sha256", plan.planSha256]
  );
});

test("B-R2-1: a selected item that changed between plan and execute is refused by sj and nothing is removed", async () => {
  const world = sjWorld([A, B]);
  const gate = await gateFor(world);
  const plan = await gate.createDryRunPlan([cand(A), cand(B)]);
  world.touch(B); // size/mtime/inode of B changed after the user inspected the plan
  const res = await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
  assert.equal(res.executed, false);
  assert.deepEqual(res.removed, []);
  assert.deepEqual((res.failed as Array<{ path: string }>).map((f) => f.path), [A, B]);
  assert.match((res.failed as Array<{ error: string }>)[0].error, /sj_exit_2/);
  assert.ok(world.has(A) && world.has(B));
});

test("candidates sj does not plan are blocked with sj's own exclusion reason or not_in_sj_plan", async () => {
  const sjRun: RunSj = async () => ({
    schema: "spacejanitor.proposal.v1",
    mode: "dry-run",
    mutated: false,
    plan_sha256: "a".repeat(64),
    items: [],
    protected_exclusions: [{ path: "/h/proj", reason: "protected_descendant:protected_key_ext:*.pem" }],
    selection: { paths: [], ids: [], unmatched: ["/h/other", "/h/proj"], selection_sha256: "b".repeat(64) },
  });
  const gate = new RemediationGate({ runSj: sjRun, planRoot: "/h" });
  gate.registerApprovedCandidates([cand("/h/proj", 5, "dir"), cand("/h/other", 5, "dir")]);
  const plan = await gate.createDryRunPlan([cand("/h/proj", 5, "dir"), cand("/h/other", 5, "dir")]);
  assert.equal(plan.items.length, 0);
  assert.equal(plan.blockedItems.find((b) => b.path === "/h/proj")?.reason, "protected_descendant:protected_key_ext:*.pem");
  assert.equal(plan.blockedItems.find((b) => b.path === "/h/other")?.reason, "not_in_sj_plan");
  const res = await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
  assert.equal(res.error, "empty_or_missing_plan");
});

test("missing sj fails closed: no plan, no execution, nothing deleted", async () => {
  const gate = new RemediationGate({
    runSj: async () => {
      throw new core.SjGateError("sj_unavailable");
    },
    planRoot: "/h",
  });
  gate.registerApprovedCandidates([cand(A)]);
  await assert.rejects(() => gate.createDryRunPlan([cand(A)]), /sj_unavailable/);
  const res = await gate.run({ planSha256: "a".repeat(64), phrase: "CONFIRM-AAAAAAAA" });
  assert.equal(res.executed, false);
  assert.equal(res.error, "no_active_dry_run_plan");
});

test("unparseable or malformed sj plans are refused (fail closed)", async () => {
  const good = (await (async () => {
    const w = sjWorld([A]);
    return w.run(["plan", "/h", "--json", "--select", A]);
  })()) as Record<string, unknown>;
  const bad: unknown[] = [
    { schema: "other.v1" },
    { ...good, mutated: true },
    { ...good, mode: "executed" },
    { ...good, plan_sha256: "not-a-sha" },
    { ...good, items: "nope" },
    { ...good, selection: undefined },
    { ...good, selection: { paths: [A], unmatched: [], selection_sha256: "short" } },
    { ...good, selection: { paths: ["/h/not-requested"], unmatched: [], selection_sha256: "c".repeat(64) } },
    { ...good, selection: { paths: [A], unmatched: "x", selection_sha256: "c".repeat(64) } },
    { ...good, items: [{ id: "x", path: 7 }] },
  ];
  for (const raw of bad) {
    const gate = new RemediationGate({ runSj: async () => raw as Record<string, unknown>, planRoot: "/h" });
    gate.registerApprovedCandidates([cand(A)]);
    await assert.rejects(() => gate.createDryRunPlan([cand(A)]), /sj_unparseable/, JSON.stringify(raw).slice(0, 80));
  }
});

test("only main-process-approved candidates may be planned", async () => {
  const world = sjWorld([A]);
  const gate = new RemediationGate({ runSj: world.run, planRoot: "/h" });
  await assert.rejects(() => gate.createDryRunPlan([cand(A)]), /unapproved_candidate/);
  assert.equal(world.calls.length, 0);
});

test("execute: wrong sha, wrong phrase, expiry and replay are refused before sj is asked to delete", async () => {
  const world = sjWorld([A]);
  const gate = await gateFor(world);
  const plan = await gate.createDryRunPlan([cand(A)], 1000);
  assert.equal((await gate.run({ planSha256: "b".repeat(64), phrase: plan.confirmationPhrase, nowMs: 1001 })).error, "plan_sha256_mismatch");
  assert.equal((await gate.run({ planSha256: plan.planSha256, phrase: "CONFIRM-NOPE", nowMs: 1001 })).error, "confirmation_phrase_mismatch");
  assert.equal((await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase, nowMs: plan.expiresAtMs + 1 })).error, "confirmation_token_expired");
  assert.equal(world.calls.some((c) => c.includes("--execute")), false);
  const ok = await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase, nowMs: 1001 });
  assert.equal(ok.executed, true);
  assert.equal((await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase, nowMs: 1002 })).error, "no_active_dry_run_plan");
});

test("a failed or cancelled cleanup can be retried: re-planning the same selection works again", async () => {
  let failOnce = true;
  const world = sjWorld([A]);
  const flaky: RunSj = async (args) => {
    if (args.includes("--execute") && failOnce) {
      failOnce = false;
      throw new core.SjGateError("sj_timeout");
    }
    return world.run(args);
  };
  const gate = new RemediationGate({ runSj: flaky, planRoot: "/h" });
  gate.registerApprovedCandidates([cand(A)]);
  const p1 = await gate.createDryRunPlan([cand(A)]);
  const r1 = await gate.run({ planSha256: p1.planSha256, phrase: p1.confirmationPhrase });
  assert.equal(r1.executed, false);
  assert.deepEqual(r1.removed, []);
  assert.ok(world.has(A));
  const p2 = await gate.createDryRunPlan([cand(A)]);
  assert.equal(p2.planSha256, p1.planSha256, "the same selection of unchanged items has the same token");
  assert.equal((await gate.run({ planSha256: p2.planSha256, phrase: p2.confirmationPhrase })).executed, true);
});

test("execute: sj missing/timing out/garbage mid-run refuses and reports every item failed", async () => {
  for (const reason of ["sj_unavailable", "sj_timeout", "sj_unparseable"]) {
    const world = sjWorld([A, B]);
    const run: RunSj = async (args) => {
      if (args.includes("--execute")) throw new core.SjGateError(reason);
      return world.run(args);
    };
    const gate = new RemediationGate({ runSj: run, planRoot: "/h" });
    gate.registerApprovedCandidates([cand(A), cand(B)]);
    const plan = await gate.createDryRunPlan([cand(A), cand(B)]);
    const res = await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
    assert.equal(res.executed, false, reason);
    assert.deepEqual(res.removed, [], reason);
    assert.deepEqual((res.failed as Array<{ error: string }>).map((f) => f.error), [reason, reason]);
  }
});

test("execute: an sj result that does not confirm the selection is not counted as removed", async () => {
  const world = sjWorld([A]);
  for (const out of [
    { schema: "spacejanitor.proposal.v1", mode: "dry-run", mutated: false },
    { mode: "executed", selection_sha256: "f".repeat(64), executed_items: [], failed_items: [] },
    { mode: "executed", executed_items: [{ path: "/h/never-confirmed" }], failed_items: [] },
  ]) {
    const run: RunSj = async (args) => (args.includes("--execute") ? (out as Record<string, unknown>) : world.run(args));
    const gate = new RemediationGate({ runSj: run, planRoot: "/h" });
    gate.registerApprovedCandidates([cand(A)]);
    const plan = await gate.createDryRunPlan([cand(A)]);
    const res = await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
    assert.equal(res.executed, false);
    assert.deepEqual(res.removed, []);
  }
});

test("partial results from sj are reported per item (redacted) and unreported items count as failed", async () => {
  const world = sjWorld([A, B, C]);
  const gate = await gateFor(world, {
    runSj: async (args) => {
      const out = (await world.run(args)) as Record<string, unknown>;
      if (!args.includes("--execute")) return out;
      return { ...out, executed_items: [{ path: A }], failed_items: [{ path: B, error: "device busy" }] };
    },
  });
  const plan = await gate.createDryRunPlan([cand(A), cand(B), cand(C)]);
  const res = await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
  assert.equal(res.partial, true);
  assert.deepEqual(res.removed, [A]);
  assert.deepEqual(res.failed, [
    { path: B, error: "device busy" },
    { path: C, error: "not_reported_by_sj" },
  ]);
});

test("B-R3-2: all orphans x trash combinations build the right sj plan flags on plan AND execute; orphans are only an extra", async () => {
  const WT = "/h/wt/feature";
  const cases: Array<{ name: string; orphansOn: boolean; select: Array<ReturnType<typeof cand>>; flags: string[] | null }> = [
    { name: "orphans off, trash selected (default, unchanged)", orphansOn: false, select: [cand(A)], flags: ["--include-trash"] },
    { name: "orphans on, trash only selected (no git needed)", orphansOn: true, select: [cand(A)], flags: ["--include-trash"] },
    { name: "orphans on, trash + worktree selected", orphansOn: true, select: [cand(A), cand(WT, 1, "git-worktree")], flags: ["--include-trash", "--include-orphans"] },
    { name: "orphans on, worktree only selected", orphansOn: true, select: [cand(WT, 1, "git-worktree")], flags: ["--include-orphans"] },
    { name: "orphans off, worktree only (nothing sj may plan)", orphansOn: false, select: [cand(WT, 1, "git-worktree")], flags: null },
  ];
  for (const c of cases) {
    const world = sjWorld([A, WT]);
    const gate = new RemediationGate({ runSj: world.run, planRoot: "/h", orphanScanEnabled: () => c.orphansOn });
    gate.registerApprovedCandidates([cand(A), cand(WT, 1, "git-worktree")]);
    const plan = await gate.createDryRunPlan(c.select);
    const include = (call: string[]) => call.filter((a) => a.startsWith("--include-"));
    if (c.name.includes("nothing sj may plan")) {
      assert.equal(world.calls.length, 0, c.name);
      assert.equal(plan.items.length, 0);
      assert.equal(plan.blockedItems[0].reason, "not_in_sj_plan");
      assert.equal((await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase })).error, "empty_or_missing_plan");
      continue;
    }
    assert.equal(plan.items.length, c.select.length, c.name);
    await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
    assert.equal(world.calls.length, 2, c.name);
    for (const call of world.calls) assert.deepEqual(include(call), c.flags, `${c.name}: ${call.join(" ")}`);
  }
});

test("custom protection rules are forwarded on every call path and only ever add protection", async () => {
  const world = sjWorld([A]);
  const rules = { exactPaths: ["/data/keep"], dynamicProtectedPaths: ["/work/active"], globPatterns: ["*.vaultx"] };
  const gate = await gateFor(world, { ruleOptions: rules });
  const plan = await gate.createDryRunPlan([cand(A)]);
  await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
  assert.equal(world.calls.length, 2);
  for (const c of world.calls) {
    assert.ok(c.includes("--exact=/data/keep") && c.includes("--dynamic=/work/active") && c.includes("--glob=*.vaultx"), c.join(" "));
  }
  assert.throws(() => new RemediationGate({ ruleOptions: { globPatterns: [""] } }), /invalid_custom_rule/);
});

test("sj stderr and error text are redacted before they leave the main process (execute result and errors)", async () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { urlWith } = require("../../../../packages/core/test/_fixtures.mjs");
  const secretUrl = urlWith("https", "alice", "superSecretPass99", "git.example.com/r.git");
  const tokenFlag = ["--token", "tokSecret99"].join("=");
  const stderr = `error: git remote ${secretUrl} ${tokenFlag} failed`;
  const world = sjWorld([A]);
  const run: RunSj = async (args) => {
    if (!args.includes("--execute")) return world.run(args);
    const e = new core.SjGateError("sj_exit_2");
    (e as unknown as { stderr: string }).stderr = stderr;
    throw e;
  };
  const gate = new RemediationGate({ runSj: run, planRoot: "/h" });
  gate.registerApprovedCandidates([cand(A)]);
  const plan = await gate.createDryRunPlan([cand(A)]);
  const res = await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
  const text = JSON.stringify(res);
  for (const leak of ["superSecretPass99", "tokSecret99"]) assert.equal(text.includes(leak), false, `leaked ${leak}: ${text}`);
  assert.match((res.failed as Array<{ error: string }>)[0].error, /^sj_exit_2/);

  const run2: RunSj = async (args) => {
    if (!args.includes("--execute")) return world.run(args);
    return {
      mode: "executed",
      selection_sha256: args[args.indexOf("--selection-sha256") + 1],
      executed_items: [],
      failed_items: [{ path: A, error: `boom ${secretUrl} ${["--password", "pwSecret77"].join("=")}` }],
    };
  };
  const gate2 = new RemediationGate({ runSj: run2, planRoot: "/h" });
  gate2.registerApprovedCandidates([cand(A)]);
  const plan2 = await gate2.createDryRunPlan([cand(A)]);
  const text2 = JSON.stringify(await gate2.run({ planSha256: plan2.planSha256, phrase: plan2.confirmationPhrase }));
  for (const leak of ["superSecretPass99", "pwSecret77"]) assert.equal(text2.includes(leak), false, `leaked ${leak}: ${text2}`);
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

test("integration: real sj plans, binds the token to the selection, refuses stale/changed selections and removes only the confirmed item", { skip: integrationSkip }, async () => {
  const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sj-gate-home-")));
  const trash = process.platform === "darwin" ? path.join(home, ".Trash") : path.join(home, ".local", "share", "Trash", "files");
  const prevXdg = process.env.XDG_DATA_HOME;
  delete process.env.XDG_DATA_HOME;
  try {
    fs.mkdirSync(trash, { recursive: true });
    for (const [n, body] of [["a.bin", "aaaa"], ["b.bin", "bbbbbb"], ["c.bin", "cc"]]) fs.writeFileSync(path.join(trash, n), body);
    fs.mkdirSync(path.join(trash, "proj"));
    fs.writeFileSync(path.join(trash, "proj", ".env.production"), "S=1");
    core.configureSjBinary(REAL_SJ);
    const runReal: RunSj = (args, opts) => core.runSj(args, { ...opts, homeDir: home });
    const gate = new RemediationGate({ runSj: runReal, planRoot: home, homeDir: home });
    const pa = path.join(trash, "a.bin");
    const pb = path.join(trash, "b.bin");
    const pc = path.join(trash, "c.bin");
    const proj = path.join(trash, "proj");
    gate.registerApprovedCandidates([cand(pa), cand(pb), cand(pc), cand(proj, 1, "dir")]);

    const planA = await gate.createDryRunPlan([cand(pa)]);
    const planAB = await gate.createDryRunPlan([cand(pa), cand(pb)]);
    assert.notEqual(planA.planSha256, planAB.planSha256);
    // stale one-item token against the A+B plan: refused, nothing deleted
    assert.equal((await gate.run({ planSha256: planA.planSha256, phrase: planA.confirmationPhrase })).error, "plan_sha256_mismatch");
    assert.ok(fs.existsSync(pa) && fs.existsSync(pb));

    // B changes on disk after the dry run: sj refuses the whole selection
    fs.writeFileSync(pb, "tampered after the dry run with a different size");
    const refused = await gate.run({ planSha256: planAB.planSha256, phrase: planAB.confirmationPhrase });
    assert.equal(refused.executed, false, JSON.stringify(refused));
    assert.ok(fs.existsSync(pa) && fs.existsSync(pb), "nothing removed when the selection changed");

    // a protected tree is blocked by sj; the clean item is removed; unselected items survive
    const plan = await gate.createDryRunPlan([cand(pa), cand(proj, 1, "dir")]);
    assert.deepEqual(plan.items.map((i) => path.basename(i.path)), ["a.bin"]);
    assert.ok(plan.blockedItems.some((b) => b.path === proj), "tree holding .env.production must be blocked by sj");
    const res = await gate.run({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
    assert.equal(res.executed, true, JSON.stringify(res));
    assert.equal(fs.existsSync(pa), false);
    assert.ok(fs.existsSync(pb) && fs.existsSync(pc));
    assert.ok(fs.existsSync(path.join(proj, ".env.production")), "protected tree must survive");
  } finally {
    if (prevXdg !== undefined) process.env.XDG_DATA_HOME = prevXdg;
    core.configureSjBinary(undefined);
    fs.rmSync(home, { recursive: true, force: true });
  }
});
