import assert from "node:assert/strict";
import test from "node:test";
import { RemediationGate } from "../src/remediationGate";

const SYNTHETIC_HOME = "/home/developer";

test("enforces 2-step SHA-256 plan and execute gate in main process", () => {
  const gate = new RemediationGate({ homeDir: SYNTHETIC_HOME });

  // Cannot execute without prior plan
  const noPlan = gate.authorizeExecute({
    planSha256: "abc",
    phrase: "CONFIRM-ABC",
  });
  assert.equal(noPlan.allowed, false);

  // Step 1: create dry-run plan filtering protected paths
  const plan = gate.createDryRunPlan([
    { id: "p1", path: "/home/developer/.ssh/id_ed25519", bytes: 1024, kind: "file" },
    { id: "c1", path: "/home/developer/.cache/vite", bytes: 4096, kind: "dir" },
  ]);
  assert.equal(plan.items.length, 1);
  assert.equal(plan.blockedItems.length, 1);

  // Wrong phrase fails
  assert.equal(
    gate.authorizeExecute({ planSha256: plan.planSha256, phrase: "NOPE" }).allowed,
    false
  );

  // Matching SHA-256 + phrase succeeds once (single-use token)
  const ok = gate.authorizeExecute({
    planSha256: plan.planSha256,
    phrase: plan.confirmationPhrase,
  });
  assert.equal(ok.allowed, true);

  // Replay of single-use token is rejected
  const replay = gate.authorizeExecute({
    planSha256: plan.planSha256,
    phrase: plan.confirmationPhrase,
  });
  assert.equal(replay.allowed, false);
});

test("B3 & #5: gate binds planId to server-approved candidates and includes cryptographic nonce", () => {
  const gate = new RemediationGate({ homeDir: SYNTHETIC_HOME });
  const approved = [
    { id: "c1", path: "/home/developer/.cache/vite", bytes: 4096, kind: "dir" as const },
  ];
  gate.registerApprovedCandidates(approved);

  // Renderer-supplied arbitrary path not in server-approved list must be rejected
  assert.throws(
    () =>
      gate.createDryRunPlan([
        { id: "evil", path: "/home/developer/important-notes.txt", bytes: 100, kind: "file" },
      ]),
    /unapproved_candidate/
  );

  // Two plans with identical approved items must have distinct planSha256 (per-plan nonce)
  const p1 = gate.createDryRunPlan(approved);
  const p2 = gate.createDryRunPlan(approved);
  assert.notEqual(p1.planSha256, p2.planSha256);
});
