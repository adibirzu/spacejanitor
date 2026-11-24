import assert from "node:assert/strict";
import test from "node:test";
import {
  SCHEMA_VERSIONS,
  collectDoctor,
  collectDisk,
  collectMemory,
  collectBlockers,
  collectOrphans,
  collectTrash,
  collectMcpAudit,
  collectSummary,
  createRemediationPlan,
  verifyRemediationGate,
  validateLoopbackSlmUrl,
  redactSlmPayload,
  formatToon,
} from "../src/index.mjs";

const SYNTHETIC_HOME = "/home/developer";

test("exposes all v1 schema identifiers for M4-M7 contracts", () => {
  assert.equal(SCHEMA_VERSIONS.doctor, "spacejanitor.doctor.v1");
  assert.equal(SCHEMA_VERSIONS.disk, "spacejanitor.disk.v1");
  assert.equal(SCHEMA_VERSIONS.memory, "spacejanitor.memory.v1");
  assert.equal(SCHEMA_VERSIONS.blockers, "spacejanitor.blockers.v1");
  assert.equal(SCHEMA_VERSIONS.orphans, "spacejanitor.orphans.v1");
  assert.equal(SCHEMA_VERSIONS.trash, "spacejanitor.trash.v1");
  assert.equal(SCHEMA_VERSIONS.mcpAudit, "spacejanitor.mcp_audit.v1");
  assert.equal(SCHEMA_VERSIONS.plan, "spacejanitor.plan.v1");
  assert.equal(SCHEMA_VERSIONS.reap, "spacejanitor.reap.v1");
  assert.equal(SCHEMA_VERSIONS.proposal, "spacejanitor.proposal.v1");
  assert.equal(SCHEMA_VERSIONS.summary, "spacejanitor.summary.v1");
});

test("collectors emit valid v1 envelopes with node-fallback source", async () => {
  const doctor = collectDoctor();
  assert.equal(doctor.schema, "spacejanitor.doctor.v1");
  assert.equal(doctor.ready, true);

  const disk = await collectDisk({ targetPath: process.cwd() });
  assert.equal(disk.schema, "spacejanitor.disk.v1");
  assert.equal(disk.source, "node-fallback");
  assert.ok(["OK", "CHECK", "ALERT", "CRITICAL"].includes(disk.status));
  assert.equal(typeof disk.freeBytes, "number");

  const memory = await collectMemory();
  assert.equal(memory.schema, "spacejanitor.memory.v1");
  assert.equal(typeof memory.totalBytes, "number");
  assert.ok(Array.isArray(memory.processes));

  const blockers = await collectBlockers();
  assert.equal(blockers.schema, "spacejanitor.blockers.v1");
  assert.ok(["OK", "WARN", "CRITICAL"].includes(blockers.status));

  const orphans = await collectOrphans({ targetPath: process.cwd() });
  assert.equal(orphans.schema, "spacejanitor.orphans.v1");
  assert.ok(Array.isArray(orphans.candidates));

  const trash = await collectTrash({ homeDir: SYNTHETIC_HOME });
  assert.equal(trash.schema, "spacejanitor.trash.v1");

  const mcpAudit = await collectMcpAudit({ configDirs: [] });
  assert.equal(mcpAudit.schema, "spacejanitor.mcp_audit.v1");
  assert.ok(Array.isArray(mcpAudit.servers));

  const summary = await collectSummary({ targetPath: process.cwd(), configDirs: [] });
  assert.equal(summary.schema, "spacejanitor.summary.v1");
  assert.ok(summary.disk && summary.memory && summary.blockers);
});

test("two-step remediation plan filters protected paths and enforces SHA-256 + phrase + TTL gate", () => {
  const plan = createRemediationPlan(
    [
      { id: "c1", path: "/home/developer/.ssh/id_ed25519", bytes: 4096, kind: "file" },
      { id: "c2", path: "/home/developer/.cache/npm", bytes: 1048576, kind: "dir" },
    ],
    { homeDir: SYNTHETIC_HOME, nowMs: 1_000_000 }
  );

  assert.equal(plan.schema, "spacejanitor.plan.v1");
  assert.equal(plan.dryRun, true);
  assert.equal(plan.items.length, 1);
  assert.equal(plan.items[0].id, "c2");
  assert.equal(plan.blockedItems.length, 1);
  assert.equal(plan.blockedItems[0].id, "c1");
  assert.match(plan.planSha256, /^[a-f0-9]{64}$/);
  assert.ok(plan.confirmationPhrase.length >= 6);

  // Fails with wrong phrase
  const badPhrase = verifyRemediationGate({
    plan,
    planSha256: plan.planSha256,
    phrase: "WRONG",
    nowMs: 1_001_000,
    homeDir: SYNTHETIC_HOME,
  });
  assert.equal(badPhrase.allowed, false);

  // Fails with wrong SHA-256
  const badSha = verifyRemediationGate({
    plan,
    planSha256: "0".repeat(64),
    phrase: plan.confirmationPhrase,
    nowMs: 1_001_000,
    homeDir: SYNTHETIC_HOME,
  });
  assert.equal(badSha.allowed, false);

  // Fails when TTL (5 min) expired
  const expired = verifyRemediationGate({
    plan,
    planSha256: plan.planSha256,
    phrase: plan.confirmationPhrase,
    nowMs: 1_000_000 + 6 * 60 * 1000,
    homeDir: SYNTHETIC_HOME,
  });
  assert.equal(expired.allowed, false);

  // Succeeds when valid
  const ok = verifyRemediationGate({
    plan,
    planSha256: plan.planSha256,
    phrase: plan.confirmationPhrase,
    nowMs: 1_001_000,
    homeDir: SYNTHETIC_HOME,
  });
  assert.equal(ok.allowed, true);
});

test("SLM URL validator enforces loopback-only by default and blocks external cloud URLs", () => {
  assert.equal(validateLoopbackSlmUrl("http://127.0.0.1:11434/v1/chat/completions").allowed, true);
  assert.equal(validateLoopbackSlmUrl("http://localhost:8080/v1/chat/completions").allowed, true);
  assert.equal(validateLoopbackSlmUrl("http://[::1]:11434/v1/chat/completions").allowed, true);

  // Cloud URLs must ALWAYS be rejected
  assert.equal(validateLoopbackSlmUrl("https://api.openai.com/v1/chat/completions").allowed, false);
  assert.equal(validateLoopbackSlmUrl("https://api.openai.com/v1/chat/completions", { allowLan: true }).allowed, false);

  // Non-loopback LAN host blocked by default, allowed only with explicit opt-in
  assert.equal(validateLoopbackSlmUrl("http://workstation.local:11434/v1/chat/completions").allowed, false);
  assert.equal(
    validateLoopbackSlmUrl("http://workstation.local:11434/v1/chat/completions", { allowLan: true }).allowed,
    true
  );
});

test("SLM payload redactor strips secrets and TOON formatter produces compact output", () => {
  const fakeToken = ["ghp", "0123456789abcdef012345"].join("_");
  const redacted = redactSlmPayload({
    summary: `Process running with --token=${fakeToken}`,
    candidates: [{ id: "c1", path: "/home/developer/.cache/npm", bytes: 2048 }],
  });
  assert.equal(JSON.stringify(redacted).includes(fakeToken), false);

  const toon = formatToon({ schema: "spacejanitor.doctor.v1", status: "OK", platform: "darwin", arch: "arm64" });
  assert.ok(toon.includes("schema: spacejanitor.doctor.v1"));
  assert.ok(!toon.trim().startsWith("{"));
});
