import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
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
  adviseWithLocalSlm,
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

test("B5: collectOrphans fails closed on git errors and detects unpushed detached-HEAD commits", async () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "sj-orphans-"));
  try {
    const repoDir = path.join(tmpRoot, "repo");
    const wtDetached = path.join(tmpRoot, "wt-detached");
    const wtBroken = path.join(tmpRoot, "wt-broken");
    fs.mkdirSync(repoDir, { recursive: true });

    execFileSync("git", ["init"], { cwd: repoDir });
    execFileSync("git", ["config", "user.email", "dev@example.com"], { cwd: repoDir });
    execFileSync("git", ["config", "user.name", "Developer"], { cwd: repoDir });
    fs.writeFileSync(path.join(repoDir, "README.md"), "init\n");
    execFileSync("git", ["add", "README.md"], { cwd: repoDir });
    execFileSync("git", ["commit", "-m", "init"], { cwd: repoDir });
    execFileSync("git", ["remote", "add", "origin", "https://example.com/repo.git"], { cwd: repoDir });

    // Create detached-HEAD worktree with an unpushed commit
    execFileSync("git", ["worktree", "add", "--detach", wtDetached], { cwd: repoDir });
    fs.writeFileSync(path.join(wtDetached, "local.txt"), "unpushed\n");
    execFileSync("git", ["add", "local.txt"], { cwd: wtDetached });
    execFileSync("git", ["commit", "-m", "detached unpushed"], { cwd: wtDetached });

    // Create another worktree and corrupt its .git pointer so git commands fail
    execFileSync("git", ["worktree", "add", "-b", "broken-branch", wtBroken], { cwd: repoDir });
    fs.writeFileSync(path.join(wtBroken, ".git"), "gitdir: /nonexistent/invalid/gitdir\n");

    const report = await collectOrphans({ targetPath: repoDir });
    const detachedEntry = report.candidates.find((c) => path.basename(c.path) === "wt-detached");
    assert.ok(detachedEntry, "expected detached worktree in candidates");
    assert.equal(detachedEntry.hasUnpushed, true);
    assert.equal(detachedEntry.safeToPrune, false);

    const brokenEntry = report.candidates.find((c) => path.basename(c.path) === "wt-broken");
    assert.ok(brokenEntry, "expected broken worktree in candidates");
    assert.equal(brokenEntry.clean, false);
    assert.equal(brokenEntry.hasUnpushed, true);
    assert.equal(brokenEntry.proofStatus, "unverified");
    assert.equal(brokenEntry.safeToPrune, false);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test("B7: collectMcpAudit parses JSON & TOML configs and flags URL creds, headers, and inline tokens without leaks", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-mcp-"));
  try {
    const fakePat = ["ghp", "0123456789abcdef012345"].join("_");
    const mcpJson = {
      mcpServers: {
        leakyUrl: {
          command: "npx",
          args: [
            "mcp-remote",
            "https://user:superSecretPass@mcp.example.com/sse?api_key=querySecretVal",
            "-H",
            "Authorization: Bearer bearerSecretVal123456",
          ],
        },
        inlineEnv: {
          command: "docker",
          args: ["run", "-e", `GITHUB_TOKEN=${fakePat}`, "img"],
        },
      },
    };
    fs.writeFileSync(path.join(tmpDir, "mcp.json"), JSON.stringify(mcpJson));

    const tomlCfg = `
[mcp_servers.codexTool]
command = "node"
args = ["server.js", "--api-key=tomlSecretVal123"]
`;
    fs.writeFileSync(path.join(tmpDir, "config.toml"), tomlCfg);

    const audit = await collectMcpAudit({ configDirs: [tmpDir] });
    assert.equal(audit.totalServers, 3);
    assert.equal(audit.secretRiskCount, 3);

    const serialized = JSON.stringify(audit);
    for (const secret of ["superSecretPass", "querySecretVal", "bearerSecretVal123456", fakePat, "tomlSecretVal123"]) {
      assert.equal(serialized.includes(secret), false, `secret leaked in mcpAudit: ${secret}`);
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("R2-B7: collectMcpAudit redacts custom header tokens, URL signatures, bare keys and secret-bearing server names", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-mcp-r2-"));
  try {
    const secretNameToken = ["gh", "s_", "abcdefghijklmnop123456"].join("");
    const mcpJson = {
      mcpServers: {
        custom: {
          url: "https://mcp.example.com/sse?sig=sigSecretVal99&access_key=akSecretVal99",
          headers: { "X-Custom-Token": "hdrSecretVal99", "x-goog-api-key": "googSecretVal99" },
          args: ["--auth", "authSecretVal99", "--passwd", "pwSecretVal99", "-u", "bob:basicSecretVal99"],
        },
        [`srv-${secretNameToken}`]: { command: "node", args: ["apiKey=bareSecretVal99"] },
      },
    };
    fs.writeFileSync(path.join(tmpDir, "mcp.json"), JSON.stringify(mcpJson));
    const audit = await collectMcpAudit({ configDirs: [tmpDir] });
    const serialized = JSON.stringify(audit);
    for (const secret of ["sigSecretVal99", "akSecretVal99", "hdrSecretVal99", "googSecretVal99", "authSecretVal99", "pwSecretVal99", "basicSecretVal99", "bareSecretVal99", secretNameToken]) {
      assert.equal(serialized.includes(secret), false, `secret leaked in mcpAudit: ${secret}`);
    }
    assert.equal(audit.secretRiskCount, 2);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("R2-B7: collectMcpAudit fails closed on secrets even when called without a redactFn (raw telemetry module)", async () => {
  const { collectMcpAudit: rawAudit } = await import("../src/telemetry.mjs");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-mcp-raw-"));
  try {
    fs.writeFileSync(
      path.join(tmpDir, "mcp.json"),
      JSON.stringify({ mcpServers: { a: { command: "node", args: ["--token", "rawSecretVal99"] } } })
    );
    const audit = await rawAudit({ configDirs: [tmpDir] });
    assert.equal(JSON.stringify(audit).includes("rawSecretVal99"), false);
    assert.equal(audit.secretRiskCount, 1);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("#6: adviseWithLocalSlm enforces redirect: error and AbortSignal timeout", async () => {
  let seenInit = null;
  const res = await adviseWithLocalSlm({
    enabled: true,
    url: "http://127.0.0.1:11434/v1/chat/completions",
    fetchImpl: async (_url, init) => {
      seenInit = init;
      throw new TypeError("redirect mode is set to error");
    },
  });
  assert.ok(seenInit, "expected fetchImpl to be called");
  assert.equal(seenInit.redirect, "error");
  assert.ok(seenInit.signal, "expected AbortSignal on fetch");
  assert.equal(res.ok, false);
});

test("B8: formatToon handles Rust snake_case storage.v1, doctor.v1, and orphans.v1 without undefined", () => {
  const rustDoctor = {
    schema: "spacejanitor.doctor.v1",
    engine: "rust",
    source: "sj-core",
    version: "0.1.0",
    os: "macos",
    arch: "aarch64",
    ready: true,
  };
  const docToon = formatToon(rustDoctor);
  assert.equal(docToon.includes("undefined"), false);

  const rustStorage = {
    schema: "spacejanitor.storage.v1",
    source: "sj-core",
    root: "/tmp/work",
    total_bytes: 1048576,
    status: "ok",
    entries: [{ path: "/tmp/work/node_modules", bytes: 524288, file_count: 10, kind: "dir" }],
  };
  const storageToon = formatToon(rustStorage);
  assert.equal(storageToon.includes("undefined"), false);
  assert.ok(storageToon.includes("/tmp/work/node_modules"));

  const rustOrphans = {
    schema: "spacejanitor.orphans.v1",
    source: "sj-core",
    root: "/tmp/work",
    candidates_scanned: 2,
    safe_to_prune: [{ path: "/tmp/work/wt1", is_worktree: true, branch: "feat", bytes: 1024 }],
    blocked: [{ path: "/tmp/work/wt2", reasons: ["dirty"] }],
  };
  const orphansToon = formatToon(rustOrphans);
  assert.equal(orphansToon.includes("undefined"), false);
  assert.ok(orphansToon.includes("/tmp/work/wt1"));
});

test("R2-B7: collectMcpAudit keeps clean servers (no TDZ drop) and counts them", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-mcp-clean-"));
  try {
    fs.writeFileSync(
      path.join(tmpDir, "mcp.json"),
      JSON.stringify({ mcpServers: { clean: { command: "npx", args: ["-y", "pkg"] } } })
    );
    const audit = await collectMcpAudit({ configDirs: [tmpDir] });
    assert.equal(audit.totalServers, 1);
    assert.equal(audit.secretRiskCount, 0);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
