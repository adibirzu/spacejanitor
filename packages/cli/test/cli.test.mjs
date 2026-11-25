import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI_BIN = path.resolve(__dirname, "../bin/spacejanitor.mjs");

function runCli(args, env = {}) {
  return execFileSync(process.execPath, [CLI_BIN, ...args], {
    encoding: "utf8",
    timeout: 15000,
    env: { ...process.env, ...env },
  });
}

// Rust `sj` emits storage.v1 for disk scans; the Node fallback emits disk.v1.
// Accept either contract so the suite is green with or without a built sj.
const SCHEMA_ALIASES = {
  "spacejanitor.disk.v1": ["spacejanitor.disk.v1", "spacejanitor.storage.v1"],
};

test("AXI CLI emits compact TOON by default and valid v1 JSON with --json", () => {
  const commands = [
    ["doctor", "spacejanitor.doctor.v1"],
    ["summary", "spacejanitor.summary.v1"],
    ["disk", "spacejanitor.disk.v1"],
    ["memory", "spacejanitor.memory.v1"],
    ["blockers", "spacejanitor.blockers.v1"],
    ["mcp-audit", "spacejanitor.mcp_audit.v1"],
    ["orphans", "spacejanitor.orphans.v1"],
    ["trash", "spacejanitor.trash.v1"],
    ["remediate", "spacejanitor.plan.v1"],
  ];

  for (const [cmd, expectedSchema] of commands) {
    const toonOut = runCli([cmd]);
    assert.ok(toonOut.trim().length > 0, `expected TOON output for ${cmd}`);
    assert.ok(!toonOut.trim().startsWith("{"), `expected non-JSON TOON output for ${cmd}`);

    const jsonOut = runCli([cmd, "--json"]);
    const parsed = JSON.parse(jsonOut);
    const accepted = SCHEMA_ALIASES[expectedSchema] || [expectedSchema];
    assert.ok(accepted.includes(parsed.schema), `expected schema ${expectedSchema} for ${cmd}, got ${parsed.schema}`);
  }
});

test("AXI CLI remediate fails closed when --execute is passed without valid confirmation", () => {
  assert.throws(
    () => runCli(["remediate", "--execute", "--json"]),
    (err) => err.status === 1
  );
});

test("AXI CLI supports --path before subcommand and never fakes --execute success on empty environment", () => {
  const diskOut = runCli(["--path", process.cwd(), "disk", "--json"]);
  const diskParsed = JSON.parse(diskOut);
  assert.ok(
    diskParsed.schema === "spacejanitor.disk.v1" || diskParsed.schema === "spacejanitor.storage.v1"
  );

  // Even if someone passes --execute, on an empty/no-op environment it must never return executed: true
  assert.throws(
    () => runCli(["remediate", "--execute", "--confirm", "CONFIRM-00000000", "--plan-sha256", "0".repeat(64), "--json"]),
    (err) => {
      assert.equal(err.status, 1);
      const parsed = JSON.parse(err.stdout || "{}");
      assert.equal(parsed.executed, false);
      return true;
    }
  );
});

test("R2-B8: SPACEJANITOR_NO_SJ=1 forces the Node fallback even when a Rust sj binary exists (hermetic)", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-fake-bin-"));
  try {
    const fake = path.join(dir, "sj");
    const canExecShebang = process.platform !== "win32";
    if (canExecShebang) fs.writeFileSync(fake, '#!/bin/sh\necho \'{"schema":"spacejanitor.storage.v1","status":"OK"}\'\n', { mode: 0o755 });
    if (canExecShebang) {
      const viaSj = JSON.parse(runCli(["disk", "--json"], { SPACEJANITOR_SJ_BIN: fake }));
      assert.equal(viaSj.schema, "spacejanitor.storage.v1");
    }
    const hermetic = JSON.parse(runCli(["disk", "--json"], { SPACEJANITOR_SJ_BIN: fake, SPACEJANITOR_NO_SJ: "1" }));
    assert.equal(hermetic.schema, "spacejanitor.disk.v1");
    assert.equal(hermetic.source, "node-fallback");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
