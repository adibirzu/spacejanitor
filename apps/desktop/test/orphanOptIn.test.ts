import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { sanitizeIpcParams } from "../src/ipcValidation";
import { OrphanScanSetting, setOrphanScanWithConfirmation } from "../src/orphanSetting";
import { RemediationCandidate, RemediationGate } from "../src/remediationGate";
import { SjBridge } from "../src/sjBridge";

/** `git` shim first on PATH recording every spawn. */
async function withGitShim(fn: (ctx: { dir: string; marker: string }) => Promise<void>): Promise<void> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-desk-shim-"));
  const bin = path.join(dir, "bin");
  fs.mkdirSync(bin);
  const marker = path.join(dir, "GIT_SPAWNED");
  fs.writeFileSync(path.join(bin, "git"), `#!/bin/sh\necho "$@" >> "${marker}"\nexit 1\n`, { mode: 0o755 });
  const saved = process.env.PATH;
  process.env.PATH = `${bin}${path.delimiter}${saved}`;
  try {
    await fn({ dir: fs.realpathSync(dir), marker });
  } finally {
    process.env.PATH = saved;
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
const skip = { skip: process.platform === "win32" };

test("orphan scan setting defaults to OFF, persists an explicit opt-in and ignores junk", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-setting-"));
  try {
    const file = path.join(dir, "settings.json");
    const s = new OrphanScanSetting(file);
    assert.equal(s.get(), false);
    s.set(true);
    assert.equal(new OrphanScanSetting(file).get(), true);
    s.set("yes" as unknown as boolean);
    assert.equal(new OrphanScanSetting(file).get(), false, "only a real boolean true enables scanning");
    fs.writeFileSync(file, "{not json");
    assert.equal(new OrphanScanSetting(file).get(), false);
    assert.match(OrphanScanSetting.WARNING, /runs git inside repositories found on disk/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a renderer can never opt itself in through IPC params", () => {
  assert.equal("includeOrphans" in sanitizeIpcParams({ includeOrphans: true, targetPath: "/x" }), false);
});

test("desktop startup scan (summary), orphan view and remediation plan spawn no git by default", skip, async () => {
  await withGitShim(async ({ dir, marker }) => {
    const bridge = new SjBridge({ binaryPath: null });
    const summary = (await bridge.invoke("summary", { targetPath: dir })) as {
      orphans: { scanned?: boolean; notScannedReason?: string; candidates: unknown[] };
    };
    assert.equal(summary.orphans.scanned, false);
    assert.equal(summary.orphans.notScannedReason, "orphan_scan_disabled_by_default");
    const orphans = (await bridge.invoke("orphans", { targetPath: dir })) as { scanned?: boolean };
    assert.equal(orphans.scanned, false);
    bridge.dispose();

    const gate = new RemediationGate({
      homeDir: path.join(dir, "home"),
      planRoot: dir,
      runSj: async () => ({
        schema: "spacejanitor.proposal.v1",
        mode: "dry-run",
        mutated: false,
        plan_sha256: "a".repeat(64),
        items: [],
        protected_exclusions: [],
      }),
    });
    const cache = path.join(dir, "home", ".cache", "npm");
    fs.mkdirSync(cache, { recursive: true });
    const cands: RemediationCandidate[] = [{ id: "c", path: cache, bytes: 1, kind: "dir" }];
    gate.registerApprovedCandidates(cands);
    await gate.createDryRunPlan(cands);
    assert.equal(fs.existsSync(marker), false, `git was spawned: ${fs.existsSync(marker) ? fs.readFileSync(marker, "utf8") : ""}`);

    // explicit opt-in goes to the Rust gate only: with no sj the report fails closed and Node spawns no git
    const on = new SjBridge({ binaryPath: null });
    const optIn = (await on.invoke("orphans", { targetPath: dir, includeOrphans: true })) as { error?: string; candidates: unknown[] };
    on.dispose();
    assert.equal(optIn.error, "sj_unavailable");
    assert.deepEqual(optIn.candidates, []);
    assert.equal(fs.existsSync(marker), false);
  });
});

test("remediation never asks sj for orphan worktrees and spawns no git unless scanning is enabled", skip, async () => {
  await withGitShim(async ({ dir, marker }) => {
    const wt = path.join(dir, "wt");
    fs.mkdirSync(wt);
    fs.writeFileSync(path.join(wt, ".git"), `gitdir: ${path.join(dir, "g")}\n`);
    const calls: string[][] = [];
    const runSj = async (args: string[]) => {
      calls.push(args);
      return {
        schema: "spacejanitor.proposal.v1",
        mode: "dry-run",
        mutated: false,
        plan_sha256: "a".repeat(64),
        total_reclaimable_bytes: 0,
        items: [],
        protected_exclusions: [],
      };
    };
    const gate = new RemediationGate({ homeDir: path.join(dir, "home"), runSj, planRoot: dir, orphanScanEnabled: () => false });
    const cands: RemediationCandidate[] = [{ id: "w", path: wt, bytes: 1, kind: "git-worktree" }];
    gate.registerApprovedCandidates(cands);
    const plan = await gate.createDryRunPlan(cands);
    assert.equal(plan.items.length, 0);
    assert.equal(plan.blockedItems[0].reason, "not_in_sj_plan");
    for (const c of calls) assert.equal(c.includes("--include-orphans"), false);
    assert.equal(fs.existsSync(marker), false);
  });
});

test("enabling orphan scanning needs a main-process confirmation: cancel keeps it off, confirm turns it on, no confirmation does nothing", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-confirm-"));
  try {
    const s = new OrphanScanSetting(path.join(dir, "settings.json"));
    let shown = "";
    // plain renderer call: no confirmation function available -> stays off
    assert.equal(await setOrphanScanWithConfirmation(s, true, undefined), false);
    assert.equal(s.get(), false);
    // user cancels the native dialog
    assert.equal(await setOrphanScanWithConfirmation(s, true, async () => false), false);
    assert.equal(s.get(), false);
    // junk is never "true"
    assert.equal(await setOrphanScanWithConfirmation(s, "true" as unknown as boolean, async () => true), false);
    // user confirms, and the dialog carried the warning
    assert.equal(
      await setOrphanScanWithConfirmation(s, true, async (warning) => {
        shown = warning;
        return true;
      }),
      true
    );
    assert.equal(s.get(), true);
    assert.match(shown, /runs git inside repositories found on disk/);
    // turning it off never asks
    let asked = false;
    assert.equal(
      await setOrphanScanWithConfirmation(s, false, async () => {
        asked = true;
        return true;
      }),
      false
    );
    assert.equal(asked, false);
    assert.equal(s.get(), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("real Rust binary path, defaults: summary and orphans say scanned:false and git is only ever asked for --version", skip, async () => {
  const repoRoot = path.resolve(__dirname, "../../../..");
  const exe = [path.join(repoRoot, "target", "release", "sj"), path.join(repoRoot, "target", "debug", "sj")].find((p) => fs.existsSync(p));
  if (!exe) return; // Rust binary not built in this job; covered where it is
  await withGitShim(async ({ dir, marker }) => {
    const bridge = new SjBridge({ binaryPath: exe });
    const summary = (await bridge.invoke("summary", { targetPath: dir })) as { orphans: { scanned?: boolean } };
    const orphans = (await bridge.invoke("orphans", { targetPath: dir })) as { scanned?: boolean };
    bridge.dispose();
    assert.equal(summary.orphans.scanned, false);
    assert.equal(orphans.scanned, false);
    const calls = fs.existsSync(marker) ? fs.readFileSync(marker, "utf8").split("\n").filter(Boolean) : [];
    for (const c of calls) assert.equal(c.trim(), "--version", `unexpected git call: ${c}`);
  });
});
