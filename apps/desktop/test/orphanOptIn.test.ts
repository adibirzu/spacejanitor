import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { executePlanItems } from "../src/executor";
import { sanitizeIpcParams } from "../src/ipcValidation";
import { OrphanScanSetting } from "../src/orphanSetting";
import { RemediationCandidate, RemediationGate } from "../src/remediationGate";
import { SjBridge } from "../src/sjBridge";
import { worktreePruneBlockReason } from "../src/worktreeGuard";

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

    const gate = new RemediationGate({ homeDir: path.join(dir, "home") });
    const cache = path.join(dir, "home", ".cache", "npm");
    fs.mkdirSync(cache, { recursive: true });
    const cands: RemediationCandidate[] = [{ id: "c", path: cache, bytes: 1, kind: "dir" }];
    gate.registerApprovedCandidates(cands);
    gate.createDryRunPlan(cands);
    assert.equal(fs.existsSync(marker), false, `git was spawned: ${fs.existsSync(marker) ? fs.readFileSync(marker, "utf8") : ""}`);

    // explicit opt-in is what reaches git
    const on = new SjBridge({ binaryPath: null });
    await on.invoke("orphans", { targetPath: dir, includeOrphans: true });
    on.dispose();
    assert.equal(fs.existsSync(marker), true);
  });
});

test("worktree prune is blocked and spawns no git unless scanning is enabled", skip, async () => {
  await withGitShim(async ({ dir, marker }) => {
    const wt = path.join(dir, "wt");
    fs.mkdirSync(wt);
    fs.writeFileSync(path.join(wt, ".git"), `gitdir: ${path.join(dir, "g")}\n`);
    assert.equal(await worktreePruneBlockReason(wt), "orphan_scan_disabled_by_default");

    const gate = new RemediationGate({ homeDir: path.join(dir, "home") });
    const cands: RemediationCandidate[] = [{ id: "w", path: wt, bytes: 1, kind: "git-worktree" }];
    gate.registerApprovedCandidates(cands);
    const plan = gate.createDryRunPlan(cands);
    const auth = gate.authorizeExecute({ planSha256: plan.planSha256, phrase: plan.confirmationPhrase });
    if (auth.allowed) {
      const res = await executePlanItems(auth.plan!, auth.identities!, {
        homeDir: path.join(dir, "home"),
        isInsideOsTrash: () => false,
        trashItem: async () => {},
        removeWorktree: async () => {
          throw new Error("must not be called");
        },
        orphanScanEnabled: () => false,
      });
      assert.equal(res.removed.length, 0);
      assert.equal(res.failed[0].error, "orphan_scanning_disabled");
    }
    assert.equal(fs.existsSync(marker), false);
  });
});
