import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { worktreePruneBlockReason } from "../src/worktreeGuard";

function git(cwd: string, ...args: string[]): string {
  return execFileSync(
    "git",
    ["-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args],
    { cwd, encoding: "utf8" }
  );
}

test("R6-B21: desktop prune guard blocks ignored, untracked and unpushed worktrees and passes a proven-clean one", async () => {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sj-guard-")));
  try {
    const origin = path.join(base, "origin.git");
    const repo = path.join(base, "repo");
    fs.mkdirSync(repo);
    git(base, "init", "--bare", "-b", "main", origin);
    git(repo, "init", "-b", "main");
    fs.writeFileSync(path.join(repo, ".gitignore"), "*.secret\n");
    fs.writeFileSync(path.join(repo, "a.txt"), "a");
    git(repo, "add", ".");
    git(repo, "commit", "-m", "init");
    git(repo, "remote", "add", "origin", origin);
    git(repo, "push", "-u", "origin", "main");
    const mk = (name: string) => {
      const p = path.join(base, name);
      git(repo, "worktree", "add", "-b", `b-${name}`, p);
      git(p, "push", "-u", "origin", `b-${name}`);
      return p;
    };
    const clean = mk("clean");
    const ignored = mk("ignored");
    const untracked = mk("untracked");
    const unpushed = mk("unpushed");
    assert.equal(await worktreePruneBlockReason(clean), null);
    fs.writeFileSync(path.join(ignored, "db.secret"), "precious");
    fs.writeFileSync(path.join(untracked, "n.txt"), "n");
    fs.writeFileSync(path.join(unpushed, "u.txt"), "u");
    git(unpushed, "add", "u.txt");
    git(unpushed, "commit", "-m", "local");
    for (const p of [ignored, untracked, unpushed]) {
      assert.notEqual(await worktreePruneBlockReason(p), null, `must block ${path.basename(p)}`);
    }
    assert.notEqual(await worktreePruneBlockReason(path.join(base, "missing")), null);
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("R7-B23: guard blocks a worktree whose edits hide behind assume-unchanged / skip-worktree", async () => {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sj-guard-flags-")));
  try {
    const origin = path.join(base, "origin.git");
    const repo = path.join(base, "repo");
    fs.mkdirSync(repo);
    git(base, "init", "--bare", "-b", "main", origin);
    git(repo, "init", "-b", "main");
    fs.writeFileSync(path.join(repo, "a.txt"), "a");
    git(repo, "add", ".");
    git(repo, "commit", "-m", "init");
    git(repo, "remote", "add", "origin", origin);
    git(repo, "push", "-u", "origin", "main");
    const mk = (name: string) => {
      const p = path.join(base, name);
      git(repo, "worktree", "add", "-b", `b-${name}`, p);
      git(p, "push", "-u", "origin", `b-${name}`);
      return p;
    };
    const control = mk("control");
    const assume = mk("assume");
    const skip = mk("skip");
    assert.equal(await worktreePruneBlockReason(control), null);
    git(assume, "update-index", "--assume-unchanged", "a.txt");
    fs.writeFileSync(path.join(assume, "a.txt"), "EDIT");
    git(skip, "update-index", "--skip-worktree", "a.txt");
    fs.writeFileSync(path.join(skip, "a.txt"), "EDIT");
    assert.equal(await worktreePruneBlockReason(assume), "worktree_index_flags_hide_changes");
    assert.equal(await worktreePruneBlockReason(skip), "worktree_index_flags_hide_changes");
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("R9-B27: guard is not fooled by a lying core.fsmonitor and never runs the hook", { skip: process.platform === "win32" }, async () => {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sj-guard-fsm-")));
  try {
    const origin = path.join(base, "origin.git");
    const repo = path.join(base, "repo");
    fs.mkdirSync(repo);
    git(base, "init", "--bare", "-b", "main", origin);
    git(repo, "init", "-b", "main");
    fs.writeFileSync(path.join(repo, "a.txt"), "a");
    git(repo, "add", ".");
    git(repo, "commit", "-m", "init");
    git(repo, "remote", "add", "origin", origin);
    git(repo, "push", "-u", "origin", "main");
    const wt = path.join(base, "wt");
    git(repo, "worktree", "add", "-b", "feat", wt);
    git(wt, "push", "-u", "origin", "feat");
    const marker = path.join(base, "HOOK_RAN");
    const hook = path.join(base, "hook.sh");
    fs.writeFileSync(hook, `#!/bin/sh\ntouch "${marker}"\nprintf 'token-1\\0'\n`, { mode: 0o755 });
    git(wt, "config", "core.fsmonitor", hook);
    git(wt, "config", "core.fsmonitorHookVersion", "2");
    git(wt, "status");
    git(wt, "status");
    fs.writeFileSync(path.join(wt, "a.txt"), "UNCOMMITTED EDIT");
    fs.rmSync(marker, { force: true });
    assert.notEqual(await worktreePruneBlockReason(wt), null);
    assert.equal(fs.existsSync(marker), false);
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});
