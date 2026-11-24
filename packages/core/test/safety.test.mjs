import assert from "node:assert/strict";
import test from "node:test";
import {
  DEFAULT_PROTECTED_PATTERNS,
  SCHEMA_VERSIONS,
  isProtectedPath,
  redactSecrets,
} from "../src/index.mjs";

const SYNTHETIC_HOME = "/home/developer";

test("protects built-in home root, system paths, and credential stores", () => {
  assert.equal(isProtectedPath("/", { homeDir: SYNTHETIC_HOME }).protected, true);
  assert.equal(isProtectedPath(SYNTHETIC_HOME, { homeDir: SYNTHETIC_HOME }).protected, true);
  assert.equal(isProtectedPath("~/.ssh/id_ed25519", { homeDir: SYNTHETIC_HOME }).protected, true);
  assert.equal(isProtectedPath("~/.gnupg/private-keys-v1.d", { homeDir: SYNTHETIC_HOME }).protected, true);
  assert.equal(isProtectedPath("/System/Library", { homeDir: SYNTHETIC_HOME }).protected, true);
  assert.equal(
    isProtectedPath("/home/developer/docs/notes.private.md", { homeDir: SYNTHETIC_HOME }).protected,
    true
  );
});

test("protects custom exact paths and active dynamic worktrees while allowing normal caches", () => {
  const opts = {
    homeDir: SYNTHETIC_HOME,
    exactPaths: ["~/models"],
    dynamicProtectedPaths: ["/home/developer/workspaces/active-branch"],
  };

  assert.equal(isProtectedPath("~/models/llama.gguf", opts).protected, true);
  assert.equal(
    isProtectedPath("/home/developer/workspaces/active-branch/src", opts).protected,
    true
  );
  assert.equal(isProtectedPath("/home/developer/.cache/npm", opts).protected, false);
});

test("redacts CLI credential flags, bearer tokens, and vendor key shapes", () => {
  const fakeKey = ["sk", "test", "0000000000000000"].join("_");
  const fakeGhp = ["ghp", "0123456789abcdef012345"].join("_");
  const cmd = `node server.js --api-key=${fakeKey} --token ${fakeGhp} -H "Authorization: Bearer abcdef1234567890"`;
  const redacted = redactSecrets(cmd);

  assert.equal(redacted.includes(fakeKey), false);
  assert.equal(redacted.includes(fakeGhp), false);
  assert.equal(redacted.includes("abcdef1234567890"), false);
  assert.ok(redacted.includes("<REDACTED>"));
});

test("exposes immutable schema version identifiers", () => {
  assert.equal(SCHEMA_VERSIONS.storage, "spacejanitor.storage.v1");
  assert.equal(SCHEMA_VERSIONS.memory, "spacejanitor.memory.v1");
  assert.equal(SCHEMA_VERSIONS.blockers, "spacejanitor.blockers.v1");
  assert.equal(SCHEMA_VERSIONS.orphans, "spacejanitor.orphans.v1");
  assert.ok(DEFAULT_PROTECTED_PATTERNS.homeSubpaths.includes(".ssh"));
});
