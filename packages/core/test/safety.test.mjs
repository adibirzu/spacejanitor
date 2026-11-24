import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
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

test("blocks symlink traversal, case-insensitive credential stores, and critical OS/user roots", () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "sj-prot-"));
  try {
    const fakeHome = path.join(tmpRoot, "home");
    const sshDir = path.join(fakeHome, ".ssh");
    fs.mkdirSync(sshDir, { recursive: true });
    fs.writeFileSync(path.join(sshDir, "id_ed25519"), "dummy");

    const linkToHome = path.join(tmpRoot, "home-link");
    fs.symlinkSync(fakeHome, linkToHome);

    // Symlink to home -> .ssh and non-existent child under symlink -> .aws must be protected
    assert.equal(
      isProtectedPath(path.join(linkToHome, ".ssh", "id_ed25519"), { homeDir: fakeHome }).protected,
      true
    );
    assert.equal(
      isProtectedPath(path.join(linkToHome, ".aws", "credentials"), { homeDir: fakeHome }).protected,
      true
    );

    // Critical user and OS roots must be protected
    for (const p of [
      "~/Documents",
      "~/Desktop",
      "~/Library",
      "~/.config",
      "~/.docker",
      "~/.netrc",
      path.dirname(fakeHome),
      "/usr",
      "/etc",
      "/Applications",
      "/Library",
      "C:\\",
      "C:\\Windows",
    ]) {
      assert.equal(isProtectedPath(p, { homeDir: fakeHome }).protected, true, `expected protected: ${p}`);
    }

    // Case-insensitive credential paths on darwin/win32
    if (process.platform === "darwin" || process.platform === "win32") {
      assert.equal(isProtectedPath("~/.AWS/credentials", { homeDir: fakeHome }).protected, true);
      assert.equal(isProtectedPath("~/.SSH/id_rsa", { homeDir: fakeHome }).protected, true);
      assert.equal(isProtectedPath("~/DOCUMENTS/report.pdf", { homeDir: fakeHome }).protected, true);
    }

    // Relative paths are rejected
    assert.equal(isProtectedPath("relative/path", { homeDir: fakeHome }).protected, true);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test("redacts all 10 credential shapes without leaking raw secret characters", () => {
  const k1 = ["sk", "ant", "secret1234567890"].join("-");
  const k2 = ["glpat", "0123456789abcdefghij"].join("-");
  const k3 = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
  const k4 = ["xoxb", "1234567890", "abcdefghij"].join("-");
  const k5 = ["sk", "proj", "abcdefghijklmnop"].join("-");
  const secrets = [
    k1,
    k2,
    k3,
    k4,
    k5,
    "quotedSecretVal1",
    "singleQuotedVal2",
    "spaceKeyVal3",
    "accTokVal4",
    "apiKeyVal5",
    "cliSecVal6",
    "shortTVal7",
    "shortPVal8",
    "basicCreds999",
    "xApiKeyVal10",
    "xAuthTokVal11",
    "cookieSessVal12",
    "urlPassSecret13",
    "qApiKeyVal14",
    "qTokenVal15",
    "qSecretVal16",
    "envTokVal17",
    "ghEnvVal18",
    "fooSecVal19",
  ];

  const sample = [
    `--api-key="${secrets[5]}"`,
    `--api-key '${secrets[6]}'`,
    `--key ${secrets[7]}`,
    `--access-token=${secrets[8]}`,
    `--apikey=${secrets[9]}`,
    `--client-secret ${secrets[10]}`,
    `-t ${secrets[11]}`,
    `-p ${secrets[12]}`,
    `Authorization: Basic ${secrets[13]}`,
    `X-Api-Key: ${secrets[14]}`,
    `X-Auth-Token: ${secrets[15]}`,
    `Cookie: session=${secrets[16]}`,
    `https://admin:${secrets[17]}@registry.example.com/pkg?api_key=${secrets[18]}&token=${secrets[19]}&secret=${secrets[20]}`,
    `-e TOKEN=${secrets[21]}`,
    `GITHUB_TOKEN=${secrets[22]}`,
    `FOO_SECRET=${secrets[23]}`,
    `${k1} ${k2} ${k3} ${k4} ${k5}`,
  ].join(" ");

  const redacted = redactSecrets(sample);
  for (const s of secrets) {
    assert.equal(redacted.includes(s), false, `secret leaked in redacted output: ${s}`);
  }
  assert.ok(redacted.includes("<REDACTED>"));
});
