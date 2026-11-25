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

test("R2-B3: denylist covers foreign homes, OS roots, extra credential stores and home ancestors; case-insensitive on every platform", () => {
  const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sj-r2b3-")));
  try {
    for (const sub of [".SSH/id", ".AZURE", ".oci/config", ".npmrc", ".git-credentials", ".local/share/keyrings", ".password-store", ".1password", ".Aws/credentials"]) {
      assert.equal(
        isProtectedPath(path.join(home, sub), { homeDir: home, caseInsensitive: false }).protected,
        true,
        `expected ${sub} protected even when caller says case-sensitive`
      );
    }
    for (const abs of ["/Users", "/home", "/root", "/var", "/private", "/System", "/Volumes", "/boot", "/dev", "/proc", "/sys", "/lib", "/Users/alice/Documents/x", "/home/alice/.cache/x", "/ETC/passwd"]) {
      assert.equal(isProtectedPath(abs, { homeDir: home }).protected, true, `expected ${abs} protected`);
    }
    // ancestors of home (beyond immediate parent) are home-root candidates
    assert.equal(isProtectedPath(path.dirname(path.dirname(home)), { homeDir: home }).protected, true);
    // normal cache under home stays removable
    fs.mkdirSync(path.join(home, ".cache", "vite"), { recursive: true });
    assert.equal(isProtectedPath(path.join(home, ".cache", "vite"), { homeDir: home }).protected, false);
    // symlink pointing at a credential store is denied, and a symlink aliased protected root is denied lexically
    fs.mkdirSync(path.join(home, ".ssh"));
    fs.symlinkSync(path.join(home, ".ssh"), path.join(home, ".cache", "alias"));
    assert.equal(isProtectedPath(path.join(home, ".cache", "alias", "id"), { homeDir: home }).protected, true);
    const elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), "sj-r2b3-ext-"));
    fs.rmSync(path.join(home, ".ssh"), { recursive: true });
    fs.symlinkSync(elsewhere, path.join(home, ".ssh"));
    assert.equal(isProtectedPath(path.join(home, ".ssh", "id"), { homeDir: home }).protected, true, "lexical ~/.ssh stays protected when it is a symlink elsewhere");
    assert.equal(isProtectedPath(path.join(elsewhere, "id"), { homeDir: home }).protected, true, "real target of ~/.ssh stays protected");
    fs.rmSync(elsewhere, { recursive: true, force: true });
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("R2-B7: redactSecrets covers extended flag names, custom headers, URL userinfo/query signatures, bare env keys, PEM and vendor tokens", () => {
  const j = (...p) => p.join("");
  const V = "abc123secretvalue";
  const cases = [
    `--authorization ${V}`, `--credentials ${V}`, `--auth ${V}`, `--pat ${V}`, `--passwd ${V}`,
    `X-Custom-Token: ${V}`, `x-goog-api-key: ${V}`, `apikey: ${V}`, `client_secret: ${V}`, `Authorization: token ${V}`,
    `https://${V}@host/x`, `https://host/x?sig=${V}`, `https://host/x?access_key=${V}&client_secret=${V}`,
    `https://host/?auth=${V}`, `https://host/?X-Amz-Signature=${V}`,
    `apiKey=${V}`, `password=${V}`, `export token=${V}`,
    `-u user:${V}`, `--user user:${V}`,
    j("gh", "s_", "abcdefghijklmnop123456"), j("gh", "o_", "abcdefghijklmnop123456"), j("gh", "u_", "abcdefghijklmnop123456"),
    j("np", "m_", "abcdefghijklmnopqrstuvwxyz0123456789"), j("AI", "zaSy", "A1234567890abcdefghijklmnopqrstuvw"),
    j("hf", "_", "abcdefghijklmnopqrstuvwxyz1234"), j("SG", ".", "abcdefghijklmnop", ".", "qrstuvwxyz0123456789"),
    j("ey", "JhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.", "abc123SIGNATURE_xyz"),
    j("-----BEGIN ", "PRIVATE KEY-----\nMIIabcDEF123\n-----END ", "PRIVATE KEY-----"),
  ];
  for (const input of cases) {
    const out = redactSecrets(input);
    assert.ok(!/abc123secretvalue|abcdefghijkl|abc123SIGNATURE|MIIabcDEF123/.test(out), `leak: ${JSON.stringify(input)} => ${JSON.stringify(out)}`);
    assert.ok(out.includes("<REDACTED>"), `no marker: ${JSON.stringify(out)}`);
  }
  // non-secret text is untouched
  assert.equal(redactSecrets("node server.js --port 3000 --verbose"), "node server.js --port 3000 --verbose");
  assert.equal(redactSecrets("https://example.com/path?page=2"), "https://example.com/path?page=2");
});

test("R2-B7: redactSecrets handles JSON-quoted keys and stays linear on long inputs", () => {
  assert.ok(!redactSecrets('{"api_key": "abcdef123456"}').includes("abcdef123456"));
  assert.ok(!redactSecrets('{"password":"hunter2hunter2"}').includes("hunter2hunter2"));
  for (const tail of [" ", "=", ":"]) {
    const t0 = Date.now();
    redactSecrets("a".repeat(200000) + tail);
    assert.ok(Date.now() - t0 < 1000, `redactSecrets too slow on long input (tail ${JSON.stringify(tail)})`);
  }
});

test("R3-B9: Windows-style home is not swallowed by a C:/Users root; foreign Windows homes stay protected", () => {
  const home = "C:/Users/runner";
  const o = { homeDir: home, windowsSemantics: true };
  assert.equal(isProtectedPath("C:/Users/runner/.cache/vite", o).protected, false);
  assert.equal(isProtectedPath("C:\\Users\\runner\\.cache\\vite", o).protected, false);
  assert.equal(isProtectedPath("C:/Users", o).protected, true);
  assert.equal(isProtectedPath("C:/Users/alice/.cache/x", o).protected, true);
  assert.equal(isProtectedPath("C:/Users/runner/.SSH/id", o).protected, true);
  assert.equal(isProtectedPath("C:/Windows/System32", o).protected, true);
});

test("R3-B10: symlink followed by '..' is resolved the way the OS does (symlink first, then parent)", () => {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sj-r3b10-")));
  try {
    const home = path.join(base, "home");
    fs.mkdirSync(path.join(home, ".ssh", "sub"), { recursive: true });
    fs.writeFileSync(path.join(home, ".ssh", "secret"), "x");
    fs.mkdirSync(path.join(base, "outside"));
    fs.symlinkSync(path.join(home, ".ssh", "sub"), path.join(base, "outside", "sublink"));
    fs.symlinkSync(path.join(home, ".ssh"), path.join(base, "outside", "sshlink"));
    const opts = { homeDir: home };
    // OS: outside/sublink/.. == home/.ssh ; lexical removal would give base/outside
    assert.equal(isProtectedPath(`${base}/outside/sublink/../secret`, opts).protected, true);
    assert.equal(isProtectedPath(`${base}/outside/sublink/..`, opts).protected, true);
    // outside/sshlink/.. == home
    assert.equal(isProtectedPath(`${base}/outside/sshlink/..`, opts).protected, true);
    // control: a plain cache under home is still removable
    fs.mkdirSync(path.join(home, ".cache", "vite"), { recursive: true });
    assert.equal(isProtectedPath(path.join(home, ".cache", "vite"), opts).protected, false);
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("R3-B11: macOS /System/Volumes/Data alias cannot bypass the denylist", () => {
  const home = "/Users/alice";
  const D = "/System/Volumes/Data";
  for (const p of [`${D}${home}`, `${D}${home}/Documents/x`, `${D}${home}/.aws/credentials`, `${D}/Users`, `${D}/Applications`, `${D}/Library`, `${D}/private/etc`, `${D}/usr/local`, `${D.toLowerCase()}${home}/.ssh/id`, D]) {
    assert.equal(isProtectedPath(p, { homeDir: home }).protected, true, `expected protected: ${p}`);
  }
  // the Data volume only exists on macOS; on Windows "/System" is a plain (protected) directory name
  if (process.platform !== "win32") {
    assert.equal(isProtectedPath(`${D}${home}/.cache/vite`, { homeDir: home }).protected, false);
  }
});

test("R3-B12: redactSecrets covers underscore and single-dash credential flags, more token shapes, and stays linear on dashes", () => {
  const j = (...p) => p.join("");
  const V = "abc123secretvalue";
  for (const input of [
    `--access_token ${V}`, `--auth_token ${V}`, `--bot_token=${V}`, `--client_secret ${V}`, `--db_password ${V}`,
    `-token ${V}`, `-api-key ${V}`, `-Password ${V}`, `https://host/x?code=${V}`, `https://host/x?jwt=${V}`,
    j("sk", "-or-v1-", "abcdef0123456789abcdef"), j("gs", "k_", "abcdefghijklmnopqrstuvwx"), j("nt", "n_", "abcdefghijklmnopqrstuvwx"),
  ]) {
    const out = redactSecrets(input);
    assert.ok(!/abc123secretvalue|abcdef0123456789|abcdefghijklmnop/.test(out), `leak: ${input} => ${out}`);
  }
  for (const s of ["-".repeat(100000), "-a".repeat(50000), "--".repeat(50000) + "x"]) {
    const t0 = Date.now();
    redactSecrets(s);
    assert.ok(Date.now() - t0 < 1000, "redactSecrets slow on dash-heavy input");
  }
});

test("R4: shared Rust/Node protect vectors (crates/sj-core/tests/fixtures/protect_vectors.json)", { skip: process.platform === "win32" }, () => {
  const vectors = JSON.parse(
    fs.readFileSync(new URL("../../../crates/sj-core/tests/fixtures/protect_vectors.json", import.meta.url), "utf8")
  );
  const opts = { homeDir: vectors.home };
  for (const p of vectors.protected) {
    assert.equal(isProtectedPath(p, opts).protected, true, `shared vector expected protected: ${p}`);
  }
  for (const p of vectors.unprotected) {
    assert.equal(isProtectedPath(p, opts).protected, false, `shared vector expected unprotected: ${p}`);
  }
});

test("R4-B13/B14: /System subtree and filesystem alias roots are protected; unknown root-level dot entries fail closed", () => {
  const o = { homeDir: "/Users/alice" };
  for (const p of ["/System/Volumes", "/System/Volumes/VM", "/System/Cryptexes", "/System/DriverKit", "/.nofollow/Users/alice/.ssh", "/.vol/1/2", "/.resolve/1/x", "/.somethingnew/x"]) {
    assert.equal(isProtectedPath(p, o).protected, true, p);
  }
});

test("R4-B14: a real alias path through /.nofollow to a protected dir is denied (macOS only)", { skip: process.platform !== "darwin" }, () => {
  const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sj-r4b14-")));
  try {
    fs.mkdirSync(path.join(home, ".ssh"));
    assert.equal(isProtectedPath(`/.nofollow${home}/.ssh/x`, { homeDir: home }).protected, true);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("R4-B15: drive-letter strings fail closed on POSIX hosts unless Windows semantics are requested", { skip: process.platform === "win32" }, () => {
  const cwd = process.cwd();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sj-r4b15-"));
  try {
    process.chdir(tmp);
    fs.mkdirSync(path.join(tmp, "C:"));
    fs.mkdirSync(path.join(tmp, ".ssh"));
    const r = isProtectedPath("C:/../.ssh", { homeDir: "/Users/alice" });
    assert.equal(r.protected, true, "C:/../.ssh must not be treated as unprotected on POSIX");
    assert.equal(isProtectedPath("D:/data/x", { homeDir: "/Users/alice" }).protected, true);
  } finally {
    process.chdir(cwd);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
