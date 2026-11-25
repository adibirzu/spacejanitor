import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  SCHEMA_VERSIONS,
  redactSecrets,
} from "../src/index.mjs";
import { up, urlWith } from "./_fixtures.mjs";

const SYNTHETIC_HOME = "/home/developer";

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

test("R2-B7: redactSecrets covers extended flag names, custom headers, URL userinfo/query signatures, bare env keys, PEM and vendor tokens", () => {
  const j = (...p) => p.join("");
  const V = "abc123secretvalue";
  const cases = [
    `--authorization ${V}`, `--credentials ${V}`, `--auth ${V}`, `--pat ${V}`, `--passwd ${V}`,
    `X-Custom-Token: ${V}`, `x-goog-api-key: ${V}`, `apikey: ${V}`, `client_secret: ${V}`, `Authorization: token ${V}`,
    `https://${V}@host/x`, `https://host/x?sig=${V}`, `https://host/x?access_key=${V}&client_secret=${V}`,
    `https://host/?auth=${V}`, `https://host/?X-Amz-Signature=${V}`,
    `apiKey=${V}`, `password=${V}`, `export token=${V}`,
    `-u ${up("user", V)}`, `--user ${up("user", V)}`,
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

