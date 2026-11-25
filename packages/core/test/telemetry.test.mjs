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
  collectCleanableCaches,
  activeSjBinary,
  validateLoopbackSlmUrl,
  redactSlmPayload,
  adviseWithLocalSlm,
  formatToon,
} from "../src/index.mjs";
import { up, urlWith } from "./_fixtures.mjs";

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

  const orphans = await collectOrphans({ targetPath: process.cwd(), includeOrphans: true });
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
            urlWith("https", "user", "superSecretPass", "mcp.example.com/sse?api_key=querySecretVal"),
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
          args: ["--auth", "authSecretVal99", "--passwd", "pwSecretVal99", "-u", up("bob", "basicSecretVal99")],
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

test("R3-B12: collectMcpAudit never prints URL paths/queries (secret-in-path) and keeps TOML env tables out of the server list", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-mcp-r3-"));
  try {
    fs.writeFileSync(
      path.join(tmpDir, "mcp.json"),
      JSON.stringify({
        mcpServers: {
          hosted: { url: "https://mcp.example.com/api/mcp/s/pathSecretTok0123456789/sse" },
          viaArg: { command: "npx", args: ["mcp-remote", "https://mcp.example.com/k/argPathSecretTok0123456789?x=1"] },
          flagy: { command: "node", args: ["--access_token", "flagSecretVal99", "-token", "dashSecretVal99"] },
        },
      })
    );
    fs.writeFileSync(
      path.join(tmpDir, "config.toml"),
      '[mcp_servers.tomlsrv]\ncommand = "node"\n[mcp_servers.tomlsrv.env]\nAPI_KEY = "tomlEnvSecretVal99"\n'
    );
    const audit = await collectMcpAudit({ configDirs: [tmpDir] });
    const text = JSON.stringify(audit);
    for (const s of ["pathSecretTok0123456789", "argPathSecretTok0123456789", "flagSecretVal99", "dashSecretVal99", "tomlEnvSecretVal99"]) {
      assert.equal(text.includes(s), false, `leaked ${s}`);
    }
    assert.ok(text.includes("mcp.example.com"), "origin should still be reported");
    assert.equal(audit.totalServers, 4, "toml env table must not count as its own server");
    const hosted = audit.servers.find((s) => s.name === "hosted");
    assert.equal(hosted.hasSecretRisk, true);
    const toml = audit.servers.find((s) => s.name === "tomlsrv");
    assert.equal(toml.hasSecretRisk, true);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("R4-B16: collectMcpAudit prints header names only, never header values", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-mcp-r4-"));
  try {
    fs.writeFileSync(
      path.join(tmpDir, "mcp.json"),
      JSON.stringify({
        mcpServers: {
          hdr: { url: "https://mcp.example.com/sse", headers: { "X-Honeycomb-Team": "hcSecretValue0123456789", "X-Custom-Thing": "customSecretVal99" } },
        },
      })
    );
    const audit = await collectMcpAudit({ configDirs: [tmpDir] });
    const text = JSON.stringify(audit);
    assert.equal(text.includes("hcSecretValue0123456789"), false);
    assert.equal(text.includes("customSecretVal99"), false);
    const srv = audit.servers[0];
    assert.deepEqual(srv.headerNames, ["X-Honeycomb-Team", "X-Custom-Thing"]);
    assert.equal(srv.hasSecretRisk, true);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("R5-B17: mcp-audit prints header names only for every args-based header form (JSON and TOML)", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-mcp-r5-"));
  const V = (t) => `FAKEVAL-${t}-0123456789abcdef`;
  try {
    fs.writeFileSync(
      path.join(tmpDir, "mcp.json"),
      JSON.stringify({
        mcpServers: {
          sep: { command: "npx", args: ["-y", "mcp-remote", "https://mcp.example.com/sse", "--header", `X-Custom: ${V("sep")}`] },
          eq: { command: "npx", args: ["mcp-remote", "https://mcp.example.com/sse", `--header=X-Tenant:${V("eq")}`] },
          short: { command: "x", args: ["-H", `X-Sess: ${V("short")}`] },
          glued: { command: "x", args: [`-HX-Glued: ${V("glued")}`] },
          multi: { command: "x", args: ["--header", `A-One: ${V("m1")}`, "--header", `B-Two: ${V("m2")}`] },
        },
      })
    );
    fs.writeFileSync(
      path.join(tmpDir, "config.toml"),
      `[mcp_servers.tomlhdr]\ncommand = "npx"\nargs = ["mcp-remote", "https://mcp.example.com/sse", "--header", "X-Toml: ${V("toml")}"]\n`
    );
    const audit = await collectMcpAudit({ configDirs: [tmpDir] });
    const text = JSON.stringify(audit);
    for (const t of ["sep", "eq", "short", "glued", "m1", "m2", "toml"]) {
      assert.equal(text.includes(V(t)), false, `header value leaked: ${t}`);
    }
    assert.equal(audit.totalServers, 6);
    const by = Object.fromEntries(audit.servers.map((s) => [s.name, s]));
    assert.deepEqual(by.sep.headerNames, ["X-Custom"]);
    assert.deepEqual(by.eq.headerNames, ["X-Tenant"]);
    assert.deepEqual(by.short.headerNames, ["X-Sess"]);
    assert.deepEqual(by.glued.headerNames, ["X-Glued"]);
    assert.deepEqual(by.multi.headerNames, ["A-One", "B-Two"]);
    assert.deepEqual(by.tomlhdr.headerNames, ["X-Toml"]);
    for (const s of audit.servers) assert.equal(s.hasSecretRisk, true, s.name);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("R5-B18: collectCleanableCaches offers the macOS Library/Caches targets", async () => {
  const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sj-caches-")));
  try {
    for (const rel of ["Library/Caches/Homebrew", "Library/Caches/pip", "Library/Caches/pnpm", ".npm/_cacache", "Library/Keychains"]) {
      fs.mkdirSync(path.join(home, rel), { recursive: true });
      fs.writeFileSync(path.join(home, rel, "f"), "x");
    }
    const found = (await collectCleanableCaches({ homeDir: home })).map((c) => path.relative(home, c.path).split(path.sep).join("/")).sort();
    if (!activeSjBinary()) {
      assert.deepEqual(found, [], "no sj gate: no cache may be offered (fail closed)");
      return;
    }
    assert.deepEqual(found, [".npm/_cacache", "Library/Caches/Homebrew", "Library/Caches/pip", "Library/Caches/pnpm"]);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("R6-B19: mcp-audit redacts the value of every two-argument header form (-H KEY VALUE, --headers KEY VALUE)", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-mcp-r6-"));
  const V = (t) => `FAKEVAL-${t}-0123456789`;
  try {
    const servers = {
      a: ["-H", "X-API-Key", V("a")],
      b: ["--headers", "X-API-Key", V("b")],
      c: ["-H", "X-Auth-Token", V("c")],
      d: ["-H", "X-Secret", "shortv"],
      e: ["-H", "Authorization", V("e")],
      f: ["-H", "Cookie", `sid=${V("f")}`],
      g: ["-H", "X-Custom", V("g")],
      h: ["--headers", "Authorization", `Bearer ${V("h")}`],
      i: ["--header", "X-Two", V("i"), "--url", "https://mcp.example.com/sse"],
    };
    fs.writeFileSync(
      path.join(tmpDir, "mcp.json"),
      JSON.stringify({ mcpServers: Object.fromEntries(Object.entries(servers).map(([k, args]) => [k, { command: "mcp-proxy", args }])) })
    );
    const audit = await collectMcpAudit({ configDirs: [tmpDir] });
    const text = JSON.stringify(audit);
    for (const t of "abcefghi") assert.equal(text.includes(V(t)), false, `value leaked: ${t}`);
    assert.equal(text.includes("shortv"), false);
    const by = Object.fromEntries(audit.servers.map((x) => [x.name, x]));
    assert.deepEqual(by.a.headerNames, ["X-API-Key"]);
    assert.deepEqual(by.d.headerNames, ["X-Secret"]);
    assert.deepEqual(by.h.headerNames, ["Authorization"]);
    assert.deepEqual(by.i.headerNames, ["X-Two"]);
    assert.ok(text.includes("--url"), "following flag must be preserved");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

function git(cwd, ...args) {
  return execFileSync("git", ["-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { cwd, encoding: "utf8" });
}

test("R7-B24: credential values containing spaces never reach reports, the IPC summary or the SLM payload", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-mcp-r7-"));
  const W = ["spacedWordOne", "spacedWordTwo"];
  const secretsIn = (text) => W.filter((w) => text.includes(w));
  try {
    fs.writeFileSync(
      path.join(tmpDir, "mcp.json"),
      JSON.stringify({
        mcpServers: {
          sep: { command: "x", args: ["--password", W.join(" ")] },
          eq: { command: "x", args: [`--api-key=${W.join(" ")}`] },
          tok: { command: "x", args: ["--access_token", W.join(" "), "--verbose"] },
          dash: { command: "x", args: ["-p", W.join(" ")] },
          envarg: { command: "docker", args: ["run", "-e", `DB_PASSWORD=${W.join(" ")}`, "img"] },
          quoted: { command: "x", args: [`--secret="${W.join(" ")}"`] },
        },
      })
    );
    const audit = await collectMcpAudit({ configDirs: [tmpDir] });
    assert.deepEqual(secretsIn(JSON.stringify(audit)), [], "report leak");
    assert.ok(JSON.stringify(audit).includes("--verbose"), "unrelated args preserved");
    for (const srv of audit.servers) assert.equal(srv.hasSecretRisk, true, srv.name);

    const summary = await collectSummary({ configDirs: [tmpDir], targetPath: tmpDir });
    assert.deepEqual(secretsIn(JSON.stringify(summary)), [], "IPC summary leak");
    assert.equal(summary.mcpAudit.secretRiskCount, 6);

    let body = "";
    await adviseWithLocalSlm({
      enabled: true,
      url: "http://127.0.0.1:11434/v1/chat/completions",
      summary,
      candidates: [],
      fetchImpl: async (_u, init) => {
        body = String(init.body);
        return { ok: true, status: 200, json: async () => ({ choices: [{ message: { content: "{}" } }] }) };
      },
    });
    assert.ok(body.length > 0, "SLM request was made");
    assert.deepEqual(secretsIn(body), [], "SLM payload leak");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("R8-B25: whole-element redaction covers -u user:pass, -p=, --x= and JSON/key=value argv with spaces (report, summary, SLM body)", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-mcp-r8-"));
  const WORDS = ["AlphaSecretW", "BravoSecretW", "CharlieSecretW", "DeltaSecretW"];
  const leaks = (text) => WORDS.filter((w) => text.includes(w));
  try {
    const servers = {
      u: ["-u", up("alice", "AlphaSecretW BravoSecretW")],
      ueq: [`--user=${up("alice", "AlphaSecretW BravoSecretW")}`],
      peq: ["-p=AlphaSecretW BravoSecretW"],
      teq: ["-t=AlphaSecretW BravoSecretW"],
      json: ["--config", '{"password":"AlphaSecretW \\"BravoSecretW CharlieSecretW\\" DeltaSecretW"}'],
      kv: ["--env", "db_password=AlphaSecretW BravoSecretW"],
      xeq: ["--x-token=AlphaSecretW BravoSecretW"],
      pass: ["--password", "AlphaSecretW BravoSecretW"],
      quoted: ['--secret="AlphaSecretW BravoSecretW"'],
      bare: ["--opt", 'user=alice password="AlphaSecretW BravoSecretW" host=h'],
    };
    fs.writeFileSync(
      path.join(tmpDir, "mcp.json"),
      JSON.stringify({ mcpServers: Object.fromEntries(Object.entries(servers).map(([k, args]) => [k, { command: "x", args }])) })
    );
    const audit = await collectMcpAudit({ configDirs: [tmpDir] });
    assert.deepEqual(leaks(JSON.stringify(audit)), [], "report leak");
    for (const srv of audit.servers) assert.equal(srv.hasSecretRisk, true, srv.name);

    const summary = await collectSummary({ configDirs: [tmpDir], targetPath: tmpDir });
    assert.deepEqual(leaks(JSON.stringify(summary)), [], "IPC summary leak");

    let body = "";
    await adviseWithLocalSlm({
      enabled: true,
      url: "http://127.0.0.1:11434/v1/chat/completions",
      summary,
      candidates: [],
      fetchImpl: async (_u, init) => {
        body = String(init.body);
        return { ok: true, status: 200, json: async () => ({ choices: [{ message: { content: "{}" } }] }) };
      },
    });
    assert.ok(body.length > 0);
    assert.deepEqual(leaks(body), [], "SLM payload leak");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("R9-B30: 32-shape credential argv probe (+TOML, +candidate field) never leaks through the report, the summary or the SLM body", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-mcp-r9-"));
  const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-mcp-r9h-"));
  const cases = {
    mysql_short_cluster_p: ["-h", "db", "-uroot", "-pLEAK01xyzSecret"],
    short_cluster_t: ["-tLEAK02tokenvalue"],
    user_cluster_u_colon: [`-u${up("admin", "LEAK03pw")}`],
    curl_user_space: ["-u", up("admin", "LEAK04pw")],
    long_flag_eq: ["--api-key=LEAK05abc"],
    long_flag_space: ["--client-secret", "LEAK06abc"],
    flag_value_starting_dashdash: ["--token", "--LEAK07weird"],
    url_userinfo_arg: ["--db", urlWith("postgres", "app", "LEAK08pw", "db.internal:5432/x")],
    url_userinfo_at_in_pw: ["--db", "postgres://app:p@LEAK09ss@db.internal/x"],
    env_assign: ["env", "OPENAI_API_KEY=LEAK10sk"],
    env_assign_unrecognized_name: [`DATABASE_URL=${urlWith("mysql", "u", "LEAK11", "h/db")}`],
    env_assign_dsn: ["SENTRY_DSN=https://LEAK12public@o1.ingest.sentry.io/1"],
    json_fragment: ["--config", "{\"apiKey\":\"LEAK13\"}"],
    json_fragment_nonsecret_name: ["--config", "{\"dsn\":\"https://LEAK14@sentry.io/1\"}"],
    yaml_fragment: ["--inline", "client_secret: LEAK15"],
    base64_blob: ["--config-b64", Buffer.from("{\"password\":\"LEAK16\"}").toString("base64")],
    heredoc_style: ["--script", "cat <<EOF\nexport GITHUB_TOKEN=LEAK17\nEOF"],
    long_flag_name_over_64: [`--${"x".repeat(70)}-token`, "LEAK18"],
    unicode_nbsp: ["--token LEAK19"],
    unicode_ideographic_space_header: ["Authorization:　Bearer　LEAK20abcdefgh"],
    connection_string: ["--conn", "Server=x;User Id=sa;Password=LEAK21;"],
    conn_no_space_value: ["--conn=Server=x;Pwd=LEAK22"],
    slack_webhook_positional: ["https://hooks.slack.com/services/T0/B0/LEAK23XXXXXXXXXXXXXXXX"],
    docker_env_cluster: ["-eAWS_SECRET_ACCESS_KEY=LEAK24"],
    docker_env_long_eq: ["--env=GITHUB_PAT=LEAK25"],
    password_stdin_like: ["--password", "LEAK26", "--next"],
    header_twoarg_x_api: ["--header", "X-Api-Key", "LEAK27"],
    header_eq_form: ["--header=X-Goog-Api-Key:LEAK28"],
    bearer_in_single_arg: ["Authorization: Bearer LEAK29abcdefgh"],
    dashed_secret_value: ["--secret", "-LEAK30"],
    kv_colon_form: ["token:LEAK31"],
    very_long_arg: ["--note", "a".repeat(200000) + " password=LEAK32"],
  };
  const leaks = (text) => [...new Set(String(text).match(/LEAK\d\d/g) || [])];
  try {
    const mcpServers = {};
    for (const [name, args] of Object.entries(cases)) mcpServers[name] = { command: "tool", args };
    fs.writeFileSync(path.join(tmpDir, "mcp.json"), JSON.stringify({ mcpServers }));
    fs.writeFileSync(
      path.join(tmpDir, "config.toml"),
      ["[mcp_servers.toml_mysql]", 'command = "mysql"', 'args = ["-uroot", "-pLEAK40toml"]', "[mcp_servers.toml_env]", 'command = "x"', 'env = { API_TOKEN = "LEAK41inline" }', ""].join("\n")
    );
    const audit = await collectMcpAudit({ configDirs: [tmpDir] });
    const bad = audit.servers.map((s) => [s.name, leaks(JSON.stringify(s))]).filter(([, l]) => l.length);
    assert.deepEqual(bad, [], "report leaks");
    for (const s of audit.servers) {
      if (s.name.startsWith("toml_mysql") || ["mysql_short_cluster_p", "short_cluster_t", "user_cluster_u_colon"].includes(s.name)) {
        assert.equal(s.hasSecretRisk, true, `${s.name} must be flagged`);
      }
    }
    const summary = await collectSummary({ configDirs: [tmpDir], homeDir, targetPath: homeDir });
    assert.deepEqual(leaks(JSON.stringify(summary)), [], "summary leaks");
    let body = "";
    await adviseWithLocalSlm({
      enabled: true,
      url: "http://127.0.0.1:11434/v1/chat/completions",
      summary,
      candidates: [{ path: "/tmp/x", note: "-pLEAK50direct" }],
      memoryReport: { freeBytes: 64 * 1024 ** 3 },
      fetchImpl: async (_u, init) => {
        body = String(init.body);
        return { ok: true, status: 200, json: async () => ({ choices: [{ message: { content: "{}" } }] }) };
      },
    });
    assert.ok(body.length > 0);
    assert.deepEqual(leaks(body), [], "SLM body leaks");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

function lyingFsmonitorFixture(base) {
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
  return { repo, wt, marker };
}

test("R10-B33: attached short-flag credentials inside shell strings and -p-… leak nowhere; ordinary flags stay readable", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sj-mcp-r10b33-"));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "sj-mcp-r10b33h-"));
  const leaks = (t) => [...new Set(String(t).match(/LEAK\d\d/g) || [])];
  try {
    fs.writeFileSync(
      path.join(dir, "mcp.json"),
      JSON.stringify({
        mcpServers: {
          sh_c_mysql: { command: "sh", args: ["-c", "mysql -h db -uroot -pLEAK71shell mydb"] },
          dash_leading_pw: { command: "mysql", args: ["-uroot", "-p-LEAK72dash"] },
          sh_c_curl_u: { command: "bash", args: ["-lc", `curl -u${up("admin", "LEAK73pw")} https://x`] },
          quoted_shell: { command: "sh", args: ["-c", "mysql -uroot '-pLEAK74quoted' db"] },
          plain_flags: { command: "tool", args: ["-transport", "stdio", "-timeout", "30", "-tls", "-url", "x", "-update", "-path", "/srv", "-port=8080"] },
        },
      })
    );
    const audit = await collectMcpAudit({ configDirs: [dir] });
    assert.deepEqual(leaks(JSON.stringify(audit)), []);
    const by = Object.fromEntries(audit.servers.map((s) => [s.name, s]));
    for (const n of ["sh_c_mysql", "dash_leading_pw", "sh_c_curl_u", "quoted_shell"]) assert.equal(by[n].hasSecretRisk, true, n);
    // over-redaction stays small: ordinary single-dash flags are left readable
    for (const w of ["-transport", "-timeout", "-tls", "-url", "-update", "-path", "-port=8080"]) {
      assert.ok(by.plain_flags.argsRedacted.includes(w), `${w} must stay readable: ${by.plain_flags.argsRedacted}`);
    }
    const summary = await collectSummary({ configDirs: [dir], homeDir: home, targetPath: home });
    assert.deepEqual(leaks(JSON.stringify(summary)), []);
    let body = "";
    await adviseWithLocalSlm({
      enabled: true,
      url: "http://127.0.0.1:11434/v1/chat/completions",
      summary,
      candidates: [{ path: "/tmp/x", note: "mysql -uroot -pLEAK75cand" }],
      fetchImpl: async (_u, init) => {
        body = String(init.body);
        return { ok: true, status: 200, json: async () => ({ choices: [{ message: { content: "{}" } }] }) };
      },
    });
    assert.deepEqual(leaks(body), []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
});

