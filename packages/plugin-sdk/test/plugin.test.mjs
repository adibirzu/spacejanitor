import assert from "node:assert/strict";
import test from "node:test";
import { definePlugin, validatePluginRules } from "../src/index.mjs";
import { activeSjBinary } from "../../core/src/index.mjs";

const SYNTHETIC_HOME = "/home/developer";

test("accepts valid v1 plugin manifest", () => {
  const plugin = definePlugin({
    id: "sample-cleaner",
    version: "1.0.0",
    apiVersion: "1",
    capabilities: ["rule-pack", "widget"],
    rules: [{ id: "t1-sample", paths: ["~/.cache/sample"] }],
  });
  assert.equal(plugin.id, "sample-cleaner");
  assert.equal(plugin.apiVersion, "1");
  assert.deepEqual(plugin.capabilities, ["rule-pack", "widget"]);
});

test("rejects invalid plugin id or capability", () => {
  assert.throws(() => definePlugin({ id: "Bad_ID", apiVersion: "1", capabilities: ["rule-pack"] }), RangeError);
  assert.throws(() => definePlugin({ id: "good-id", apiVersion: "2", capabilities: ["rule-pack"] }), RangeError);
  assert.throws(() => definePlugin({ id: "good-id", apiVersion: "1", capabilities: ["unknown"] }), RangeError);
});

test("validates plugin rules against core immutable protected denylist", () => {
  const plugin = definePlugin({
    id: "mixed-rules",
    version: "1.0.0",
    apiVersion: "1",
    capabilities: ["rule-pack", "collector", "exporter"],
    rules: [
      { id: "safe-cache", paths: ["~/.cache/mytool"] },
      { id: "unsafe-ssh", paths: ["~/.ssh/id_ed25519"] },
      { id: "unsafe-system", paths: ["/System/Library"] },
    ],
  });

  const result = validatePluginRules(plugin, { homeDir: SYNTHETIC_HOME });
  if (!activeSjBinary()) {
    // Fail closed: without the Rust gate no plugin rule can be proven safe.
    assert.equal(result.allowedRules.length, 0);
    assert.equal(result.rejectedRules.length, 3);
    assert.ok(result.rejectedRules.every((r) => r.reason === "sj_unavailable"));
    return;
  }
  assert.equal(result.allowedRules.length, 1);
  assert.equal(result.allowedRules[0].id, "safe-cache");
  assert.equal(result.rejectedRules.length, 2);
  assert.equal(result.rejectedRules[0].ruleId, "unsafe-ssh");
  assert.equal(result.rejectedRules[1].ruleId, "unsafe-system");
});
