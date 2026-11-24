import assert from "node:assert/strict";
import test from "node:test";
import { definePlugin } from "../src/index.mjs";

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
