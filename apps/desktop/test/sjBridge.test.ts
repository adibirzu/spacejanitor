import assert from "node:assert/strict";
import test from "node:test";
import { resolveSjBinary, SjBridge } from "../src/sjBridge";

test("resolves sj binary with fallback order and falls back gracefully to node-fallback", async () => {
  const resolved = resolveSjBinary({
    resourcesPath: "/nonexistent/resources",
    cwd: "/nonexistent/cwd",
    existsSync: () => false,
  });
  assert.equal(resolved, null);

  const bridge = new SjBridge({
    binaryPath: null,
  });
  const doc = await bridge.invoke("doctor");
  assert.equal(doc.schema, "spacejanitor.doctor.v1");
  assert.equal(doc.source, "node-fallback");
});
