import assert from "node:assert/strict";
import test from "node:test";
import { isSafeNavigationUrl, validateIpcMethod, validateTargetPath } from "../src/ipcValidation";

test("rejects shell metacharacters and empty paths in IPC payloads", () => {
  assert.equal(validateTargetPath("/home/developer/project").valid, true);
  assert.equal(validateTargetPath("").valid, false);
  assert.equal(validateTargetPath("/tmp; rm -rf /").valid, false);
  assert.equal(validateTargetPath("/tmp/$(whoami)").valid, false);
  assert.equal(validateTargetPath("/tmp/`id`").valid, false);
  assert.equal(validateTargetPath("/tmp | cat").valid, false);
});

test("allows only allowlisted IPC methods", () => {
  assert.equal(validateIpcMethod("summary"), true);
  assert.equal(validateIpcMethod("disk"), true);
  assert.equal(validateIpcMethod("plan_reap"), true);
  assert.equal(validateIpcMethod("execute_reap"), true);
  assert.equal(validateIpcMethod("exec_shell"), false);
  assert.equal(validateIpcMethod("fs_write"), false);
});

test("locks down navigation and external popups", () => {
  assert.equal(isSafeNavigationUrl("http://127.0.0.1:5173/index.html"), true);
  assert.equal(isSafeNavigationUrl("file:///app/dist/index.html"), true);
  assert.equal(isSafeNavigationUrl("https://evil.example/phish"), false);
  assert.equal(isSafeNavigationUrl("javascript:alert(1)"), false);
});
