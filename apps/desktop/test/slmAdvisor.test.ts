import assert from "node:assert/strict";
import test from "node:test";
import { SlmAdvisorService } from "../src/slmAdvisor";

test("SLM advisor is strictly OFF by default and blocks external cloud URLs", async () => {
  const advisor = new SlmAdvisorService();
  assert.equal(advisor.getConfig().enabled, false);

  const disabledRes = await advisor.explainPlan({ summary: {}, candidates: [] });
  assert.equal(disabledRes.ok, false);
  assert.equal(disabledRes.reason, "slm_disabled");

  assert.throws(
    () =>
      advisor.updateConfig({
        enabled: true,
        url: "https://api.openai.com/v1/chat/completions",
      }),
    /external_cloud_url_blocked/
  );

  advisor.updateConfig({
    enabled: true,
    url: "http://127.0.0.1:11434/v1/chat/completions",
    model: "qwen2.5:1.5b",
  });
  assert.equal(advisor.getConfig().enabled, true);
});
