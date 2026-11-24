// eslint-disable-next-line @typescript-eslint/no-var-requires
const core = require("@spacejanitor/core");

export interface SlmConfig {
  enabled: boolean;
  url: string;
  allowLan: boolean;
  model: string;
}

export class SlmAdvisorService {
  private config: SlmConfig = {
    enabled: false,
    url: "http://127.0.0.1:11434/v1/chat/completions",
    allowLan: false,
    model: "qwen2.5:1.5b",
  };

  getConfig(): SlmConfig {
    return { ...this.config };
  }

  updateConfig(next: Partial<SlmConfig>): SlmConfig {
    const merged: SlmConfig = {
      enabled: Boolean(next.enabled ?? this.config.enabled),
      url: String(next.url ?? this.config.url),
      allowLan: Boolean(next.allowLan ?? this.config.allowLan),
      model: String(next.model ?? this.config.model),
    };

    if (merged.enabled || next.url !== undefined) {
      const check = core.validateLoopbackSlmUrl(merged.url, { allowLan: merged.allowLan });
      if (!check.allowed) {
        throw new Error(check.reason || "invalid_slm_url");
      }
    }

    this.config = merged;
    return this.getConfig();
  }

  async explainPlan(input: {
    summary: Record<string, unknown>;
    candidates: Array<Record<string, unknown>>;
    memoryReport?: Record<string, unknown>;
  }): Promise<Record<string, unknown>> {
    return core.adviseWithLocalSlm({
      enabled: this.config.enabled,
      url: this.config.url,
      allowLan: this.config.allowLan,
      model: this.config.model,
      summary: input.summary,
      candidates: input.candidates,
      memoryReport: input.memoryReport,
    });
  }
}
