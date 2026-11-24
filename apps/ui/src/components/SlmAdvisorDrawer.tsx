import React, { useState } from "react";
import { DiskConsumer, SlmConfig, SummaryReport } from "../types";

interface Props {
  config: SlmConfig;
  onUpdateConfig: (next: Partial<SlmConfig>) => Promise<void>;
  onExplain: (candidates: DiskConsumer[]) => Promise<{
    ok: boolean;
    reason?: string;
    explanation?: string;
    proposals?: Array<Record<string, unknown>>;
  }>;
  candidates: DiskConsumer[];
  summary: SummaryReport | null;
}

export const SlmAdvisorDrawer: React.FC<Props> = ({
  config,
  onUpdateConfig,
  onExplain,
  candidates,
}) => {
  const [urlInput, setUrlInput] = useState(config.url);
  const [modelInput, setModelInput] = useState(config.model);
  const [allowLan, setAllowLan] = useState(config.allowLan);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [advice, setAdvice] = useState<{
    explanation?: string;
    proposals?: Array<Record<string, unknown>>;
  } | null>(null);

  const handleToggle = async (enabled: boolean) => {
    setError(null);
    try {
      await onUpdateConfig({ enabled, url: urlInput, allowLan, model: modelInput });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update SLM config");
    }
  };

  const handleSaveEndpoint = async () => {
    setError(null);
    try {
      await onUpdateConfig({ enabled: config.enabled, url: urlInput, allowLan, model: modelInput });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid endpoint URL");
    }
  };

  const handleExplain = async () => {
    setError(null);
    setLoading(true);
    try {
      const res = await onExplain(candidates);
      if (!res.ok) {
        setError(res.reason || "Local SLM request failed");
      } else {
        setAdvice({ explanation: res.explanation, proposals: res.proposals });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "SLM error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="card slm-card" aria-label="Optional Local SLM Advisor">
      <div className="card-header">
        <div>
          <h2>Optional Local SLM Advisor (M6)</h2>
          <p className="muted">
            Strictly OFF by default. Loopback-only (127.0.0.1 / localhost). Zero execution authority.
          </p>
        </div>
        <label className="switch-label">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => void handleToggle(e.target.checked)}
          />
          <span>{config.enabled ? "Enabled (On-Demand)" : "Disabled"}</span>
        </label>
      </div>

      {config.enabled && (
        <div className="slm-controls">
          <div className="slm-row">
            <input
              type="url"
              className="text-input"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="http://127.0.0.1:11434/v1/chat/completions"
            />
            <input
              type="text"
              className="text-input small-input"
              value={modelInput}
              onChange={(e) => setModelInput(e.target.value)}
              placeholder="qwen2.5:1.5b"
            />
            <button type="button" className="btn-ghost" onClick={() => void handleSaveEndpoint()}>
              Validate URL
            </button>
          </div>
          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={allowLan}
              onChange={(e) => setAllowLan(e.target.checked)}
            />
            <span>Allow non-loopback LAN endpoint (external cloud URLs remain blocked)</span>
          </label>
          <div className="slm-actions">
            <button
              type="button"
              className="btn-primary"
              disabled={loading}
              onClick={() => void handleExplain()}
            >
              {loading ? "Analyzing..." : "Explain Plan with Local SLM"}
            </button>
          </div>
        </div>
      )}

      {error && <div className="error-banner">{error}</div>}
      {advice && (
        <div className="advice-box">
          {advice.explanation && <p>{advice.explanation}</p>}
          {advice.proposals && advice.proposals.length > 0 && (
            <ul className="target-list">
              {advice.proposals.map((p, idx) => (
                <li key={idx}>
                  <span>
                    <strong>{String(p.target || "")}</strong> ({String(p.safety_tier || "review")})
                  </span>
                  <span className="muted">{String(p.rationale || "")}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  );
};
