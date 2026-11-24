import React, { useState } from "react";
import { formatBytes, RemediationPlan } from "../types";

interface Props {
  plan: RemediationPlan | null;
  onClose: () => void;
  onExecute: (planSha256: string, phrase: string) => Promise<void>;
  resultMessage: string | null;
}

export const RemediationModal: React.FC<Props> = ({ plan, onClose, onExecute, resultMessage }) => {
  const [inspected, setInspected] = useState(false);
  const [phrase, setPhrase] = useState("");
  const [busy, setBusy] = useState(false);

  if (!plan) return null;

  const canExecute = inspected && phrase.trim() === plan.confirmationPhrase && plan.items.length > 0 && !busy;

  const handleConfirm = async () => {
    setBusy(true);
    try {
      await onExecute(plan.planSha256, phrase.trim());
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Two-Step Remediation Gate">
      <div className="modal-panel">
        <div className="card-header">
          <h2>Two-Step SHA-256 Remediation Gate</h2>
          <button type="button" className="btn-ghost" onClick={onClose}>
            Close
          </button>
        </div>

        <div className="step-box">
          <h3>Step 1: Dry-Run Plan Inspection</h3>
          <p className="muted">
            Reclaimable: <strong>{formatBytes(plan.totalBytes)}</strong> across{" "}
            <strong>{plan.items.length}</strong> target(s).
          </p>
          <div className="badge-row">
            <span className="badge badge-ok">Protected Denylist Pass</span>
            {plan.blockedItems.length > 0 && (
              <span className="badge badge-warn">{plan.blockedItems.length} Protected Item(s) Blocked</span>
            )}
          </div>
          <div className="digest-box">
            <span className="muted">SHA-256 Digest:</span>
            <code>{plan.planSha256}</code>
          </div>
          <ul className="target-list">
            {plan.items.map((item) => (
              <li key={item.id}>
                <span>{item.path}</span>
                <strong>{formatBytes(item.bytes)}</strong>
              </li>
            ))}
          </ul>
          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={inspected}
              onChange={(e) => setInspected(e.target.checked)}
            />
            <span>I have inspected the exact paths and byte savings above.</span>
          </label>
        </div>

        <div className="step-box">
          <h3>Step 2: Typed Confirmation Unlock</h3>
          <p className="muted">
            Type <code>{plan.confirmationPhrase}</code> to unlock execution:
          </p>
          <input
            type="text"
            className="text-input"
            value={phrase}
            onChange={(e) => setPhrase(e.target.value)}
            placeholder={plan.confirmationPhrase}
            disabled={!inspected}
          />
          <div className="modal-actions">
            <button type="button" className="btn-ghost" onClick={onClose}>
              Cancel (Keep Dry-Run)
            </button>
            <button
              type="button"
              className="btn-danger"
              disabled={!canExecute}
              onClick={() => void handleConfirm()}
            >
              {busy ? "Executing..." : "Execute Cleanup"}
            </button>
          </div>
          {resultMessage && <div className="result-banner">{resultMessage}</div>}
        </div>
      </div>
    </div>
  );
};
