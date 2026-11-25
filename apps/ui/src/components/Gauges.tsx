import React from "react";
import { formatBytes } from "../types";

export const DiskHeroGauge: React.FC<{
  freeBytes: number;
  totalBytes: number;
  freeGiB: number;
  status: string;
}> = ({ freeBytes, totalBytes, freeGiB, status }) => {
  const usedRatio = totalBytes > 0 ? Math.min(1, Math.max(0, (totalBytes - freeBytes) / totalBytes)) : 0;
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference * (1 - usedRatio);

  return (
    <div className="card hero-card">
      <div className="card-header">
        <h2>Disk Free Capacity</h2>
        <span className={`badge badge-${status.toLowerCase()}`}>{status}</span>
      </div>
      <div className="gauge-row">
        <svg width="132" height="132" viewBox="0 0 132 132" aria-label={`Disk usage ${Math.round(usedRatio * 100)}%`}>
          <circle cx="66" cy="66" r={radius} fill="none" stroke="var(--border)" strokeWidth="12" />
          <circle
            cx="66"
            cy="66"
            r={radius}
            fill="none"
            stroke="var(--accent)"
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            transform="rotate(-90 66 66)"
          />
          <text x="66" y="62" textAnchor="middle" className="gauge-val">
            {freeGiB}
          </text>
          <text x="66" y="80" textAnchor="middle" className="gauge-unit">
            GiB free
          </text>
        </svg>
        <div className="threshold-list">
          <div className={`thresh ${freeGiB < 150 ? "active" : ""}`}>150 GiB Check</div>
          <div className={`thresh ${freeGiB < 100 ? "active" : ""}`}>100 GiB Alert</div>
          <div className={`thresh ${freeGiB < 50 ? "active" : ""}`}>50 GiB Floor</div>
          <div className={`thresh ${freeGiB < 20 ? "active-crit" : ""}`}>20 GiB Critical</div>
          <div className="muted">Total volume: {formatBytes(totalBytes)}</div>
        </div>
      </div>
    </div>
  );
};

export const MemoryComparisonCard: React.FC<{
  usedBytes: number;
  totalBytes: number;
  swapUsedBytes: number;
  rssSumBytes: number;
  status: string;
}> = ({ usedBytes, totalBytes, swapUsedBytes, rssSumBytes, status }) => {
  const safeTotal = Math.max(totalBytes, 1);
  const rssPct = Math.min(100, Math.round((rssSumBytes / safeTotal) * 100));
  const truePct = Math.min(100, Math.round(((usedBytes + swapUsedBytes) / safeTotal) * 100));

  return (
    <div className="card">
      <div className="card-header">
        <h2>True Memory Footprint vs ps RSS</h2>
        <span className={`badge badge-${status.toLowerCase()}`}>{status}</span>
      </div>
      <div className="bar-group">
        <div className="bar-label">
          <span>True Footprint (Resident + Compressed + Swap)</span>
          <strong>{formatBytes(usedBytes + swapUsedBytes)}</strong>
        </div>
        <div className="bar-track">
          <div className="bar-fill bar-true" style={{ width: `${truePct}%` }} />
        </div>
        <div className="bar-label">
          <span>Reported Process ps RSS Sum</span>
          <strong>{formatBytes(rssSumBytes)}</strong>
        </div>
        <div className="bar-track">
          <div className="bar-fill bar-rss" style={{ width: `${rssPct}%` }} />
        </div>
        <div className="muted">
          Swap in use: {formatBytes(swapUsedBytes)} | Physical RAM: {formatBytes(totalBytes)}
        </div>
      </div>
    </div>
  );
};
