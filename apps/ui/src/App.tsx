import React, { useEffect, useState } from "react";
import { DiskHeroGauge, MemoryComparisonCard } from "./components/Gauges";
import { RemediationModal } from "./components/RemediationModal";
import { SlmAdvisorDrawer } from "./components/SlmAdvisorDrawer";
import { DiskConsumer, formatBytes, RemediationPlan, SlmConfig, SummaryReport } from "./types";

type TabId = "overview" | "disk" | "memory" | "mcp";

const MOCK_SUMMARY: SummaryReport = {
  schema: "spacejanitor.summary.v1",
  source: "browser-preview",
  status: "OK",
  disk: {
    status: "OK",
    totalBytes: 512 * 1024 ** 3,
    freeBytes: 184 * 1024 ** 3,
    freeGiB: 184,
    topConsumers: [
      { id: "c-npm", path: "~/.cache/npm", bytes: 1.4 * 1024 ** 3, kind: "dir", protected: false },
      { id: "c-ssh", path: "~/.ssh", bytes: 64 * 1024, kind: "dir", protected: true, protectedReason: "protected_credential_store" },
    ],
  },
  memory: {
    status: "OK",
    totalBytes: 32 * 1024 ** 3,
    freeBytes: 12 * 1024 ** 3,
    usedBytes: 20 * 1024 ** 3,
    swapUsedBytes: 512 * 1024 ** 2,
    processes: [
      { pid: 1042, ppid: 1, rssBytes: 900 * 1024 ** 2, trueFootprintBytes: 1100 * 1024 ** 2, command: "node-worker", isOrphanPpid1: true },
    ],
  },
  blockers: {
    status: "OK",
    counters: [{ name: "kern.vnodes", current: 42100, max: 263168, percent: 16, status: "OK" }],
  },
  orphans: { candidates: [] },
  trash: { totalBytes: 120 * 1024 ** 2, itemCount: 3, candidates: [] },
  mcpAudit: { totalServers: 2, duplicateCount: 0, secretRiskCount: 0, servers: [] },
};

export const App: React.FC = () => {
  const [tab, setTab] = useState<TabId>("overview");
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [summary, setSummary] = useState<SummaryReport | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [activePlan, setActivePlan] = useState<RemediationPlan | null>(null);
  const [execResult, setExecResult] = useState<string | null>(null);
  const [slmConfig, setSlmConfig] = useState<SlmConfig>({
    enabled: false,
    url: "http://127.0.0.1:11434/v1/chat/completions",
    allowLan: false,
    model: "qwen2.5:1.5b",
  });

  const refresh = async () => {
    if (window.spaceJanitor) {
      const [s, slm] = await Promise.all([
        window.spaceJanitor.getSummary(),
        window.spaceJanitor.getSlmConfig(),
      ]);
      setSummary(s);
      setSlmConfig(slm);
    } else {
      setSummary(MOCK_SUMMARY);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  const allCandidates: DiskConsumer[] = [
    ...(summary?.disk.topConsumers || []),
    ...(summary?.trash.candidates || []),
  ];

  const selectedCandidates = allCandidates.filter((c) => selectedIds.has(c.id));

  const toggleCandidate = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleOpenDryRun = async () => {
    setExecResult(null);
    if (window.spaceJanitor) {
      const plan = await window.spaceJanitor.planRemediation(selectedCandidates);
      setActivePlan(plan);
    } else {
      setActivePlan({
        schema: "spacejanitor.plan.v1",
        dryRun: true,
        items: selectedCandidates.filter((c) => !c.protected),
        blockedItems: selectedCandidates
          .filter((c) => c.protected)
          .map((c) => ({ id: c.id, path: c.path, bytes: c.bytes, reason: c.protectedReason || "protected" })),
        totalBytes: selectedCandidates.reduce((a, b) => a + b.bytes, 0),
        planSha256: "0".repeat(64),
        confirmationPhrase: "CONFIRM-00000000",
        expiresAtMs: Date.now() + 300_000,
      });
    }
  };

  const handleExecute = async (planSha256: string, phrase: string) => {
    if (!window.spaceJanitor) {
      setExecResult("Browser preview mode: execution disabled.");
      return;
    }
    const res = await window.spaceJanitor.executeRemediation({ planSha256, phrase });
    setExecResult(res.executed ? "Cleanup completed safely." : `Blocked: ${String(res.error || "failed")}`);
    await refresh();
  };

  const rssSum = (summary?.memory.processes || []).reduce((acc, p) => acc + p.rssBytes, 0);

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-dot" />
          <h1>SpaceJanitor</h1>
          <span className="engine-pill">{summary?.source || "loading"}</span>
        </div>
        <nav className="nav-tabs" aria-label="Primary Views">
          <button type="button" className={tab === "overview" ? "active" : ""} onClick={() => setTab("overview")}>
            Overview
          </button>
          <button type="button" className={tab === "disk" ? "active" : ""} onClick={() => setTab("disk")}>
            Disk &amp; Orphans
          </button>
          <button type="button" className={tab === "memory" ? "active" : ""} onClick={() => setTab("memory")}>
            Memory &amp; Blockers
          </button>
          <button type="button" className={tab === "mcp" ? "active" : ""} onClick={() => setTab("mcp")}>
            MCP Sprawl
          </button>
        </nav>
        <div className="top-actions">
          <button type="button" className="btn-ghost" onClick={() => void refresh()}>
            Refresh
          </button>
          <button
            type="button"
            className="btn-ghost"
            onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
          >
            {theme === "dark" ? "Light" : "Dark"}
          </button>
        </div>
      </header>

      <main className="main-content">
        {summary && tab === "overview" && (
          <>
            <div className="grid-2">
              <DiskHeroGauge
                freeBytes={summary.disk.freeBytes}
                totalBytes={summary.disk.totalBytes}
                freeGiB={summary.disk.freeGiB}
                status={summary.disk.status}
              />
              <MemoryComparisonCard
                usedBytes={summary.memory.usedBytes}
                totalBytes={summary.memory.totalBytes}
                swapUsedBytes={summary.memory.swapUsedBytes}
                rssSumBytes={rssSum}
                status={summary.memory.status}
              />
            </div>

            <div className="grid-3">
              <div className="card">
                <div className="card-header">
                  <h2>Kernel / VFS Blockers</h2>
                  <span className={`badge badge-${summary.blockers.status.toLowerCase()}`}>
                    {summary.blockers.status}
                  </span>
                </div>
                {summary.blockers.counters.length === 0 ? (
                  <p className="muted">No kernel pressure counters triggered.</p>
                ) : (
                  summary.blockers.counters.map((c) => (
                    <div key={c.name} className="kv-row">
                      <span>{c.name}</span>
                      <strong>
                        {c.current}/{c.max} ({c.percent}%)
                      </strong>
                    </div>
                  ))
                )}
              </div>

              <div className="card">
                <div className="card-header">
                  <h2>MCP Fleet &amp; Orphans</h2>
                  <span className="badge badge-ok">{summary.mcpAudit.totalServers} servers</span>
                </div>
                <div className="kv-row">
                  <span>Duplicates</span>
                  <strong>{summary.mcpAudit.duplicateCount}</strong>
                </div>
                <div className="kv-row">
                  <span>Redacted Secret Risks</span>
                  <strong>{summary.mcpAudit.secretRiskCount}</strong>
                </div>
                <div className="kv-row">
                  <span>Git Worktree Orphans</span>
                  <strong>{summary.orphans.candidates.length}</strong>
                </div>
              </div>

              <div className="card">
                <div className="card-header">
                  <h2>OS Trash</h2>
                  <span className="badge badge-ok">{summary.trash.itemCount} items</span>
                </div>
                <p className="metric-lg">{formatBytes(summary.trash.totalBytes)}</p>
                <p className="muted">Dry-run default. Select targets in Disk &amp; Orphans.</p>
              </div>
            </div>

            <SlmAdvisorDrawer
              config={slmConfig}
              summary={summary}
              candidates={allCandidates.slice(0, 8)}
              onUpdateConfig={async (next) => {
                if (window.spaceJanitor) {
                  const updated = await window.spaceJanitor.updateSlmConfig(next);
                  setSlmConfig(updated);
                }
              }}
              onExplain={async (cands) => {
                if (!window.spaceJanitor) {
                  return { ok: false, reason: "SLM requires Electron desktop host." };
                }
                return window.spaceJanitor.explainWithSlm({
                  summary,
                  candidates: cands,
                  memoryReport: summary.memory,
                });
              }}
            />
          </>
        )}

        {summary && tab === "disk" && (
          <section className="card">
            <div className="card-header">
              <h2>Top Space Consumers &amp; Trash</h2>
              <button
                type="button"
                className="btn-primary"
                disabled={selectedCandidates.length === 0}
                onClick={() => void handleOpenDryRun()}
              >
                Dry-Run Plan ({selectedCandidates.length})
              </button>
            </div>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Select</th>
                  <th>Path</th>
                  <th>Size</th>
                  <th>Protection</th>
                </tr>
              </thead>
              <tbody>
                {allCandidates.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <input
                        type="checkbox"
                        disabled={Boolean(c.protected)}
                        checked={selectedIds.has(c.id)}
                        onChange={() => toggleCandidate(c.id)}
                      />
                    </td>
                    <td className="mono">{c.path}</td>
                    <td>{formatBytes(c.bytes)}</td>
                    <td>
                      {c.protected ? (
                        <span className="badge badge-warn">LOCKED ({c.protectedReason})</span>
                      ) : (
                        <span className="badge badge-ok">Candidate</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        )}

        {summary && tab === "memory" && (
          <section className="card">
            <h2>Processes Sorted by True Memory Footprint</h2>
            <table className="data-table">
              <thead>
                <tr>
                  <th>PID</th>
                  <th>PPID</th>
                  <th>True Footprint</th>
                  <th>ps RSS</th>
                  <th>Command (Redacted)</th>
                </tr>
              </thead>
              <tbody>
                {summary.memory.processes.map((p) => (
                  <tr key={p.pid}>
                    <td className="mono">{p.pid}</td>
                    <td className="mono">
                      {p.ppid}
                      {p.isOrphanPpid1 ? " [ORPHAN]" : ""}
                    </td>
                    <td>{formatBytes(p.trueFootprintBytes)}</td>
                    <td>{formatBytes(p.rssBytes)}</td>
                    <td className="mono">{p.command}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        )}

        {summary && tab === "mcp" && (
          <section className="card">
            <h2>MCP Fleet Sprawl &amp; Secret Audit</h2>
            {summary.mcpAudit.servers.length === 0 ? (
              <p className="muted">No MCP server configs detected in scanned directories.</p>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Server</th>
                    <th>Duplicates</th>
                    <th>Secret Risk</th>
                    <th>Args (Redacted)</th>
                  </tr>
                </thead>
                <tbody>
                  {summary.mcpAudit.servers.map((s, idx) => (
                    <tr key={`${s.name}-${idx}`}>
                      <td>{s.name}</td>
                      <td>x{s.duplicateCount}</td>
                      <td>
                        {s.hasSecretRisk ? (
                          <span className="badge badge-warn">REDACTED SECRET</span>
                        ) : (
                          <span className="badge badge-ok">Clean</span>
                        )}
                      </td>
                      <td className="mono">{s.argsRedacted || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        )}
      </main>

      <RemediationModal
        plan={activePlan}
        onClose={() => setActivePlan(null)}
        onExecute={handleExecute}
        resultMessage={execResult}
      />
    </div>
  );
};
