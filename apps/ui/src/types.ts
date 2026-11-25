export interface DiskConsumer {
  id: string;
  path: string;
  bytes: number;
  kind: "file" | "dir" | "git-worktree";
  protected?: boolean;
  protectedReason?: string;
}

export interface ProcessEntry {
  pid: number;
  ppid: number;
  rssBytes: number;
  trueFootprintBytes: number;
  command: string;
  isOrphanPpid1?: boolean;
}

export interface BlockerCounter {
  name: string;
  current: number;
  max: number;
  percent: number;
  status: "OK" | "WARN" | "CRITICAL";
}

export interface McpServerEntry {
  name: string;
  command: string;
  argsRedacted: string;
  duplicateCount: number;
  hasSecretRisk: boolean;
  sourceFile: string;
}

export interface OrphanCandidate {
  id: string;
  path: string;
  kind: string;
  clean: boolean;
  hasRemote: boolean;
  hasUnpushed: boolean;
  safeToPrune: boolean;
}

export interface SummaryReport {
  schema: string;
  source?: string;
  status: string;
  disk: {
    status: string;
    totalBytes: number;
    freeBytes: number;
    freeGiB: number;
    topConsumers: DiskConsumer[];
  };
  memory: {
    status: string;
    totalBytes: number;
    freeBytes: number;
    usedBytes: number;
    swapUsedBytes: number;
    processes: ProcessEntry[];
  };
  blockers: {
    status: "OK" | "WARN" | "CRITICAL";
    counters: BlockerCounter[];
  };
  orphans: {
    /** false = orphan scanning is OFF (default): the list below is NOT "no orphans", it was never looked at */
    scanned?: boolean;
    notScannedReason?: string;
    message?: string;
    candidates: OrphanCandidate[];
  };
  trash: {
    totalBytes: number;
    itemCount: number;
    candidates: DiskConsumer[];
  };
  mcpAudit: {
    totalServers: number;
    duplicateCount: number;
    secretRiskCount: number;
    servers: McpServerEntry[];
  };
  cleanableCaches?: DiskConsumer[];
  remediationGate?: { available: boolean; reason: string };
}

export interface RemediationPlan {
  schema: string;
  planId?: string;
  dryRun: boolean;
  items: DiskConsumer[];
  blockedItems: Array<{ id: string; path: string; bytes: number; reason: string }>;
  totalBytes: number;
  planSha256: string;
  confirmationPhrase: string;
  expiresAtMs: number;
  gateError?: { reason: string; message: string };
}

export interface SlmConfig {
  enabled: boolean;
  url: string;
  allowLan: boolean;
  model: string;
}

export interface SpaceJanitorBridge {
  getSummary: (targetPath?: string) => Promise<SummaryReport>;
  planRemediation: (candidates: DiskConsumer[]) => Promise<RemediationPlan>;
  executeRemediation: (payload: { planSha256: string; phrase: string }) => Promise<Record<string, unknown>>;
  getOrphanScan: () => Promise<{ enabled: boolean; warning: string }>;
  setOrphanScan: (enabled: boolean) => Promise<{ enabled: boolean; warning: string }>;
  getSlmConfig: () => Promise<SlmConfig>;
  updateSlmConfig: (config: Partial<SlmConfig>) => Promise<SlmConfig>;
  explainWithSlm: (payload: {
    summary: SummaryReport;
    candidates: DiskConsumer[];
    memoryReport?: SummaryReport["memory"];
  }) => Promise<{ ok: boolean; reason?: string; explanation?: string; proposals?: Array<Record<string, unknown>> }>;
}

declare global {
  interface Window {
    spaceJanitor?: SpaceJanitorBridge;
  }
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const idx = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const val = bytes / 1024 ** idx;
  return `${val.toFixed(idx === 0 ? 0 : 1)} ${units[idx]}`;
}
