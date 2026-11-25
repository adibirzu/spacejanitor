import { contextBridge, ipcRenderer } from "electron";

export interface SpaceJanitorApi {
  getSummary: (targetPath?: string) => Promise<Record<string, unknown>>;
  getDoctor: () => Promise<Record<string, unknown>>;
  getDisk: (targetPath?: string) => Promise<Record<string, unknown>>;
  getMemory: () => Promise<Record<string, unknown>>;
  getBlockers: () => Promise<Record<string, unknown>>;
  getOrphans: (targetPath?: string) => Promise<Record<string, unknown>>;
  getTrash: () => Promise<Record<string, unknown>>;
  getMcpAudit: () => Promise<Record<string, unknown>>;
  planRemediation: (candidates: Array<Record<string, unknown>>) => Promise<Record<string, unknown>>;
  executeRemediation: (payload: { planSha256: string; phrase: string }) => Promise<Record<string, unknown>>;
  getOrphanScan: () => Promise<{ enabled: boolean; warning: string }>;
  setOrphanScan: (enabled: boolean) => Promise<{ enabled: boolean; warning: string }>;
  getSlmConfig: () => Promise<Record<string, unknown>>;
  updateSlmConfig: (config: Record<string, unknown>) => Promise<Record<string, unknown>>;
  explainWithSlm: (payload: Record<string, unknown>) => Promise<Record<string, unknown>>;
}

const api: SpaceJanitorApi = {
  getSummary: (targetPath) => ipcRenderer.invoke("sj:invoke", { method: "summary", params: { targetPath } }),
  getDoctor: () => ipcRenderer.invoke("sj:invoke", { method: "doctor", params: {} }),
  getDisk: (targetPath) => ipcRenderer.invoke("sj:invoke", { method: "disk", params: { targetPath } }),
  getMemory: () => ipcRenderer.invoke("sj:invoke", { method: "memory", params: {} }),
  getBlockers: () => ipcRenderer.invoke("sj:invoke", { method: "blockers", params: {} }),
  getOrphans: (targetPath) => ipcRenderer.invoke("sj:invoke", { method: "orphans", params: { targetPath } }),
  getTrash: () => ipcRenderer.invoke("sj:invoke", { method: "trash", params: {} }),
  getMcpAudit: () => ipcRenderer.invoke("sj:invoke", { method: "mcp-audit", params: {} }),
  planRemediation: (candidates) => ipcRenderer.invoke("sj:plan", { candidates }),
  executeRemediation: (payload) => ipcRenderer.invoke("sj:execute", payload),
  getOrphanScan: () => ipcRenderer.invoke("sj:orphan-scan-get"),
  setOrphanScan: (enabled) => ipcRenderer.invoke("sj:orphan-scan-set", { enabled }),
  getSlmConfig: () => ipcRenderer.invoke("sj:slm-get-config"),
  updateSlmConfig: (config) => ipcRenderer.invoke("sj:slm-update-config", config),
  explainWithSlm: (payload) => ipcRenderer.invoke("sj:slm-explain", payload),
};

contextBridge.exposeInMainWorld("spaceJanitor", api);
