import { app, BrowserWindow, ipcMain, IpcMainInvokeEvent, Menu, nativeImage, session, shell, Tray } from "electron";
import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import {
  isAuthorizedSenderFrame,
  isSafeNavigationUrl,
  sanitizeIpcParams,
  validateIpcMethod,
  validateTargetPath,
} from "./ipcValidation";
import { RemediationCandidate, RemediationGate } from "./remediationGate";
import { executePlanItems } from "./executor";
import { removeWorktreeSafely } from "./worktreeGuard";
import { OrphanScanSetting } from "./orphanSetting";
import { resolveSjBinary, SjBridge } from "./sjBridge";
import { SlmAdvisorService } from "./slmAdvisor";

const execFileAsync = promisify(execFile);

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let isQuitting = false;
let lastStatusSummary = "Status: Initializing...";

const bridge = new SjBridge({
  binaryPath: resolveSjBinary({ isPackaged: app.isPackaged }),
});
const gate = new RemediationGate();
const orphanScan = new OrphanScanSetting(path.join(app.getPath("userData"), "settings.json"));
const slmAdvisor = new SlmAdvisorService();

function resolveUiEntry(): { devUrl?: string; indexPath?: string } {
  if (!app.isPackaged) {
    const devUrl = process.env.SPACEJANITOR_UI_URL;
    if (devUrl && isSafeNavigationUrl(devUrl)) {
      return { devUrl };
    }
  }
  const prodIndex = path.resolve(__dirname, "../../ui/dist/index.html");
  if (fs.existsSync(prodIndex)) {
    return { indexPath: prodIndex };
  }
  return { indexPath: path.resolve(__dirname, "../ui/dist/index.html") };
}

function createMainWindow(): BrowserWindow {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.show();
    mainWindow.focus();
    return mainWindow;
  }

  const win = new BrowserWindow({
    width: 1180,
    height: 780,
    minWidth: 920,
    minHeight: 620,
    title: "SpaceJanitor",
    backgroundColor: "#0b1120",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      preload: path.join(__dirname, "preload.js"),
    },
  });

  const entry = resolveUiEntry();
  win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  win.webContents.on("will-navigate", (event, url) => {
    if (!isAuthorizedSenderFrame(url, entry)) {
      event.preventDefault();
    }
  });

  // Hide to tray & destroy BrowserWindow renderer on close to keep idle RAM minimal (ADR-001)
  win.on("close", (event) => {
    if (!isQuitting) {
      event.preventDefault();
      win.hide();
      win.destroy();
      mainWindow = null;
    }
  });

  if (entry.devUrl) {
    void win.loadURL(entry.devUrl);
  } else if (entry.indexPath) {
    void win.loadFile(entry.indexPath);
  }

  mainWindow = win;
  return win;
}

function refreshTrayMenu(): void {
  if (!tray) return;
  const menu = Menu.buildFromTemplate([
    { label: lastStatusSummary, enabled: false },
    { type: "separator" },
    {
      label: "Open Dashboard",
      click: () => {
        createMainWindow();
      },
    },
    {
      label: "Run Read-Only Audit",
      click: () => {
        void runQuickAudit();
      },
    },
    { type: "separator" },
    {
      label: "Quit SpaceJanitor",
      click: () => {
        isQuitting = true;
        bridge.dispose();
        app.quit();
      },
    },
  ]);
  tray.setContextMenu(menu);
}

async function runQuickAudit(): Promise<void> {
  try {
    const summary = await bridge.invoke("summary", {});
    const status = String(summary.status || "OK");
    const disk = summary.disk as { freeGiB?: number } | undefined;
    lastStatusSummary = `Status: ${status} | Free: ${disk?.freeGiB ?? "?"} GiB`;
    refreshTrayMenu();
  } catch {
    lastStatusSummary = "Status: Audit error";
    refreshTrayMenu();
  }
}

function setupTray(): void {
  const iconName = process.platform === "darwin" ? "trayTemplate.png" : "icon.png";
  const iconPath = path.resolve(__dirname, "../build", iconName);
  const img = fs.existsSync(iconPath)
    ? nativeImage.createFromPath(iconPath)
    : nativeImage.createEmpty();
  if (process.platform === "darwin") {
    img.setTemplateImage(true);
  }
  tray = new Tray(img);
  tray.setToolTip("SpaceJanitor — Workstation Telemetry");
  tray.on("click", () => {
    createMainWindow();
  });
  refreshTrayMenu();
}

function assertAuthorizedSender(event: IpcMainInvokeEvent): void {
  const entry = resolveUiEntry();
  const frameUrl = event.senderFrame?.url;
  if (!isAuthorizedSenderFrame(frameUrl, entry)) {
    throw new Error("Unauthorized IPC sender frame");
  }
}

function registerApprovedFromReport(method: string, result: Record<string, unknown>): void {
  if (method !== "summary") return;
  const trashCands = Array.isArray((result.trash as { candidates?: RemediationCandidate[] })?.candidates)
    ? ((result.trash as { candidates: RemediationCandidate[] }).candidates)
    : [];
  const cacheCands = Array.isArray(result.cleanableCaches)
    ? (result.cleanableCaches as RemediationCandidate[])
    : [];
  const orphanCands = Array.isArray((result.orphans as { candidates?: Array<RemediationCandidate & { safeToPrune?: boolean }> })?.candidates)
    ? (result.orphans as { candidates: Array<RemediationCandidate & { safeToPrune?: boolean }> }).candidates.filter(
        (c) => c.safeToPrune
      )
    : [];
  gate.registerApprovedCandidates([...trashCands, ...cacheCands, ...orphanCands]);
}

function isInsideOsTrash(targetPath: string): boolean {
  const home = os.homedir();
  const resolved = path.resolve(targetPath);
  const trashRoots = [
    path.join(home, ".Trash"),
    path.join(home, ".local", "share", "Trash", "files"),
  ];
  return trashRoots.some((r) => resolved === r || resolved.startsWith(`${r}${path.sep}`));
}

function registerIpcHandlers(): void {
  ipcMain.handle("sj:invoke", async (event, payload: { method?: string; params?: Record<string, unknown> }) => {
    assertAuthorizedSender(event);
    const method = String(payload?.method || "");
    if (!validateIpcMethod(method)) {
      throw new Error(`Disallowed IPC method: ${method}`);
    }
    const params = sanitizeIpcParams(payload?.params);
    if (params.targetPath !== undefined && params.targetPath !== null && params.targetPath !== "") {
      const pathCheck = validateTargetPath(params.targetPath);
      if (!pathCheck.valid) {
        throw new Error(`Invalid targetPath: ${pathCheck.reason}`);
      }
      params.targetPath = pathCheck.value;
    } else {
      delete params.targetPath;
    }
    // Only the main process decides whether git may run inside repositories found on disk (default OFF).
    if (method === "orphans" || method === "summary") params.includeOrphans = orphanScan.get();
    const result = await bridge.invoke(method, params);
    registerApprovedFromReport(method, result);
    return result;
  });

  ipcMain.handle("sj:plan", async (event, payload: { candidates?: RemediationCandidate[] }) => {
    assertAuthorizedSender(event);
    const candidates = Array.isArray(payload?.candidates) ? payload.candidates : [];
    for (const c of candidates) {
      const check = validateTargetPath(c?.path);
      if (!check.valid) {
        throw new Error(`Invalid candidate path: ${check.reason}`);
      }
    }
    return gate.createDryRunPlan(candidates);
  });

  ipcMain.handle("sj:execute", async (event, payload: { planSha256?: string; phrase?: string }) => {
    assertAuthorizedSender(event);
    const planSha256 = String(payload?.planSha256 || "");
    const phrase = String(payload?.phrase || "");
    const auth = gate.authorizeExecute({ planSha256, phrase });
    if (!auth.allowed || !auth.plan) {
      return {
        schema: "spacejanitor.reap.v1",
        executed: false,
        error: auth.reason,
      };
    }

    return gate.withMutex(() =>
      executePlanItems(auth.plan!, auth.identities || {}, {
        homeDir: os.homedir(),
        isInsideOsTrash,
        trashItem: (p) => shell.trashItem(p),
        removeWorktree: (p) => removeWorktreeSafely(p, { includeOrphans: orphanScan.get() }),
        orphanScanEnabled: () => orphanScan.get(),
      })
    );
  });

  ipcMain.handle("sj:orphan-scan-get", (event) => {
    assertAuthorizedSender(event);
    return { enabled: orphanScan.get(), warning: OrphanScanSetting.WARNING };
  });
  ipcMain.handle("sj:orphan-scan-set", (event, payload: { enabled?: unknown }) => {
    assertAuthorizedSender(event);
    return { enabled: orphanScan.set(payload?.enabled === true), warning: OrphanScanSetting.WARNING };
  });
  ipcMain.handle("sj:slm-get-config", (event) => {
    assertAuthorizedSender(event);
    return slmAdvisor.getConfig();
  });
  ipcMain.handle("sj:slm-update-config", (event, config) => {
    assertAuthorizedSender(event);
    return slmAdvisor.updateConfig(config || {});
  });
  ipcMain.handle("sj:slm-explain", (event, payload) => {
    assertAuthorizedSender(event);
    return slmAdvisor.explainPlan({
      summary: payload?.summary || {},
      candidates: Array.isArray(payload?.candidates) ? payload.candidates : [],
      memoryReport: payload?.memoryReport,
    });
  });
}

app.whenReady().then(() => {
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        "Content-Security-Policy": [
          "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        ],
      },
    });
  });

  registerIpcHandlers();
  setupTray();
  createMainWindow();
  void runQuickAudit();

  app.on("activate", () => {
    createMainWindow();
  });
});

app.on("window-all-closed", () => {
  // Stay alive in tray until user explicitly clicks Quit SpaceJanitor
});

app.on("before-quit", () => {
  isQuitting = true;
  bridge.dispose();
});
