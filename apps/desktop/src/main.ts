import { app, BrowserWindow, dialog, ipcMain, IpcMainInvokeEvent, Menu, nativeImage, session, Tray } from "electron";
import fs from "node:fs";
import path from "node:path";
import {
  isAuthorizedSenderFrame,
  isSafeNavigationUrl,
  sanitizeIpcParams,
  validateIpcMethod,
  validateTargetPath,
} from "./ipcValidation";
import { RemediationCandidate, RemediationGate } from "./remediationGate";
import { annotateSummary, approvedFromSummary } from "./candidateAnnotations";
import { OrphanScanSetting, setOrphanScanWithConfirmation } from "./orphanSetting";
import { resolveSjBinary, SjBridge } from "./sjBridge";
import { SlmAdvisorService } from "./slmAdvisor";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const core = require("@spacejanitor/core");

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let isQuitting = false;
let lastStatusSummary = "Status: Initializing...";

const bridge = new SjBridge({
  binaryPath: resolveSjBinary({ isPackaged: app.isPackaged }),
});
const orphanScan = new OrphanScanSetting(path.join(app.getPath("userData"), "settings.json"));
const gate = new RemediationGate({ orphanScanEnabled: () => orphanScan.get() });
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
    // Tray refresh deliberately does NOT pass the orphan setting: it never scans orphans (default OFF).
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
  const orphanRoot = method === "orphans" ? result.targetPath : (result.orphans as { targetPath?: unknown } | undefined)?.targetPath;
  if (typeof orphanRoot === "string" && path.isAbsolute(orphanRoot)) gate.setPlanRoot(orphanRoot);
  if (method !== "summary") return;
  // Only what the Rust gate judged selectable can ever be planned (caches never are).
  gate.registerApprovedCandidates(approvedFromSummary(result));
}

function gateRefusalMessage(reason: string): string {
  return (
    `The Rust safety gate (sj) refused or could not run (${reason}). ` +
    "Cleanup is disabled until it is available; read-only views still work."
  );
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
    let result = await bridge.invoke(method, params);
    // Tell the UI which candidates the gate accepts (and why not), so it never offers what plan would refuse.
    if (method === "summary") result = annotateSummary(result, (paths) => core.protectPaths(paths));
    registerApprovedFromReport(method, result);
    // Read-only views always work; the renderer is told whether destructive actions are possible.
    return method === "summary" ? { ...result, remediationGate: bridge.remediationAvailable() } : result;
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
    try {
      return await gate.createDryRunPlan(candidates);
    } catch (err) {
      const reason = (err as { reason?: string })?.reason;
      if (!reason) throw err;
      // sj missing, timed out or unparseable: refuse and say why (no JavaScript fallback exists).
      return {
        schema: "spacejanitor.plan.v1",
        planId: "",
        dryRun: true,
        items: [],
        blockedItems: [],
        totalBytes: 0,
        planSha256: "",
        confirmationPhrase: "",
        createdAtMs: Date.now(),
        expiresAtMs: 0,
        gateError: { reason, message: gateRefusalMessage(reason) },
      };
    }
  });

  ipcMain.handle("sj:execute", async (event, payload: { planSha256?: string; phrase?: string }) => {
    assertAuthorizedSender(event);
    const planSha256 = String(payload?.planSha256 || "");
    const phrase = String(payload?.phrase || "");
    return gate.run({ planSha256, phrase });
  });

  ipcMain.handle("sj:orphan-scan-get", (event) => {
    assertAuthorizedSender(event);
    return { enabled: orphanScan.get(), warning: OrphanScanSetting.WARNING };
  });
  ipcMain.handle("sj:orphan-scan-set", async (event, payload: { enabled?: unknown }) => {
    assertAuthorizedSender(event);
    // Enabling needs a native confirmation owned by the main process; a renderer script cannot supply it.
    const enabled = await setOrphanScanWithConfirmation(orphanScan, payload?.enabled, async (warning) => {
      const win = BrowserWindow.fromWebContents(event.sender);
      const opts = {
        type: "warning" as const,
        buttons: ["Cancel", "Enable experimental scan"],
        defaultId: 0,
        cancelId: 0,
        noLink: true,
        message: "Enable orphan repository scanning?",
        detail: warning,
      };
      const res = win ? await dialog.showMessageBox(win, opts) : await dialog.showMessageBox(opts);
      return res.response === 1;
    });
    return { enabled, warning: OrphanScanSetting.WARNING };
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
