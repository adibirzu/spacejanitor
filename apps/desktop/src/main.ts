import { app, BrowserWindow, ipcMain, Menu, nativeImage, session, Tray } from "electron";
import fs from "node:fs";
import path from "node:path";
import { isSafeNavigationUrl, validateIpcMethod, validateTargetPath } from "./ipcValidation";
import { RemediationCandidate, RemediationGate } from "./remediationGate";
import { SjBridge } from "./sjBridge";
import { SlmAdvisorService } from "./slmAdvisor";

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let isQuitting = false;
let lastStatusSummary = "Status: Initializing...";

const bridge = new SjBridge();
const gate = new RemediationGate();
const slmAdvisor = new SlmAdvisorService();

function resolveUiEntry(): { devUrl?: string; indexPath?: string } {
  const devUrl = process.env.SPACEJANITOR_UI_URL;
  if (devUrl && isSafeNavigationUrl(devUrl)) {
    return { devUrl };
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

  win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  win.webContents.on("will-navigate", (event, url) => {
    if (!isSafeNavigationUrl(url)) {
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

  const entry = resolveUiEntry();
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

function registerIpcHandlers(): void {
  ipcMain.handle("sj:invoke", async (_event, payload: { method?: string; params?: Record<string, unknown> }) => {
    const method = String(payload?.method || "");
    if (!validateIpcMethod(method)) {
      throw new Error(`Disallowed IPC method: ${method}`);
    }
    const params = { ...(payload?.params || {}) };
    if (params.targetPath !== undefined && params.targetPath !== null && params.targetPath !== "") {
      const pathCheck = validateTargetPath(params.targetPath);
      if (!pathCheck.valid) {
        throw new Error(`Invalid targetPath: ${pathCheck.reason}`);
      }
      params.targetPath = pathCheck.value;
    } else {
      delete params.targetPath;
    }
    return bridge.invoke(method, params);
  });

  ipcMain.handle("sj:plan", async (_event, payload: { candidates?: RemediationCandidate[] }) => {
    const candidates = Array.isArray(payload?.candidates) ? payload.candidates : [];
    for (const c of candidates) {
      const check = validateTargetPath(c?.path);
      if (!check.valid) {
        throw new Error(`Invalid candidate path: ${check.reason}`);
      }
    }
    return gate.createDryRunPlan(candidates);
  });

  ipcMain.handle("sj:execute", async (_event, payload: { planSha256?: string; phrase?: string }) => {
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

    return gate.withMutex(async () => {
      // Safe execution: remove only validated non-protected items via fs.rmSync
      const removed: string[] = [];
      const failed: Array<{ path: string; error: string }> = [];
      for (const item of auth.plan!.items) {
        try {
          if (fs.existsSync(item.path)) {
            fs.rmSync(item.path, { recursive: item.kind === "dir", force: false });
          }
          removed.push(item.path);
        } catch (err) {
          failed.push({ path: item.path, error: err instanceof Error ? err.message : "rm_failed" });
        }
      }
      return {
        schema: "spacejanitor.reap.v1",
        executed: true,
        planSha256,
        removed,
        failed,
      };
    });
  });

  ipcMain.handle("sj:slm-get-config", () => slmAdvisor.getConfig());
  ipcMain.handle("sj:slm-update-config", (_event, config) => slmAdvisor.updateConfig(config || {}));
  ipcMain.handle("sj:slm-explain", (_event, payload) =>
    slmAdvisor.explainPlan({
      summary: payload?.summary || {},
      candidates: Array.isArray(payload?.candidates) ? payload.candidates : [],
      memoryReport: payload?.memoryReport,
    })
  );
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
