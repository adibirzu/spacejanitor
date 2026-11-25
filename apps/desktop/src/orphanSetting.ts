import fs from "node:fs";
import path from "node:path";

/**
 * Explicit, persisted opt-in for orphan-repo scanning. OFF by default; only a real boolean `true`
 * ever enables it. The renderer cannot set it through the generic invoke path (see ipcValidation).
 */
export class OrphanScanSetting {
  static readonly WARNING =
    "Orphan scanning runs git inside repositories found on disk. It is unreviewed, experimental behavior " +
    "(see Known limitations). Only enable it for repositories you trust.";

  private enabled = false;

  constructor(private readonly file: string | null = null) {
    this.enabled = this.read();
  }

  private read(): boolean {
    if (!this.file) return false;
    try {
      const parsed = JSON.parse(fs.readFileSync(this.file, "utf8"));
      return parsed?.orphanScan === true;
    } catch {
      return false;
    }
  }

  get(): boolean {
    return this.enabled;
  }

  set(value: unknown): boolean {
    this.enabled = value === true;
    if (this.file) {
      try {
        let existing: Record<string, unknown> = {};
        try {
          existing = JSON.parse(fs.readFileSync(this.file, "utf8")) ?? {};
        } catch {
          existing = {};
        }
        fs.mkdirSync(path.dirname(this.file), { recursive: true });
        fs.writeFileSync(this.file, JSON.stringify({ ...existing, orphanScan: this.enabled }, null, 2));
      } catch {
        // persistence is best effort; the in-memory value still applies for this session
      }
    }
    return this.enabled;
  }
}

/**
 * The ONLY way the renderer-facing IPC may change the setting. Turning scanning ON needs a
 * main-process confirmation (a native dialog carrying the warning, Cancel as the default); a call with
 * no confirmation function, a cancelled dialog or a non-boolean value leaves it OFF. Turning it OFF
 * never asks.
 */
export async function setOrphanScanWithConfirmation(
  setting: OrphanScanSetting,
  requested: unknown,
  confirm?: (warning: string) => Promise<boolean>
): Promise<boolean> {
  if (requested !== true) return setting.set(false);
  if (!confirm) return setting.get();
  const ok = await confirm(OrphanScanSetting.WARNING);
  return ok === true ? setting.set(true) : setting.get();
}
