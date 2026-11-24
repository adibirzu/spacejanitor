export type PluginCapability = "rule-pack" | "collector" | "widget" | "exporter";

export interface StorageOrProcessRule {
  id: string;
  description?: string;
  tier?: 1 | 2;
  paths?: string[];
  processPattern?: string;
}

export interface WidgetDescriptor {
  id: string;
  title: string;
  kind: "kpi" | "bar-breakdown" | "alert-list" | "dry-run-action";
  dataSource: string;
}

export interface CollectorDescriptor {
  id: string;
  schema: string;
  collect: () => Promise<Record<string, unknown>>;
}

export interface ExporterDescriptor {
  id: string;
  format: string;
  exportSnapshot: (snapshot: Record<string, unknown>) => Promise<void>;
}

export interface SpaceJanitorPlugin {
  id: string;
  version: string;
  apiVersion: "1";
  capabilities: PluginCapability[];
  rules?: StorageOrProcessRule[];
  collectors?: CollectorDescriptor[];
  widgets?: WidgetDescriptor[];
  exporters?: ExporterDescriptor[];
}

export function definePlugin(manifest: SpaceJanitorPlugin): Readonly<SpaceJanitorPlugin>;

export function validatePluginRules(
  plugin: SpaceJanitorPlugin,
  options?: { homeDir?: string; exactPaths?: string[]; globPatterns?: string[] }
): {
  allowedRules: StorageOrProcessRule[];
  rejectedRules: Array<{ ruleId: string; reason: string }>;
};
