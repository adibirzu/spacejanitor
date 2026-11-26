import { normalizeReportEnvelope } from "./telemetry.mjs";

/**
 * Compact, token-efficient TOON formatter for SpaceJanitor v1 envelopes (ADR-003).
 */
export function formatToon(rawReport) {
  if (!rawReport || typeof rawReport !== "object") return "status: UNKNOWN";
  const report = normalizeReportEnvelope(rawReport);
  const lines = [];
  if (report.schema) lines.push(`schema: ${report.schema}`);
  if (report.status) lines.push(`status: ${report.status}`);
  if (report.source) lines.push(`source: ${report.source}`);

  if (report.schema === "spacejanitor.doctor.v1") {
    lines.push(`host: ${report.platform}/${report.arch} (${report.node})`);
    lines.push(`mem_gib: ${report.freeMemGiB}/${report.totalMemGiB} free | safety: ${report.safetyMode}`);
    lines.push(`ready: ${Boolean(report.ready)}`);
  } else if (report.schema === "spacejanitor.disk.v1" || report.schema === "spacejanitor.storage.v1") {
    lines.push(`target: ${report.targetPath} | free_gib: ${report.freeGiB}`);
    for (const c of (report.topConsumers || []).slice(0, 8)) {
      const mb = (c.bytes / (1024 * 1024)).toFixed(1);
      lines.push(`  - ${c.path} (${mb} MiB)${c.protected ? " [PROTECTED]" : ""}`);
    }
  } else if (report.schema === "spacejanitor.memory.v1") {
    const usedGiB = ((report.usedBytes || 0) / 1024 ** 3).toFixed(2);
    const totalGiB = ((report.totalBytes || 0) / 1024 ** 3).toFixed(2);
    const swapMiB = ((report.swapUsedBytes || 0) / 1024 ** 2).toFixed(1);
    lines.push(`ram_gib: ${usedGiB}/${totalGiB} | swap_mib: ${swapMiB}`);
    for (const p of (report.processes || []).slice(0, 8)) {
      const mib = ((p.trueFootprintBytes || 0) / 1024 ** 2).toFixed(1);
      lines.push(`  - pid=${p.pid} ppid=${p.ppid} ${mib} MiB ${p.command}`);
    }
  } else if (report.schema === "spacejanitor.blockers.v1") {
    for (const c of report.counters || []) {
      lines.push(`  - ${c.name}: ${c.current}/${c.max} (${c.percent}%) [${c.status}]`);
    }
    if (report.systemd) {
      for (const u of report.systemd.systemFailed || []) {
        lines.push(`  - systemd[system]: ${u.unit} (${u.active}/${u.sub})`);
      }
      for (const u of report.systemd.userFailed || []) {
        lines.push(`  - systemd[user]: ${u.unit} (${u.active}/${u.sub})${u.isPodmanHealthcheck ? " [PODMAN_HEALTHCHECK]" : ""}`);
      }
    }
    if ((report.counters || []).length === 0 && !(report.systemd?.systemFailed?.length || report.systemd?.userFailed?.length)) {
      lines.push("  - no_kernel_blockers_detected");
    }
  } else if (report.schema === "spacejanitor.linux_audit.v1") {
    lines.push(`host: ${report.os}/${report.arch} | mounts: ${(report.mounts || []).length} | appimage_mounts: ${(report.appimageMounts || []).length}`);
    const dk = report.docker || {};
    const pm = report.podman || {};
    const dkBuildGiB = ((dk.buildCacheReclaimableBytes ?? dk.df?.buildCacheReclaimableBytes ?? 0) / 1024 ** 3).toFixed(2);
    const dkImgGiB = ((dk.imagesReclaimableBytes ?? dk.df?.imagesReclaimableBytes ?? 0) / 1024 ** 3).toFixed(2);
    lines.push(`docker: exited=${(dk.exitedContainers || []).length} unhealthy=${(dk.unhealthyContainers || []).length} dangling_imgs=${(dk.danglingImages || []).length} img_reclaim_gib=${dkImgGiB} docker_build_cache_gib=${dkBuildGiB}`);
    lines.push(`podman: exited=${(pm.exitedContainers || []).length} unhealthy=${(pm.unhealthyContainers || []).length}`);
    const jMiB = ((report.journald?.bytes || 0) / 1024 ** 2).toFixed(1);
    const aptMiB = ((report.packageCaches?.aptArchivesBytes || 0) / 1024 ** 2).toFixed(1);
    lines.push(`journald_mib: ${jMiB} | apt_archives_mib: ${aptMiB} | stale_tmp: ${(report.staleTmpEntries || []).length}`);
    lines.push(`manual_review: model_caches=${(report.modelCaches || []).length} old_backups=${(report.oldBackups || []).length}`);
  } else if (report.schema === "spacejanitor.mcp_audit.v1") {
    lines.push(`servers: ${report.totalServers} | duplicates: ${report.duplicateCount} | secret_risks: ${report.secretRiskCount}`);
    for (const s of (report.servers || []).slice(0, 10)) {
      lines.push(`  - ${s.name} (x${s.duplicateCount})${s.hasSecretRisk ? " [SECRET_RISK]" : ""}`);
    }
  } else if (report.schema === "spacejanitor.orphans.v1") {
    if (report.scanned === false) {
      // never a numeric 0: nothing was looked at
      lines.push(`target: ${report.targetPath} | orphans: not scanned (disabled by default)`);
      lines.push("  - orphan scanning runs git inside repositories found on disk; opt in with --include-orphans (experimental)");
      return lines.join("\n");
    }
    lines.push(`target: ${report.targetPath} | candidates: ${(report.candidates || []).length}`);
    for (const c of (report.candidates || []).slice(0, 10)) {
      lines.push(`  - ${c.path} [clean=${c.clean} pushed=${!c.hasUnpushed} safe=${c.safeToPrune}]`);
    }
  } else if (report.schema === "spacejanitor.trash.v1") {
    const mib = ((report.totalBytes || 0) / 1024 ** 2).toFixed(1);
    lines.push(`items: ${report.itemCount} | total_mib: ${mib}`);
  } else if (report.schema === "spacejanitor.plan.v1") {
    const mib = ((report.totalBytes || 0) / 1024 ** 2).toFixed(1);
    lines.push(`dry_run: ${report.dryRun} | items: ${report.items.length} | reclaim_mib: ${mib}`);
    lines.push(`plan_sha256: ${report.planSha256}`);
    lines.push(`confirm_phrase: ${report.confirmationPhrase}`);
  } else if (report.schema === "spacejanitor.reap.v1") {
    lines.push(`executed: ${Boolean(report.executed)}${report.error ? ` | error: ${report.error}` : ""}`);
  } else if (report.schema === "spacejanitor.summary.v1") {
    lines.push(`disk_free_gib: ${report.disk?.freeGiB} [${report.disk?.status}]`);
    lines.push(`memory: [${report.memory?.status}] | blockers: [${report.blockers?.status}]`);
    const orphanText =
      report.orphans?.scanned === false
        ? "not scanned (disabled by default)"
        : String(report.orphans?.candidates?.length ?? 0);
    lines.push(`orphans: ${orphanText} | mcp_servers: ${report.mcpAudit?.totalServers ?? 0}`);
  }

  return lines.join("\n");
}
