/**
 * Compact, token-efficient TOON formatter for SpaceJanitor v1 envelopes (ADR-003).
 */
export function formatToon(report) {
  if (!report || typeof report !== "object") return "status: UNKNOWN";
  const lines = [];
  if (report.schema) lines.push(`schema: ${report.schema}`);
  if (report.status) lines.push(`status: ${report.status}`);
  if (report.source) lines.push(`source: ${report.source}`);

  if (report.schema === "spacejanitor.doctor.v1") {
    lines.push(`host: ${report.platform}/${report.arch} (node ${report.node})`);
    lines.push(`mem_gib: ${report.freeMemGiB}/${report.totalMemGiB} free | safety: ${report.safetyMode}`);
    lines.push(`ready: ${report.ready}`);
  } else if (report.schema === "spacejanitor.disk.v1") {
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
    if ((report.counters || []).length === 0) lines.push("  - no_kernel_blockers_detected");
  } else if (report.schema === "spacejanitor.mcp_audit.v1") {
    lines.push(`servers: ${report.totalServers} | duplicates: ${report.duplicateCount} | secret_risks: ${report.secretRiskCount}`);
    for (const s of (report.servers || []).slice(0, 10)) {
      lines.push(`  - ${s.name} (x${s.duplicateCount})${s.hasSecretRisk ? " [SECRET_RISK]" : ""}`);
    }
  } else if (report.schema === "spacejanitor.orphans.v1") {
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
  } else if (report.schema === "spacejanitor.summary.v1") {
    lines.push(`disk_free_gib: ${report.disk?.freeGiB} [${report.disk?.status}]`);
    lines.push(`memory: [${report.memory?.status}] | blockers: [${report.blockers?.status}]`);
    lines.push(`orphans: ${report.orphans?.candidates?.length ?? 0} | mcp_servers: ${report.mcpAudit?.totalServers ?? 0}`);
  }

  return lines.join("\n");
}
