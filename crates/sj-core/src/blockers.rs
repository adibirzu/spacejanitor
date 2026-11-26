#[cfg(target_os = "linux")]
use crate::linux::collect_systemd_audit;
use crate::linux::SystemdAudit;
use crate::{SjError, SCHEMA_BLOCKERS_V1};
use serde::Serialize;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct BlockerMetrics {
    pub vnodes_used: Option<u64>,
    pub vnodes_max: Option<u64>,
    pub files_used: Option<u64>,
    pub files_max: Option<u64>,
    pub uninterruptible_procs: Option<u64>,
    pub fseventsd_rss_bytes: Option<u64>,
    pub inotify_watches_used: Option<u64>,
    pub inotify_watches_max: Option<u64>,
    pub open_handles: Option<u64>,
    pub commit_ratio_pct: Option<f64>,
    pub hung_procs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockerItem {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BlockersReport {
    pub schema: String,
    pub os: String,
    pub status: String,
    pub metrics: BlockerMetrics,
    pub blockers: Vec<BlockerItem>,
    pub warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub systemd: Option<SystemdAudit>,
}

fn eval_ratio_blocker(
    blockers: &mut Vec<BlockerItem>,
    id: &str,
    title: &str,
    used: u64,
    max: u64,
    recommendation: &str,
) {
    if max == 0 {
        return;
    }
    let pct = (used as f64 / max as f64) * 100.0;
    let severity = if pct >= 90.0 {
        Some("CRITICAL")
    } else if pct >= 75.0 {
        Some("WARN")
    } else {
        None
    };
    if let Some(sev) = severity {
        blockers.push(BlockerItem {
            id: id.to_string(),
            severity: sev.to_string(),
            title: title.to_string(),
            detail: format!("{used}/{max} ({pct:.1}%)"),
            recommendation: recommendation.to_string(),
        });
    }
}

fn overall_status(blockers: &[BlockerItem]) -> String {
    if blockers.iter().any(|b| b.severity == "CRITICAL") {
        "CRITICAL".to_string()
    } else if blockers.iter().any(|b| b.severity == "WARN") {
        "WARN".to_string()
    } else {
        "OK".to_string()
    }
}

pub fn evaluate_macos_blockers(
    vnodes_used: Option<u64>,
    vnodes_max: Option<u64>,
    files_used: Option<u64>,
    files_max: Option<u64>,
    uninterruptible_procs: Option<u64>,
    fseventsd_rss_bytes: Option<u64>,
    warnings: Vec<String>,
) -> BlockersReport {
    let mut blockers = Vec::new();
    if let (Some(u), Some(m)) = (vnodes_used, vnodes_max) {
        eval_ratio_blocker(
            &mut blockers,
            "macos-vnode-pressure",
            "Kernel vnode table saturation",
            u,
            m,
            "Close idle monorepo watchers or increase kern.maxvnodes",
        );
    }
    if let (Some(u), Some(m)) = (files_used, files_max) {
        eval_ratio_blocker(
            &mut blockers,
            "macos-open-files-pressure",
            "System open file descriptor pressure",
            u,
            m,
            "Close idle file-heavy processes or raise kern.maxfiles",
        );
    }
    if let Some(u_procs) = uninterruptible_procs {
        if u_procs >= 5 {
            blockers.push(BlockerItem {
                id: "macos-uninterruptible-waits".to_string(),
                severity: "CRITICAL".to_string(),
                title: "Multiple uninterruptible (U-state) processes".to_string(),
                detail: format!("{u_procs} processes stuck in uninterruptible disk/VFS wait"),
                recommendation:
                    "Check stalled network mounts, Spotlight indexing, or disk I/O contention"
                        .to_string(),
            });
        } else if u_procs >= 1 {
            blockers.push(BlockerItem {
                id: "macos-uninterruptible-waits".to_string(),
                severity: "WARN".to_string(),
                title: "Uninterruptible (U-state) process detected".to_string(),
                detail: format!("{u_procs} process(es) in uninterruptible wait"),
                recommendation: "Monitor disk/VFS I/O contention".to_string(),
            });
        }
    }
    if let Some(rss) = fseventsd_rss_bytes {
        let mib = rss / (1024 * 1024);
        if mib >= 512 {
            blockers.push(BlockerItem {
                id: "macos-fseventsd-bloat".to_string(),
                severity: "CRITICAL".to_string(),
                title: "fseventsd memory footprint critical".to_string(),
                detail: format!("fseventsd RSS is {mib} MiB"),
                recommendation:
                    "Exclude build/cache/node_modules directories from Spotlight and file watchers"
                        .to_string(),
            });
        } else if mib >= 256 {
            blockers.push(BlockerItem {
                id: "macos-fseventsd-bloat".to_string(),
                severity: "WARN".to_string(),
                title: "fseventsd memory footprint elevated".to_string(),
                detail: format!("fseventsd RSS is {mib} MiB"),
                recommendation: "Exclude high-churn directories from Spotlight indexing"
                    .to_string(),
            });
        }
    }

    let status = overall_status(&blockers);
    BlockersReport {
        schema: SCHEMA_BLOCKERS_V1.to_string(),
        os: "macos".to_string(),
        status,
        metrics: BlockerMetrics {
            vnodes_used,
            vnodes_max,
            files_used,
            files_max,
            uninterruptible_procs,
            fseventsd_rss_bytes,
            ..Default::default()
        },
        blockers,
        warnings,
        systemd: None,
    }
}

pub fn parse_linux_file_nr(raw: &str) -> Option<(u64, u64)> {
    let mut nums = raw.split_whitespace().filter_map(|s| s.parse::<u64>().ok());
    let allocated = nums.next()?;
    let _unused = nums.next()?;
    let max = nums.next()?;
    Some((allocated, max))
}

pub fn evaluate_linux_blockers(
    files_used: Option<u64>,
    files_max: Option<u64>,
    d_state_procs: Option<u64>,
    inotify_watches_used: Option<u64>,
    inotify_watches_max: Option<u64>,
    warnings: Vec<String>,
) -> BlockersReport {
    let mut blockers = Vec::new();
    if let (Some(u), Some(m)) = (files_used, files_max) {
        eval_ratio_blocker(
            &mut blockers,
            "linux-file-nr-pressure",
            "Kernel file-nr descriptor pressure",
            u,
            m,
            "Raise fs.file-max or close file-descriptor-leaking processes",
        );
    }
    if let (Some(u), Some(m)) = (inotify_watches_used, inotify_watches_max) {
        eval_ratio_blocker(
            &mut blockers,
            "linux-inotify-pressure",
            "inotify user watch saturation",
            u,
            m,
            "Increase fs.inotify.max_user_watches or exclude build trees from watchers",
        );
    }
    if let Some(d_procs) = d_state_procs {
        if d_procs >= 5 {
            blockers.push(BlockerItem {
                id: "linux-d-state-waits".to_string(),
                severity: "CRITICAL".to_string(),
                title: "Multiple uninterruptible (D-state) processes".to_string(),
                detail: format!("{d_procs} processes in D-state"),
                recommendation: "Check stalled NFS/FUSE mounts or saturated block storage"
                    .to_string(),
            });
        } else if d_procs >= 1 {
            blockers.push(BlockerItem {
                id: "linux-d-state-waits".to_string(),
                severity: "WARN".to_string(),
                title: "Uninterruptible (D-state) process detected".to_string(),
                detail: format!("{d_procs} process(es) in D-state"),
                recommendation: "Inspect /proc/<pid>/wchan for I/O wait cause".to_string(),
            });
        }
    }

    let status = overall_status(&blockers);
    BlockersReport {
        schema: SCHEMA_BLOCKERS_V1.to_string(),
        os: "linux".to_string(),
        status,
        metrics: BlockerMetrics {
            files_used,
            files_max,
            uninterruptible_procs: d_state_procs,
            inotify_watches_used,
            inotify_watches_max,
            ..Default::default()
        },
        blockers,
        warnings,
        systemd: None,
    }
}

pub fn evaluate_windows_blockers(
    open_handles: Option<u64>,
    commit_ratio_pct: Option<f64>,
    hung_procs: Option<u64>,
    warnings: Vec<String>,
) -> BlockersReport {
    let mut blockers = Vec::new();
    if let Some(ratio) = commit_ratio_pct {
        if ratio >= 90.0 {
            blockers.push(BlockerItem {
                id: "windows-commit-saturation".to_string(),
                severity: "CRITICAL".to_string(),
                title: "Virtual memory commit limit near exhaustion".to_string(),
                detail: format!("Commit ratio at {ratio:.1}%"),
                recommendation: "Close high-commit processes or expand pagefile limit".to_string(),
            });
        } else if ratio >= 75.0 {
            blockers.push(BlockerItem {
                id: "windows-commit-saturation".to_string(),
                severity: "WARN".to_string(),
                title: "Elevated virtual memory commit ratio".to_string(),
                detail: format!("Commit ratio at {ratio:.1}%"),
                recommendation: "Monitor memory-heavy workloads".to_string(),
            });
        }
    }
    if let Some(handles) = open_handles {
        if handles >= 250_000 {
            blockers.push(BlockerItem {
                id: "windows-handle-pressure".to_string(),
                severity: "CRITICAL".to_string(),
                title: "System open handle count critical".to_string(),
                detail: format!("{handles} total open handles"),
                recommendation: "Identify handle-leaking processes and restart them".to_string(),
            });
        } else if handles >= 150_000 {
            blockers.push(BlockerItem {
                id: "windows-handle-pressure".to_string(),
                severity: "WARN".to_string(),
                title: "Elevated open handle count".to_string(),
                detail: format!("{handles} total open handles"),
                recommendation: "Inspect top handle-holding processes".to_string(),
            });
        }
    }
    if let Some(hung) = hung_procs {
        if hung >= 3 {
            blockers.push(BlockerItem {
                id: "windows-hung-processes".to_string(),
                severity: "CRITICAL".to_string(),
                title: "Multiple unresponsive processes".to_string(),
                detail: format!("{hung} unresponsive processes"),
                recommendation: "Inspect hung GUI/agent processes".to_string(),
            });
        } else if hung >= 1 {
            blockers.push(BlockerItem {
                id: "windows-hung-processes".to_string(),
                severity: "WARN".to_string(),
                title: "Unresponsive process detected".to_string(),
                detail: format!("{hung} unresponsive process(es)"),
                recommendation: "Inspect unresponsive process".to_string(),
            });
        }
    }

    let status = overall_status(&blockers);
    BlockersReport {
        schema: SCHEMA_BLOCKERS_V1.to_string(),
        os: "windows".to_string(),
        status,
        metrics: BlockerMetrics {
            open_handles,
            commit_ratio_pct,
            hung_procs,
            ..Default::default()
        },
        blockers,
        warnings,
        systemd: None,
    }
}

pub fn apply_systemd_audit(report: &mut BlockersReport, systemd: SystemdAudit) {
    if !systemd.system_failed.is_empty() {
        let units: Vec<String> = systemd
            .system_failed
            .iter()
            .take(8)
            .map(|u| u.unit.clone())
            .collect();
        report.blockers.push(BlockerItem {
            id: "linux-systemd-system-failed".to_string(),
            severity: if systemd.system_failed.len() >= 3 {
                "CRITICAL".to_string()
            } else {
                "WARN".to_string()
            },
            title: "Failed systemd system unit(s)".to_string(),
            detail: format!(
                "{} failed unit(s): {}",
                systemd.system_failed.len(),
                units.join(", ")
            ),
            recommendation: "Inspect with `systemctl status <unit>` and `journalctl -xeu <unit>`"
                .to_string(),
        });
    }
    if !systemd.user_failed.is_empty() {
        let units: Vec<String> = systemd
            .user_failed
            .iter()
            .take(8)
            .map(|u| u.unit.clone())
            .collect();
        report.blockers.push(BlockerItem {
            id: "linux-systemd-user-failed".to_string(),
            severity: "WARN".to_string(),
            title: "Failed systemd user unit(s)".to_string(),
            detail: format!(
                "{} failed user unit(s): {}",
                systemd.user_failed.len(),
                units.join(", ")
            ),
            recommendation:
                "Inspect with `systemctl --user status <unit>` and reset stale units".to_string(),
        });
    }
    if !systemd.podman_healthcheck_issues.is_empty() {
        let units: Vec<String> = systemd
            .podman_healthcheck_issues
            .iter()
            .take(8)
            .map(|u| u.unit.clone())
            .collect();
        report.blockers.push(BlockerItem {
            id: "linux-podman-healthcheck-failed".to_string(),
            severity: "WARN".to_string(),
            title: "Broken/stale Podman healthcheck unit(s)".to_string(),
            detail: format!(
                "{} podman healthcheck unit(s): {}",
                systemd.podman_healthcheck_issues.len(),
                units.join(", ")
            ),
            recommendation: "Clean stale podman healthcheck timers/units or restart unhealthy containers".to_string(),
        });
    }
    report.status = overall_status(&report.blockers);
    report.systemd = Some(systemd);
}

pub fn parse_windows_blockers_json(raw_json: &str) -> Result<BlockersReport, SjError> {
    let val: serde_json::Value = serde_json::from_str(raw_json)?;
    let open_handles = val.get("open_handles").and_then(|v| v.as_u64());
    let commit_ratio_pct = val.get("commit_ratio_pct").and_then(|v| v.as_f64());
    let hung_procs = val.get("hung_procs").and_then(|v| v.as_u64());
    Ok(evaluate_windows_blockers(
        open_handles,
        commit_ratio_pct,
        hung_procs,
        Vec::new(),
    ))
}

#[cfg(target_os = "macos")]
fn sysctl_u64(key: &str) -> Option<u64> {
    Command::new("/usr/sbin/sysctl")
        .args(["-n", key])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<u64>()
                .ok()
        })
}

#[cfg(target_os = "macos")]
fn collect_platform_blockers() -> Result<BlockersReport, SjError> {
    let vnodes_used = sysctl_u64("kern.num_vnodes");
    let vnodes_max = sysctl_u64("kern.maxvnodes");
    let files_used = sysctl_u64("kern.num_files");
    let files_max = sysctl_u64("kern.maxfiles");

    let mut uninterruptible = 0u64;
    let mut fseventsd_rss = None;
    let mut warnings = Vec::new();

    match Command::new("/bin/ps")
        .args(["-axo", "state=,rss=,comm="])
        .output()
    {
        Ok(o) if o.status.success() => {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 3 {
                    continue;
                }
                let state = parts[0];
                if state.starts_with('U') {
                    uninterruptible = uninterruptible.saturating_add(1);
                }
                let comm = parts[2..].join(" ");
                if comm.ends_with("fseventsd") || comm == "fseventsd" {
                    if let Ok(rss_kb) = parts[1].parse::<u64>() {
                        fseventsd_rss = Some(rss_kb.saturating_mul(1024));
                    }
                }
            }
        }
        _ => warnings.push("ps probe unavailable for process states".to_string()),
    }

    Ok(evaluate_macos_blockers(
        vnodes_used,
        vnodes_max,
        files_used,
        files_max,
        Some(uninterruptible),
        fseventsd_rss,
        warnings,
    ))
}

/// Total inotify watches held by the processes readable under `proc_root` (a `/proc` tree): every
/// fd whose link is `anon_inode:inotify` contributes its `inotify wd:` lines from `fdinfo`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn count_inotify_watches(proc_root: &std::path::Path) -> Option<u64> {
    let mut total = 0u64;
    for ent in std::fs::read_dir(proc_root).ok()?.flatten() {
        if ent.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(ent.path().join("fd")) else {
            continue; // another user's process, or it exited
        };
        for fd in fds.flatten() {
            let is_inotify = std::fs::read_link(fd.path())
                .map(|t| t.to_string_lossy() == "anon_inode:inotify")
                .unwrap_or(false);
            if !is_inotify {
                continue;
            }
            if let Ok(info) = std::fs::read_to_string(
                ent.path().join("fdinfo").join(fd.file_name()),
            ) {
                let n = info.lines().filter(|l| l.starts_with("inotify wd:")).count() as u64;
                total = total.saturating_add(n);
            }
        }
    }
    Some(total)
}

#[cfg(target_os = "linux")]
fn collect_platform_blockers() -> Result<BlockersReport, SjError> {
    let mut warnings = Vec::new();
    let (files_used, files_max) = std::fs::read_to_string("/proc/sys/fs/file-nr")
        .ok()
        .and_then(|s| parse_linux_file_nr(&s))
        .map(|(u, m)| (Some(u), Some(m)))
        .unwrap_or_else(|| {
            warnings.push("/proc/sys/fs/file-nr unavailable".to_string());
            (None, None)
        });

    let inotify_max = std::fs::read_to_string("/proc/sys/fs/inotify/max_user_watches")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());

    let mut d_state = 0u64;
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for ent in entries.flatten() {
            if ent.file_name().to_string_lossy().parse::<u32>().is_err() {
                continue;
            }
            if let Ok(stat) = std::fs::read_to_string(ent.path().join("stat")) {
                if let Some(close) = stat.rfind(')') {
                    if let Some(state_tok) = stat[close + 1..].split_whitespace().next() {
                        if state_tok == "D" {
                            d_state = d_state.saturating_add(1);
                        }
                    }
                }
            }
        }
    }

    let mut report = evaluate_linux_blockers(
        files_used,
        files_max,
        Some(d_state),
        inotify_max.and_then(|_| count_inotify_watches(std::path::Path::new("/proc"))),
        inotify_max,
        warnings,
    );
    apply_systemd_audit(&mut report, collect_systemd_audit());
    Ok(report)
}

#[cfg(target_os = "windows")]
fn collect_platform_blockers() -> Result<BlockersReport, SjError> {
    let ps_script = "$procs = Get-Process; $handles = ($procs | Measure-Object -Property HandleCount -Sum).Sum; $hung = ($procs | Where-Object { $_.Responding -eq $false }).Count; $os = Get-CimInstance Win32_OperatingSystem; $ratio = if ($os.TotalVirtualMemorySize -gt 0) { (($os.TotalVirtualMemorySize - $os.FreeVirtualMemory) / $os.TotalVirtualMemorySize) * 100.0 } else { 0.0 }; @{ open_handles = [int64]$handles; commit_ratio_pct = [math]::Round($ratio, 2); hung_procs = [int64]$hung } | ConvertTo-Json -Compress";
    match Command::new("powershell")
        .args(["-NoProfile", "-Command", ps_script])
        .output()
    {
        Ok(o) if o.status.success() => {
            parse_windows_blockers_json(&String::from_utf8_lossy(&o.stdout))
        }
        _ => Ok(evaluate_windows_blockers(
            None,
            None,
            None,
            vec!["powershell blockers probe unavailable".to_string()],
        )),
    }
}

pub fn collect_blockers_report() -> Result<BlockersReport, SjError> {
    collect_platform_blockers()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn inotify_watches_are_summed_from_a_proc_fixture_tree() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // pid 10: one inotify fd with 2 watches, one regular fd that must be ignored
        let p10 = root.join("10");
        std::fs::create_dir_all(p10.join("fd")).unwrap();
        std::fs::create_dir_all(p10.join("fdinfo")).unwrap();
        symlink("anon_inode:inotify", p10.join("fd/3")).unwrap();
        symlink("/dev/null", p10.join("fd/4")).unwrap();
        std::fs::write(
            p10.join("fdinfo/3"),
            "pos:\t0\nflags:\t02004000\ninotify wd:1 ino:5 sdev:7 mask:2 ignored_mask:0\ninotify wd:2 ino:6 sdev:7 mask:2 ignored_mask:0\n",
        )
        .unwrap();
        std::fs::write(p10.join("fdinfo/4"), "inotify wd:9 ino:1\n").unwrap();
        // pid 11: one inotify fd with 1 watch; a non-pid entry must be skipped
        let p11 = root.join("11");
        std::fs::create_dir_all(p11.join("fd")).unwrap();
        std::fs::create_dir_all(p11.join("fdinfo")).unwrap();
        symlink("anon_inode:inotify", p11.join("fd/5")).unwrap();
        std::fs::write(p11.join("fdinfo/5"), "inotify wd:1 ino:5 sdev:7 mask:2 ignored_mask:0\n").unwrap();
        std::fs::create_dir_all(root.join("sys")).unwrap();
        assert_eq!(count_inotify_watches(root), Some(3));
        assert_eq!(count_inotify_watches(&root.join("missing")), None);
    }


    #[test]
    fn macos_blocker_thresholds_cover_ok_warn_and_critical() {
        let ok = evaluate_macos_blockers(
            Some(100_000),
            Some(263_168),
            Some(10_000),
            Some(122_880),
            Some(0),
            Some(64 * 1024 * 1024),
            vec![],
        );
        assert_eq!(ok.schema, SCHEMA_BLOCKERS_V1);
        assert_eq!(ok.os, "macos");
        assert_eq!(ok.status, "OK");
        assert!(ok.blockers.is_empty());

        let warn = evaluate_macos_blockers(
            Some(200_000),
            Some(263_168), // ~76%
            Some(10_000),
            Some(122_880),
            Some(1),
            Some(300 * 1024 * 1024),
            vec![],
        );
        assert_eq!(warn.status, "WARN");
        assert_eq!(warn.blockers.len(), 3);

        let crit = evaluate_macos_blockers(
            Some(250_000),
            Some(263_168), // ~95%
            Some(115_000),
            Some(122_880), // ~93.6%
            Some(6),
            Some(600 * 1024 * 1024),
            vec![],
        );
        assert_eq!(crit.status, "CRITICAL");
        assert!(crit.blockers.iter().all(|b| b.severity == "CRITICAL"));
    }

    #[test]
    fn linux_file_nr_and_thresholds_work() {
        let (used, max) = parse_linux_file_nr("45000\t0\t50000\n").unwrap();
        assert_eq!(used, 45_000);
        assert_eq!(max, 50_000);

        let crit = evaluate_linux_blockers(
            Some(used),
            Some(max),
            Some(2),
            Some(60_000),
            Some(65_536), // ~91.5%
            vec![],
        );
        assert_eq!(crit.status, "CRITICAL");
        assert_eq!(crit.blockers.len(), 3);
    }

    #[test]
    fn windows_blockers_json_and_thresholds_work() {
        let ok = parse_windows_blockers_json(
            r#"{"open_handles": 45000, "commit_ratio_pct": 42.5, "hung_procs": 0}"#,
        )
        .unwrap();
        assert_eq!(ok.status, "OK");

        let warn = parse_windows_blockers_json(
            r#"{"open_handles": 160000, "commit_ratio_pct": 78.0, "hung_procs": 1}"#,
        )
        .unwrap();
        assert_eq!(warn.status, "WARN");
        assert_eq!(warn.blockers.len(), 3);

        let crit = parse_windows_blockers_json(
            r#"{"open_handles": 300000, "commit_ratio_pct": 94.2, "hung_procs": 4}"#,
        )
        .unwrap();
        assert_eq!(crit.status, "CRITICAL");
        assert_eq!(crit.blockers.len(), 3);
    }

    #[test]
    fn live_blockers_report_conforms_to_schema() {
        let report = collect_blockers_report().unwrap();
        assert_eq!(report.schema, SCHEMA_BLOCKERS_V1);
        assert!(matches!(report.status.as_str(), "OK" | "WARN" | "CRITICAL"));
    }
}
