use crate::{redact_secrets, SjError, SCHEMA_MEMORY_V1};
use serde::Serialize;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SystemMemorySummary {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub wired_bytes: u64,
    pub active_bytes: u64,
    pub compressed_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub pressure_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessMemoryEntry {
    pub pid: u32,
    pub ppid: u32,
    pub command: String,
    pub resident_bytes: u64,
    pub compressed_bytes: u64,
    pub swap_bytes: u64,
    pub true_footprint_bytes: u64,
    pub ports_count: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryReport {
    pub schema: String,
    pub os: String,
    pub system: SystemMemorySummary,
    pub total_process_footprint_bytes: u64,
    pub processes: Vec<ProcessMemoryEntry>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryOptions {
    pub top_n: usize,
}

impl Default for MemoryOptions {
    fn default() -> Self {
        Self { top_n: 20 }
    }
}

pub fn parse_size_token(raw: &str) -> Option<u64> {
    let cleaned = raw.trim().trim_end_matches(['+', '-', ',']).trim();
    if cleaned.is_empty() || cleaned == "-" || cleaned.eq_ignore_ascii_case("n/a") {
        return Some(0);
    }
    let last = cleaned.chars().last()?;
    let (num_str, mult): (&str, f64) = match last {
        'B' | 'b' => (&cleaned[..cleaned.len() - 1], 1.0),
        'K' | 'k' => (&cleaned[..cleaned.len() - 1], 1024.0),
        'M' | 'm' => (&cleaned[..cleaned.len() - 1], 1024.0 * 1024.0),
        'G' | 'g' => (&cleaned[..cleaned.len() - 1], 1024.0 * 1024.0 * 1024.0),
        'T' | 't' => (
            &cleaned[..cleaned.len() - 1],
            1024.0 * 1024.0 * 1024.0 * 1024.0,
        ),
        '0'..='9' => (cleaned, 1.0),
        _ => return None,
    };
    let val: f64 = num_str.trim().parse().ok()?;
    if val.is_sign_negative() || !val.is_finite() {
        return None;
    }
    Some((val * mult).round() as u64)
}

fn compute_pressure_state(
    total_bytes: u64,
    used_bytes: u64,
    compressed_bytes: u64,
    swap_total_bytes: u64,
    swap_used_bytes: u64,
) -> String {
    let swap_ratio = if swap_total_bytes > 0 {
        swap_used_bytes as f64 / swap_total_bytes as f64
    } else {
        0.0
    };
    let mem_ratio = if total_bytes > 0 {
        used_bytes.saturating_add(compressed_bytes) as f64 / total_bytes as f64
    } else {
        0.0
    };
    if swap_ratio >= 0.75 || mem_ratio >= 0.90 {
        "critical".to_string()
    } else if swap_ratio >= 0.40 || mem_ratio >= 0.75 {
        "warn".to_string()
    } else {
        "normal".to_string()
    }
}

pub fn parse_macos_vm_stat(
    vm_stat_out: &str,
    total_bytes_hint: Option<u64>,
) -> SystemMemorySummary {
    let mut page_size: u64 = 4096;
    let mut active_pages: u64 = 0;
    let mut wired_pages: u64 = 0;
    let mut compressed_pages: u64 = 0;
    let mut inactive_pages: u64 = 0;
    let mut speculative_pages: u64 = 0;
    let mut free_pages: u64 = 0;

    for line in vm_stat_out.lines() {
        let trimmed = line.trim();
        if let Some(idx) = trimmed.find("page size of ") {
            let rest = &trimmed[idx + "page size of ".len()..];
            if let Some(num_str) = rest.split_whitespace().next() {
                if let Ok(ps) = num_str.parse::<u64>() {
                    page_size = ps;
                }
            }
            continue;
        }
        let Some((k, v)) = trimmed.split_once(':') else {
            continue;
        };
        let count = v.trim().trim_end_matches('.').parse::<u64>().unwrap_or(0);
        match k.trim() {
            "Pages active" => active_pages = count,
            "Pages wired down" => wired_pages = count,
            "Pages occupied by compressor" => compressed_pages = count,
            "Pages inactive" => inactive_pages = count,
            "Pages speculative" => speculative_pages = count,
            "Pages free" => free_pages = count,
            _ => {}
        }
    }

    let active_bytes = active_pages.saturating_mul(page_size);
    let wired_bytes = wired_pages.saturating_mul(page_size);
    let compressed_bytes = compressed_pages.saturating_mul(page_size);
    let used_bytes = active_bytes
        .saturating_add(wired_bytes)
        .saturating_add(compressed_bytes);
    let inferred_total = used_bytes
        .saturating_add(inactive_pages.saturating_mul(page_size))
        .saturating_add(speculative_pages.saturating_mul(page_size))
        .saturating_add(free_pages.saturating_mul(page_size));
    let total_bytes = total_bytes_hint.unwrap_or(inferred_total);

    SystemMemorySummary {
        total_bytes,
        used_bytes,
        wired_bytes,
        active_bytes,
        compressed_bytes,
        swap_total_bytes: 0,
        swap_used_bytes: 0,
        pressure_state: compute_pressure_state(total_bytes, used_bytes, compressed_bytes, 0, 0),
    }
}

pub fn parse_macos_swapusage(swap_out: &str) -> (u64, u64) {
    let mut total = 0u64;
    let mut used = 0u64;
    let tokens: Vec<&str> = swap_out.split_whitespace().collect();
    for i in 0..tokens.len() {
        if tokens[i] == "total" && tokens.get(i + 1) == Some(&"=") {
            if let Some(val) = tokens.get(i + 2).and_then(|s| parse_size_token(s)) {
                total = val;
            }
        } else if tokens[i] == "used" && tokens.get(i + 1) == Some(&"=") {
            if let Some(val) = tokens.get(i + 2).and_then(|s| parse_size_token(s)) {
                used = val;
            }
        }
    }
    (total, used)
}

pub fn parse_macos_top(top_out: &str) -> Vec<ProcessMemoryEntry> {
    let mut in_table = false;
    let mut entries = Vec::new();

    for line in top_out.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !in_table {
            if trimmed.starts_with("PID") && trimmed.contains("PPID") && trimmed.contains("MEM") {
                in_table = true;
            }
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let Ok(pid) = parts[0].parse::<u32>() else {
            continue;
        };
        let Ok(ppid) = parts[1].parse::<u32>() else {
            continue;
        };
        let ports_tok = parts[parts.len() - 1];
        let cmprs_tok = parts[parts.len() - 2];
        let mem_tok = parts[parts.len() - 3];
        let command_raw = parts[2..parts.len() - 3].join(" ");

        let resident_bytes = parse_size_token(mem_tok).unwrap_or(0);
        let compressed_bytes = parse_size_token(cmprs_tok).unwrap_or(0);
        let ports_count = ports_tok.trim_end_matches(['+', '-']).parse::<u32>().ok();
        let true_footprint_bytes = resident_bytes.saturating_add(compressed_bytes);

        entries.push(ProcessMemoryEntry {
            pid,
            ppid,
            command: redact_secrets(&command_raw),
            resident_bytes,
            compressed_bytes,
            swap_bytes: 0,
            true_footprint_bytes,
            ports_count,
        });
    }

    entries
}

pub fn parse_macos_ps_fallback(ps_out: &str) -> Vec<ProcessMemoryEntry> {
    let mut entries = Vec::new();
    for line in ps_out.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let Ok(pid) = parts[0].parse::<u32>() else {
            continue;
        };
        let Ok(ppid) = parts[1].parse::<u32>() else {
            continue;
        };
        let Ok(rss_kib) = parts[2].parse::<u64>() else {
            continue;
        };
        let command_raw = parts[3..].join(" ");
        let resident_bytes = rss_kib.saturating_mul(1024);
        entries.push(ProcessMemoryEntry {
            pid,
            ppid,
            command: redact_secrets(&command_raw),
            resident_bytes,
            compressed_bytes: 0,
            swap_bytes: 0,
            true_footprint_bytes: resident_bytes,
            ports_count: None,
        });
    }
    entries
}

pub fn parse_linux_meminfo(meminfo: &str) -> SystemMemorySummary {
    let mut total_kb = 0u64;
    let mut avail_kb = 0u64;
    let mut free_kb = 0u64;
    let mut buffers_kb = 0u64;
    let mut cached_kb = 0u64;
    let mut active_kb = 0u64;
    let mut slab_kb = 0u64;
    let mut swap_total_kb = 0u64;
    let mut swap_free_kb = 0u64;
    let mut has_avail = false;

    for line in meminfo.lines() {
        let Some((k, rest)) = line.split_once(':') else {
            continue;
        };
        let val = rest
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        match k.trim() {
            "MemTotal" => total_kb = val,
            "MemAvailable" => {
                avail_kb = val;
                has_avail = true;
            }
            "MemFree" => free_kb = val,
            "Buffers" => buffers_kb = val,
            "Cached" => cached_kb = val,
            "Active" => active_kb = val,
            "Slab" => slab_kb = val,
            "SwapTotal" => swap_total_kb = val,
            "SwapFree" => swap_free_kb = val,
            _ => {}
        }
    }

    let effective_avail_kb = if has_avail {
        avail_kb
    } else {
        free_kb.saturating_add(buffers_kb).saturating_add(cached_kb)
    };
    let total_bytes = total_kb.saturating_mul(1024);
    let used_bytes = total_kb
        .saturating_sub(effective_avail_kb)
        .saturating_mul(1024);
    let wired_bytes = slab_kb.saturating_mul(1024);
    let active_bytes = active_kb.saturating_mul(1024);
    let swap_total_bytes = swap_total_kb.saturating_mul(1024);
    let swap_used_bytes = swap_total_kb
        .saturating_sub(swap_free_kb)
        .saturating_mul(1024);

    SystemMemorySummary {
        total_bytes,
        used_bytes,
        wired_bytes,
        active_bytes,
        compressed_bytes: 0,
        swap_total_bytes,
        swap_used_bytes,
        pressure_state: compute_pressure_state(
            total_bytes,
            used_bytes,
            0,
            swap_total_bytes,
            swap_used_bytes,
        ),
    }
}

pub fn parse_linux_smaps_rollup(smaps: &str) -> (u64, u64, u64) {
    let mut rss_kb = 0u64;
    let mut pss_kb = None;
    let mut swap_pss_kb = None;
    let mut swap_kb = 0u64;

    for line in smaps.lines() {
        let Some((k, rest)) = line.split_once(':') else {
            continue;
        };
        let val = rest
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        match k.trim() {
            "Rss" => rss_kb = val,
            "Pss" => pss_kb = Some(val),
            "SwapPss" => swap_pss_kb = Some(val),
            "Swap" => swap_kb = val,
            _ => {}
        }
    }

    let resident_bytes = pss_kb.unwrap_or(rss_kb).saturating_mul(1024);
    let swap_bytes = swap_pss_kb.unwrap_or(swap_kb).saturating_mul(1024);
    let true_footprint = resident_bytes.saturating_add(swap_bytes);
    (resident_bytes, swap_bytes, true_footprint)
}

pub fn parse_linux_proc_stat(stat_line: &str, page_size: u64) -> Option<(u32, u32, String, u64)> {
    let open = stat_line.find('(')?;
    let close = stat_line.rfind(')')?;
    if close <= open {
        return None;
    }
    let pid = stat_line[..open].trim().parse::<u32>().ok()?;
    let comm = stat_line[open + 1..close].to_string();
    let after: Vec<&str> = stat_line[close + 1..].split_whitespace().collect();
    // after[0] = state (field 3), after[1] = ppid (field 4), after[21] = rss (field 24)
    if after.len() <= 21 {
        return None;
    }
    let ppid = after[1].parse::<u32>().ok()?;
    let rss_pages = after[21].parse::<u64>().ok()?;
    Some((pid, ppid, comm, rss_pages.saturating_mul(page_size)))
}

pub fn parse_windows_memory_json(
    raw_json: &str,
) -> Result<(SystemMemorySummary, Vec<ProcessMemoryEntry>), SjError> {
    let val: serde_json::Value = serde_json::from_str(raw_json)?;
    let os_obj = val.get("os").unwrap_or(&serde_json::Value::Null);

    let total_kb = os_obj
        .get("TotalVisibleMemorySize")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let free_kb = os_obj
        .get("FreePhysicalMemory")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let swap_total_kb = os_obj
        .get("SizeStoredInPagingFiles")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let swap_free_kb = os_obj
        .get("FreeSpaceInPagingFiles")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let total_bytes = total_kb.saturating_mul(1024);
    let used_bytes = total_kb.saturating_sub(free_kb).saturating_mul(1024);
    let swap_total_bytes = swap_total_kb.saturating_mul(1024);
    let swap_used_bytes = swap_total_kb
        .saturating_sub(swap_free_kb)
        .saturating_mul(1024);

    let system = SystemMemorySummary {
        total_bytes,
        used_bytes,
        wired_bytes: 0,
        active_bytes: used_bytes,
        compressed_bytes: 0,
        swap_total_bytes,
        swap_used_bytes,
        pressure_state: compute_pressure_state(
            total_bytes,
            used_bytes,
            0,
            swap_total_bytes,
            swap_used_bytes,
        ),
    };

    let mut processes = Vec::new();
    if let Some(arr) = val.get("processes").and_then(|v| v.as_array()) {
        for p in arr {
            let pid = p.get("ProcessId").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let ppid = p
                .get("ParentProcessId")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let cmd_raw = p
                .get("CommandLine")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .or_else(|| p.get("Name").and_then(|v| v.as_str()))
                .unwrap_or("unknown");
            let ws = p
                .get("WorkingSetSize")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let priv_bytes = p
                .get("PrivatePageCount")
                .and_then(|v| v.as_u64())
                .unwrap_or(ws);
            let page_file = p.get("PageFileUsage").and_then(|v| v.as_u64()).unwrap_or(0);
            let handles = p
                .get("HandleCount")
                .and_then(|v| v.as_u64())
                .and_then(|h| u32::try_from(h).ok());
            let true_footprint_bytes = ws.max(priv_bytes).saturating_add(page_file);
            processes.push(ProcessMemoryEntry {
                pid,
                ppid,
                command: redact_secrets(cmd_raw),
                resident_bytes: ws,
                compressed_bytes: 0,
                swap_bytes: page_file,
                true_footprint_bytes,
                ports_count: handles,
            });
        }
    }

    Ok((system, processes))
}

fn finalize_memory_report(
    os: &str,
    system: SystemMemorySummary,
    mut processes: Vec<ProcessMemoryEntry>,
    warnings: Vec<String>,
    opts: &MemoryOptions,
) -> MemoryReport {
    processes.sort_by(|a, b| {
        b.true_footprint_bytes
            .cmp(&a.true_footprint_bytes)
            .then_with(|| a.pid.cmp(&b.pid))
    });
    let total_process_footprint_bytes = processes
        .iter()
        .fold(0u64, |acc, p| acc.saturating_add(p.true_footprint_bytes));
    if opts.top_n > 0 && processes.len() > opts.top_n {
        processes.truncate(opts.top_n);
    }
    MemoryReport {
        schema: SCHEMA_MEMORY_V1.to_string(),
        os: os.to_string(),
        system,
        total_process_footprint_bytes,
        processes,
        warnings,
    }
}

#[cfg(target_os = "macos")]
fn collect_platform_memory(opts: &MemoryOptions) -> Result<MemoryReport, SjError> {
    let mut warnings = Vec::new();
    let hw_mem = Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<u64>()
                .ok()
        });

    let vm_out = Command::new("vm_stat").output();
    let mut system = match vm_out {
        Ok(o) if o.status.success() => {
            parse_macos_vm_stat(&String::from_utf8_lossy(&o.stdout), hw_mem)
        }
        _ => {
            warnings.push("vm_stat unavailable".to_string());
            SystemMemorySummary {
                total_bytes: hw_mem.unwrap_or(0),
                used_bytes: 0,
                wired_bytes: 0,
                active_bytes: 0,
                compressed_bytes: 0,
                swap_total_bytes: 0,
                swap_used_bytes: 0,
                pressure_state: "normal".to_string(),
            }
        }
    };

    if let Ok(o) = Command::new("sysctl").args(["vm.swapusage"]).output() {
        if o.status.success() {
            let (st, su) = parse_macos_swapusage(&String::from_utf8_lossy(&o.stdout));
            system.swap_total_bytes = st;
            system.swap_used_bytes = su;
            system.pressure_state = compute_pressure_state(
                system.total_bytes,
                system.used_bytes,
                system.compressed_bytes,
                st,
                su,
            );
        }
    }

    let mut processes = match Command::new("top")
        .args(["-l", "1", "-stats", "pid,ppid,command,mem,cmprs,ports"])
        .output()
    {
        Ok(o) if o.status.success() => parse_macos_top(&String::from_utf8_lossy(&o.stdout)),
        _ => Vec::new(),
    };

    if processes.is_empty() {
        warnings.push("top unavailable or empty; fell back to ps".to_string());
        if let Ok(o) = Command::new("ps")
            .args(["-axo", "pid=,ppid=,rss=,comm="])
            .output()
        {
            if o.status.success() {
                processes = parse_macos_ps_fallback(&String::from_utf8_lossy(&o.stdout));
            }
        }
    }

    Ok(finalize_memory_report(
        std::env::consts::OS,
        system,
        processes,
        warnings,
        opts,
    ))
}

#[cfg(target_os = "linux")]
fn collect_platform_memory(opts: &MemoryOptions) -> Result<MemoryReport, SjError> {
    let mut warnings = Vec::new();
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    if meminfo.is_empty() {
        warnings.push("/proc/meminfo unavailable".to_string());
    }
    let system = parse_linux_meminfo(&meminfo);
    let mut processes = Vec::new();

    if let Ok(entries) = std::fs::read_dir("/proc") {
        for ent in entries.flatten() {
            let name = ent.file_name();
            let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
                continue;
            };
            let proc_dir = ent.path();
            let Ok(stat_line) = std::fs::read_to_string(proc_dir.join("stat")) else {
                continue;
            };
            let Some((_, ppid, comm, stat_rss)) = parse_linux_proc_stat(&stat_line, 4096) else {
                continue;
            };
            let cmdline = std::fs::read(proc_dir.join("cmdline"))
                .ok()
                .map(|b| {
                    String::from_utf8_lossy(&b)
                        .replace('\0', " ")
                        .trim()
                        .to_string()
                })
                .filter(|s| !s.is_empty())
                .unwrap_or(comm);

            let (resident_bytes, swap_bytes, true_footprint_bytes) =
                match std::fs::read_to_string(proc_dir.join("smaps_rollup")) {
                    Ok(smaps) => parse_linux_smaps_rollup(&smaps),
                    Err(_) => (stat_rss, 0, stat_rss),
                };

            processes.push(ProcessMemoryEntry {
                pid,
                ppid,
                command: redact_secrets(&cmdline),
                resident_bytes,
                compressed_bytes: 0,
                swap_bytes,
                true_footprint_bytes,
                ports_count: None,
            });
        }
    }

    Ok(finalize_memory_report(
        std::env::consts::OS,
        system,
        processes,
        warnings,
        opts,
    ))
}

#[cfg(target_os = "windows")]
fn collect_platform_memory(opts: &MemoryOptions) -> Result<MemoryReport, SjError> {
    let ps_script = "$os = Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory,SizeStoredInPagingFiles,FreeSpaceInPagingFiles; $procs = Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine,WorkingSetSize,PrivatePageCount,PageFileUsage,HandleCount; @{ os = $os; processes = $procs } | ConvertTo-Json -Depth 3 -Compress";
    let mut warnings = Vec::new();
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", ps_script])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let raw = String::from_utf8_lossy(&o.stdout);
            match parse_windows_memory_json(&raw) {
                Ok((sys, procs)) => Ok(finalize_memory_report(
                    std::env::consts::OS,
                    sys,
                    procs,
                    warnings,
                    opts,
                )),
                Err(e) => {
                    warnings.push(format!("failed to parse windows telemetry: {e}"));
                    Ok(finalize_memory_report(
                        std::env::consts::OS,
                        SystemMemorySummary {
                            total_bytes: 0,
                            used_bytes: 0,
                            wired_bytes: 0,
                            active_bytes: 0,
                            compressed_bytes: 0,
                            swap_total_bytes: 0,
                            swap_used_bytes: 0,
                            pressure_state: "normal".to_string(),
                        },
                        Vec::new(),
                        warnings,
                        opts,
                    ))
                }
            }
        }
        _ => {
            warnings.push("powershell CIM memory probe unavailable".to_string());
            Ok(finalize_memory_report(
                std::env::consts::OS,
                SystemMemorySummary {
                    total_bytes: 0,
                    used_bytes: 0,
                    wired_bytes: 0,
                    active_bytes: 0,
                    compressed_bytes: 0,
                    swap_total_bytes: 0,
                    swap_used_bytes: 0,
                    pressure_state: "normal".to_string(),
                },
                Vec::new(),
                warnings,
                opts,
            ))
        }
    }
}

pub fn collect_memory_report(opts: &MemoryOptions) -> Result<MemoryReport, SjError> {
    collect_platform_memory(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_vm_stat_swap_and_top_parsers_work_deterministically() {
        let vm_stat = "\
Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                               10000.
Pages active:                            120000.
Pages inactive:                           40000.
Pages speculative:                         2000.
Pages wired down:                         80000.
Pages occupied by compressor:             60000.
";
        let mut sys = parse_macos_vm_stat(vm_stat, Some(32 * 1024 * 1024 * 1024));
        let (st, su) = parse_macos_swapusage(
            "vm.swapusage: total = 4096.00M  used = 3200.00M  free = 896.00M  (encrypted)",
        );
        sys.swap_total_bytes = st;
        sys.swap_used_bytes = su;
        sys.pressure_state = compute_pressure_state(
            sys.total_bytes,
            sys.used_bytes,
            sys.compressed_bytes,
            st,
            su,
        );

        assert_eq!(sys.active_bytes, 120_000 * 16384);
        assert_eq!(sys.wired_bytes, 80_000 * 16384);
        assert_eq!(sys.compressed_bytes, 60_000 * 16384);
        assert_eq!(sys.swap_total_bytes, 4096 * 1024 * 1024);
        assert_eq!(sys.pressure_state, "critical");

        let top_out = "\
Processes: 400 total, 3 running, 397 sleeping, 2000 threads
PID    PPID  COMMAND          MEM      CMPRS    PORTS
1234   1     node --token=abc 512M+    256M     42+
5678   1234  rust-analyzer    1G       128M     12
";
        let procs = parse_macos_top(top_out);
        assert_eq!(procs.len(), 2);
        assert_eq!(procs[0].pid, 1234);
        assert_eq!(procs[0].ppid, 1);
        assert!(!procs[0].command.contains("abc"));
        assert!(procs[0].command.contains("--token=<REDACTED>"));
        assert_eq!(procs[0].resident_bytes, 512 * 1024 * 1024);
        assert_eq!(procs[0].compressed_bytes, 256 * 1024 * 1024);
        assert_eq!(procs[0].true_footprint_bytes, 768 * 1024 * 1024);
        assert_eq!(procs[0].ports_count, Some(42));
        assert_eq!(procs[1].true_footprint_bytes, (1024 + 128) * 1024 * 1024);
    }

    #[test]
    fn linux_meminfo_smaps_and_stat_parsers_work_deterministically() {
        let meminfo = "\
MemTotal:       16384000 kB
MemFree:         1024000 kB
MemAvailable:    4096000 kB
Active:          8192000 kB
Slab:             512000 kB
SwapTotal:       4194304 kB
SwapFree:        2097152 kB
";
        let sys = parse_linux_meminfo(meminfo);
        assert_eq!(sys.total_bytes, 16_384_000 * 1024);
        assert_eq!(sys.used_bytes, (16_384_000 - 4_096_000) * 1024);
        assert_eq!(sys.swap_used_bytes, 2_097_152 * 1024);
        assert_eq!(sys.pressure_state, "warn");

        let smaps = "\
Rss:              204800 kB
Pss:              150000 kB
Swap:              64000 kB
SwapPss:           32000 kB
";
        let (res, swap, total) = parse_linux_smaps_rollup(smaps);
        assert_eq!(res, 150_000 * 1024);
        assert_eq!(swap, 32_000 * 1024);
        assert_eq!(total, 182_000 * 1024);

        let stat = "4321 (node (worker)) S 1 4321 4321 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 4 0 12345 1048576 2500 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";
        let (pid, ppid, comm, rss) = parse_linux_proc_stat(stat, 4096).unwrap();
        assert_eq!(pid, 4321);
        assert_eq!(ppid, 1);
        assert_eq!(comm, "node (worker)");
        assert_eq!(rss, 2500 * 4096);
    }

    #[test]
    fn windows_cim_memory_json_parser_works_and_redacts_secrets() {
        let fixture = r#"{
            "os": {
                "TotalVisibleMemorySize": 16777216,
                "FreePhysicalMemory": 4194304,
                "SizeStoredInPagingFiles": 4194304,
                "FreeSpaceInPagingFiles": 2097152
            },
            "processes": [
                {
                    "ProcessId": 9001,
                    "ParentProcessId": 1,
                    "Name": "node.exe",
                    "CommandLine": "node.exe mcp.js --api-key=secret_xyz",
                    "WorkingSetSize": 268435456,
                    "PrivatePageCount": 536870912,
                    "PageFileUsage": 67108864,
                    "HandleCount": 640
                }
            ]
        }"#;

        let (sys, procs) = parse_windows_memory_json(fixture).unwrap();
        assert_eq!(sys.total_bytes, 16_777_216 * 1024);
        assert_eq!(sys.used_bytes, (16_777_216 - 4_194_304) * 1024);
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].pid, 9001);
        assert!(!procs[0].command.contains("secret_xyz"));
        assert!(procs[0].command.contains("--api-key=<REDACTED>"));
        assert_eq!(procs[0].true_footprint_bytes, 536_870_912 + 67_108_864);
        assert_eq!(procs[0].ports_count, Some(640));
    }

    #[test]
    fn live_memory_report_conforms_to_schema_and_ordering() {
        let report = collect_memory_report(&MemoryOptions { top_n: 5 }).unwrap();
        assert_eq!(report.schema, SCHEMA_MEMORY_V1);
        assert!(report.processes.len() <= 5);
        for w in report.processes.windows(2) {
            assert!(w[0].true_footprint_bytes >= w[1].true_footprint_bytes);
        }
    }
}
