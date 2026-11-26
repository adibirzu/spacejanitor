use crate::protect::{
    check_dir_descendants_safe, check_path_protection_anchored, ProtectionContext,
};
use crate::{SjError, SCHEMA_LINUX_AUDIT_V1};
use jwalk::WalkDir;
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

const GIB: u64 = 1024 * 1024 * 1024;
const DEFAULT_STALE_TMP_SECS: u64 = 24 * 3600;
const DEFAULT_BACKUP_AGE_SECS: u64 = 30 * 24 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MountKind {
    Physical,
    Tmpfs,
    Overlay,
    AppImage,
    Virtual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MountInfo {
    pub device: String,
    pub mountpoint: String,
    pub fstype: String,
    pub kind: MountKind,
    pub alert_eligible: bool,
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub used_percent: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct DockerDfSummary {
    pub available: bool,
    pub images_total_bytes: u64,
    pub images_reclaimable_bytes: u64,
    pub containers_total_bytes: u64,
    pub containers_reclaimable_bytes: u64,
    pub volumes_total_bytes: u64,
    pub volumes_reclaimable_bytes: u64,
    pub build_cache_total_bytes: u64,
    pub build_cache_reclaimable_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainerInfo {
    pub runtime: String,
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub state: String,
    pub size_bytes: u64,
    pub unhealthy: bool,
}

impl ContainerInfo {
    pub fn is_reclaimable_stopped(&self) -> bool {
        let s = self.state.to_ascii_lowercase();
        let st = self.status.to_ascii_lowercase();
        matches!(s.as_str(), "exited" | "created" | "dead")
            || st.starts_with("exited")
            || st == "created"
            || st.starts_with("dead")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DanglingImage {
    pub id: String,
    pub repository: String,
    pub tag: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct ContainerRuntimeAudit {
    pub available: bool,
    pub df: DockerDfSummary,
    pub exited_containers: Vec<ContainerInfo>,
    pub unhealthy_containers: Vec<ContainerInfo>,
    pub dangling_images: Vec<DanglingImage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct JournaldAudit {
    pub available: bool,
    pub bytes: u64,
    pub vacuum_target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct PackageCachesAudit {
    pub apt_archives_path: String,
    pub apt_archives_bytes: u64,
    pub user_caches: Vec<PathArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PathArtifact {
    pub path: String,
    pub bytes: u64,
    pub kind: String,
    pub age_days: u64,
    pub manual_review_only: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SystemdUnitIssue {
    pub unit: String,
    pub scope: String,
    pub load: String,
    pub active: String,
    pub sub: String,
    pub description: String,
    pub is_podman_healthcheck: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct SystemdAudit {
    pub available: bool,
    pub user_bus_available: bool,
    pub system_failed: Vec<SystemdUnitIssue>,
    pub user_failed: Vec<SystemdUnitIssue>,
    pub podman_healthcheck_issues: Vec<SystemdUnitIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinuxAuditReport {
    pub schema: String,
    pub os: String,
    pub arch: String,
    pub mounts: Vec<MountInfo>,
    pub appimage_mounts: Vec<MountInfo>,
    pub docker: ContainerRuntimeAudit,
    pub podman: ContainerRuntimeAudit,
    pub journald: JournaldAudit,
    pub package_caches: PackageCachesAudit,
    pub stale_tmp_entries: Vec<PathArtifact>,
    pub model_caches: Vec<PathArtifact>,
    pub old_backups: Vec<PathArtifact>,
    pub systemd: SystemdAudit,
}

#[derive(Debug, Clone)]
pub struct LinuxFixtures {
    pub home_dir: PathBuf,
    pub tmp_dir: PathBuf,
    pub apt_archives_dir: Option<PathBuf>,
    pub mounts_raw: String,
    pub docker_df_raw: String,
    pub docker_ps_raw: String,
    pub docker_images_raw: String,
    pub podman_df_raw: String,
    pub podman_ps_raw: String,
    pub journald_usage_raw: String,
    pub systemctl_system_raw: String,
    pub systemctl_user_raw: String,
    pub stale_age_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct LinuxMemInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub free_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
}

fn unescape_mount_field(raw: &str) -> String {
    raw.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

pub fn classify_mount(_device: &str, mountpoint: &str, fstype: &str) -> MountKind {
    let ft = fstype.to_ascii_lowercase();
    if mountpoint.starts_with("/tmp/.mount_")
        || ft.starts_with("fuse.appimage")
        || (ft.starts_with("fuse.") && mountpoint.contains(".mount_"))
        || (ft == "squashfs" && mountpoint.starts_with("/tmp/.mount_"))
    {
        return MountKind::AppImage;
    }
    if ft == "overlay" || ft == "overlayfs" {
        return MountKind::Overlay;
    }
    if ft == "tmpfs" || ft == "devtmpfs" {
        return if ft == "devtmpfs" {
            MountKind::Virtual
        } else {
            MountKind::Tmpfs
        };
    }
    if matches!(
        ft.as_str(),
        "proc"
            | "sysfs"
            | "devpts"
            | "cgroup"
            | "cgroup2"
            | "pstore"
            | "bpf"
            | "tracefs"
            | "debugfs"
            | "securityfs"
            | "hugetlbfs"
            | "mqueue"
            | "fusectl"
            | "configfs"
            | "efivarfs"
            | "binfmt_misc"
            | "autofs"
            | "rpc_pipefs"
            | "nsfs"
            | "ramfs"
            | "squashfs"
    ) {
        return MountKind::Virtual;
    }
    MountKind::Physical
}

pub fn parse_proc_mounts(content: &str) -> Vec<MountInfo> {
    let mut out = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(dev_raw) = parts.next() else { continue };
        let Some(mp_raw) = parts.next() else { continue };
        let Some(ft_raw) = parts.next() else { continue };
        let device = unescape_mount_field(dev_raw);
        let mountpoint = unescape_mount_field(mp_raw);
        let fstype = unescape_mount_field(ft_raw);
        let kind = classify_mount(&device, &mountpoint, &fstype);
        let alert_eligible = kind == MountKind::Physical;
        out.push(MountInfo {
            device,
            mountpoint,
            fstype,
            kind,
            alert_eligible,
            total_bytes: None,
            free_bytes: None,
            used_percent: None,
        });
    }
    out
}

pub fn live_proc_mounts() -> Vec<MountInfo> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(raw) = std::fs::read_to_string("/proc/mounts") {
            let mut mounts = parse_proc_mounts(&raw);
            for m in &mut mounts {
                if m.kind == MountKind::Physical || m.kind == MountKind::Tmpfs {
                    if let Some((total, free)) = statvfs_bytes(Path::new(&m.mountpoint)) {
                        m.total_bytes = Some(total);
                        m.free_bytes = Some(free);
                        if total > 0 {
                            let used = total.saturating_sub(free);
                            m.used_percent = Some(((used.saturating_mul(100)) / total).min(100) as u8);
                        }
                    }
                }
            }
            return mounts;
        }
    }
    Vec::new()
}

pub fn is_active_mountpoint(path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(raw) = std::fs::read_to_string("/proc/mounts") else {
            return false;
        };
        let target_s = path.to_string_lossy();
        let canon_s = std::fs::canonicalize(path)
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        for m in parse_proc_mounts(&raw) {
            if m.mountpoint == target_s || canon_s.as_deref() == Some(m.mountpoint.as_str()) {
                return true;
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = path;
    false
}

#[cfg(unix)]
pub fn statvfs_bytes(path: &Path) -> Option<(u64, u64)> {
    use std::ffi::CString;
    let c_path = CString::new(path.to_string_lossy().as_bytes()).ok()?;
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut vfs) };
    if rc != 0 {
        return None;
    }
    let frsize = if vfs.f_frsize > 0 {
        vfs.f_frsize as u64
    } else {
        vfs.f_bsize as u64
    };
    let total = (vfs.f_blocks as u64).saturating_mul(frsize);
    let free = (vfs.f_bavail as u64).saturating_mul(frsize);
    Some((total, free))
}

#[cfg(not(unix))]
pub fn statvfs_bytes(_path: &Path) -> Option<(u64, u64)> {
    None
}

pub fn parse_human_size(raw: &str) -> u64 {
    let first = raw.split('(').next().unwrap_or(raw).trim();
    if first.is_empty() {
        return 0;
    }
    let split_idx = first
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(first.len());
    let num_str = first[..split_idx].trim();
    let unit = first[split_idx..].trim().to_ascii_lowercase();
    let Ok(val) = num_str.parse::<f64>() else {
        return 0;
    };
    if !val.is_finite() || val <= 0.0 {
        return 0;
    }
    let mult: f64 = match unit.as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1_000.0,
        "ki" | "kib" => 1024.0,
        "m" | "mb" => 1_000_000.0,
        "mi" | "mib" => (1024u64 * 1024) as f64,
        "g" | "gb" => 1_000_000_000.0,
        "gi" | "gib" => (1024u64 * 1024 * 1024) as f64,
        "t" | "tb" => 1_000_000_000_000.0,
        "ti" | "tib" => (1024u64 * 1024 * 1024 * 1024) as f64,
        _ => 1.0,
    };
    (val * mult).round() as u64
}

pub fn parse_docker_system_df(stdout: &str) -> DockerDfSummary {
    let mut summary = DockerDfSummary::default();
    let mut any = false;
    let ingest = |obj: &serde_json::Value, summary: &mut DockerDfSummary, any: &mut bool| {
        let Some(kind) = obj.get("Type").and_then(|v| v.as_str()) else {
            return;
        };
        *any = true;
        let size = obj
            .get("Size")
            .and_then(|v| v.as_str())
            .map(parse_human_size)
            .unwrap_or(0);
        let reclaimable = obj
            .get("Reclaimable")
            .and_then(|v| v.as_str())
            .map(parse_human_size)
            .unwrap_or(0);
        match kind.to_ascii_lowercase().as_str() {
            "images" => {
                summary.images_total_bytes = size;
                summary.images_reclaimable_bytes = reclaimable;
            }
            "containers" => {
                summary.containers_total_bytes = size;
                summary.containers_reclaimable_bytes = reclaimable;
            }
            "local volumes" | "volumes" => {
                summary.volumes_total_bytes = size;
                summary.volumes_reclaimable_bytes = reclaimable;
            }
            "build cache" => {
                summary.build_cache_total_bytes = size;
                summary.build_cache_reclaimable_bytes = reclaimable;
            }
            _ => {}
        }
    };

    let trimmed = stdout.trim();
    if trimmed.starts_with('[') {
        if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) {
            for obj in &arr {
                ingest(obj, &mut summary, &mut any);
            }
        }
    } else {
        for line in trimmed.lines() {
            if let Ok(obj) = serde_json::from_str::<serde_json::Value>(line.trim()) {
                ingest(&obj, &mut summary, &mut any);
            }
        }
    }
    summary.available = any;
    summary
}

pub fn parse_docker_containers(stdout: &str) -> Vec<ContainerInfo> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let id = obj
            .get("ID")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if id.is_empty() {
            continue;
        }
        let name = obj
            .get("Names")
            .and_then(|v| v.as_str())
            .unwrap_or(&id)
            .to_string();
        let image = obj
            .get("Image")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let status = obj
            .get("Status")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let state = obj
            .get("State")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let size_bytes = obj
            .get("Size")
            .and_then(|v| v.as_str())
            .map(parse_human_size)
            .unwrap_or(0);
        let unhealthy = status.to_ascii_lowercase().contains("unhealthy");
        out.push(ContainerInfo {
            runtime: "docker".to_string(),
            id,
            name,
            image,
            status,
            state,
            size_bytes,
            unhealthy,
        });
    }
    out
}

pub fn parse_docker_dangling_images(stdout: &str) -> Vec<DanglingImage> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let id = obj
            .get("ID")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if id.is_empty() {
            continue;
        }
        out.push(DanglingImage {
            id,
            repository: obj
                .get("Repository")
                .and_then(|v| v.as_str())
                .unwrap_or("<none>")
                .to_string(),
            tag: obj
                .get("Tag")
                .and_then(|v| v.as_str())
                .unwrap_or("<none>")
                .to_string(),
            size_bytes: obj
                .get("Size")
                .and_then(|v| v.as_str())
                .map(parse_human_size)
                .unwrap_or(0),
        });
    }
    out
}

pub fn parse_podman_ps(stdout: &str) -> Vec<ContainerInfo> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let items: Vec<serde_json::Value> = if trimmed.starts_with('[') {
        serde_json::from_str(trimmed).unwrap_or_default()
    } else {
        trimmed
            .lines()
            .filter_map(|l| serde_json::from_str(l.trim()).ok())
            .collect()
    };
    let mut out = Vec::new();
    for obj in items {
        let id = obj
            .get("Id")
            .or_else(|| obj.get("ID"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if id.is_empty() {
            continue;
        }
        let name = obj
            .get("Names")
            .and_then(|v| {
                v.as_array()
                    .and_then(|a| a.first().and_then(|x| x.as_str()))
                    .or_else(|| v.as_str())
            })
            .unwrap_or(&id)
            .to_string();
        let image = obj
            .get("Image")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let status = obj
            .get("Status")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let state = obj
            .get("State")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let size_bytes = obj
            .get("Size")
            .and_then(|v| v.as_str())
            .map(parse_human_size)
            .or_else(|| obj.get("Size").and_then(|v| v.as_u64()))
            .unwrap_or(0);
        let unhealthy = status.to_ascii_lowercase().contains("unhealthy");
        out.push(ContainerInfo {
            runtime: "podman".to_string(),
            id,
            name,
            image,
            status,
            state,
            size_bytes,
            unhealthy,
        });
    }
    out
}

pub fn parse_journald_disk_usage(stdout: &str) -> Option<u64> {
    // Example: "Archived and active journals take up 2.4G in the file system."
    for token in stdout.split_whitespace() {
        let trimmed = token.trim_end_matches(['.', ',', ';']);
        let bytes = trimmed.as_bytes();
        if bytes.len() >= 2
            && bytes[0].is_ascii_digit()
            && matches!(
                bytes[bytes.len() - 1].to_ascii_uppercase(),
                b'B' | b'K' | b'M' | b'G' | b'T'
            )
        {
            let suffix = bytes[bytes.len() - 1].to_ascii_uppercase();
            let num_part = &trimmed[..trimmed.len() - 1];
            if let Ok(val) = num_part.parse::<f64>() {
                if val.is_finite() && val >= 0.0 {
                    let mult = match suffix {
                        b'B' => 1.0,
                        b'K' => 1024.0,
                        b'M' => (1024u64 * 1024) as f64,
                        b'G' => (1024u64 * 1024 * 1024) as f64,
                        b'T' => (1024u64 * 1024 * 1024 * 1024) as f64,
                        _ => 1.0,
                    };
                    return Some((val * mult) as u64);
                }
            }
        }
    }
    None
}

pub fn parse_systemctl_failed(stdout: &str, scope: &str) -> Vec<SystemdUnitIssue> {
    let mut out = Vec::new();
    for raw_line in stdout.lines() {
        let line = raw_line.trim().trim_start_matches('●').trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(unit) = parts.next() else { continue };
        let Some(load) = parts.next() else { continue };
        let Some(active) = parts.next() else { continue };
        let Some(sub) = parts.next() else { continue };
        let description = parts.collect::<Vec<_>>().join(" ");
        let low_unit = unit.to_ascii_lowercase();
        let low_desc = description.to_ascii_lowercase();
        let is_podman_healthcheck = (low_unit.contains("podman") || low_unit.contains("libpod"))
            && (low_unit.contains("healthcheck") || low_desc.contains("healthcheck"))
            || low_unit.contains("healthcheck") && low_desc.contains("conmon");
        out.push(SystemdUnitIssue {
            unit: unit.to_string(),
            scope: scope.to_string(),
            load: load.to_string(),
            active: active.to_string(),
            sub: sub.to_string(),
            description,
            is_podman_healthcheck,
        });
    }
    out
}

pub fn parse_proc_meminfo(content: &str) -> LinuxMemInfo {
    let mut total = 0u64;
    let mut available = None;
    let mut free = 0u64;
    let mut buffers = 0u64;
    let mut cached = 0u64;
    let mut swap_total = 0u64;
    let mut swap_free = 0u64;

    for line in content.lines() {
        let Some((k, rest)) = line.split_once(':') else {
            continue;
        };
        let kb = rest
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let bytes = kb.saturating_mul(1024);
        match k.trim() {
            "MemTotal" => total = bytes,
            "MemAvailable" => available = Some(bytes),
            "MemFree" => free = bytes,
            "Buffers" => buffers = bytes,
            "Cached" => cached = bytes,
            "SwapTotal" => swap_total = bytes,
            "SwapFree" => swap_free = bytes,
            _ => {}
        }
    }
    let avail = available.unwrap_or_else(|| free.saturating_add(buffers).saturating_add(cached));
    LinuxMemInfo {
        total_bytes: total,
        available_bytes: avail.min(total),
        free_bytes: free,
        swap_total_bytes: swap_total,
        swap_used_bytes: swap_total.saturating_sub(swap_free),
    }
}

pub fn parse_proc_status_vm_swap(content: &str) -> u64 {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("VmSwap:") {
            let kb = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            return kb.saturating_mul(1024);
        }
    }
    0
}

pub fn allowed_linux_cache_roots(home_dir: &Path) -> Vec<PathBuf> {
    [
        ".cache/pip",
        ".cache/uv",
        ".cache/yarn",
        ".cache/pnpm",
        ".cache/go-build",
        ".cache/pipenv",
        ".npm/_cacache",
        ".cargo/registry/cache",
        ".gradle/caches",
    ]
    .iter()
    .map(|rel| home_dir.join(rel))
    .collect()
}

pub fn allowed_tmp_roots() -> Vec<PathBuf> {
    vec![PathBuf::from("/tmp")]
}

fn dir_size_bounded_no_follow(path: &Path, max_depth: usize) -> u64 {
    let mut sum = 0u64;
    for entry_res in WalkDir::new(path)
        .follow_links(false)
        .skip_hidden(false)
        .max_depth(max_depth)
    {
        let Ok(entry) = entry_res else {
            continue;
        };
        if entry.file_type().is_symlink() || !entry.file_type().is_file() {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            sum = sum.saturating_add(meta.len());
        }
    }
    sum
}

fn path_age_days(meta: &std::fs::Metadata) -> (u64, u64) {
    let Ok(mtime) = meta.modified() else {
        return (0, 0);
    };
    let Ok(elapsed) = SystemTime::now().duration_since(mtime) else {
        return (0, 0);
    };
    let secs = elapsed.as_secs();
    (secs, secs / 86_400)
}

fn run_cmd_capture(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn build_container_audit(
    runtime: &str,
    df_raw: &str,
    ps_raw: &str,
    images_raw: &str,
) -> ContainerRuntimeAudit {
    let df = parse_docker_system_df(df_raw);
    let containers = if runtime == "podman" {
        parse_podman_ps(ps_raw)
    } else {
        parse_docker_containers(ps_raw)
    };
    let dangling_images = parse_docker_dangling_images(images_raw);
    let available = df.available || !containers.is_empty() || !dangling_images.is_empty();
    let exited_containers = containers
        .iter()
        .filter(|c| c.is_reclaimable_stopped())
        .cloned()
        .collect();
    let unhealthy_containers = containers
        .iter()
        .filter(|c| c.unhealthy && !c.is_reclaimable_stopped())
        .cloned()
        .collect();
    ContainerRuntimeAudit {
        available,
        df,
        exited_containers,
        unhealthy_containers,
        dangling_images,
    }
}

fn discover_user_caches(home_dir: &Path, ctx: &ProtectionContext) -> Vec<PathArtifact> {
    let mut out = Vec::new();
    for root in allowed_linux_cache_roots(home_dir) {
        if !root.exists() {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(&root) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if check_path_protection_anchored(&root, ctx).protected {
            continue;
        }
        if meta.is_dir() && check_dir_descendants_safe(&root, ctx, 50_000).protected {
            continue;
        }
        let bytes = dir_size_bounded_no_follow(&root, 4);
        let (_, age_days) = path_age_days(&meta);
        out.push(PathArtifact {
            path: root.to_string_lossy().into_owned(),
            bytes,
            kind: "linux_user_cache".to_string(),
            age_days,
            manual_review_only: false,
            reason: "rebuildable_package_cache".to_string(),
        });
    }
    out.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    out
}

fn discover_apt_archives_bytes(apt_dir: &Path) -> u64 {
    if !apt_dir.is_dir() {
        return 0;
    }
    let mut sum = 0u64;
    let Ok(rd) = std::fs::read_dir(apt_dir) else {
        return 0;
    };
    for ent in rd.flatten() {
        let p = ent.path();
        let Ok(meta) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            continue;
        }
        if p.extension().and_then(|e| e.to_str()) == Some("deb") {
            sum = sum.saturating_add(meta.len());
        }
    }
    sum
}

fn is_protected_tmp_system_name(name: &str) -> bool {
    name.starts_with(".X11")
        || name.starts_with(".ICE")
        || name.starts_with("systemd-private-")
        || name.starts_with("ssh-")
        || name.starts_with("tmux-")
        || name.starts_with("orbit-")
        || name == ".font-unix"
        || name == ".XIM-unix"
}

const MAX_TMP_INSPECT_ENTRIES: usize = 100_000;

fn effective_min_age_secs(path: &Path, root_meta: &std::fs::Metadata) -> Option<(u64, u64)> {
    let (mut min_age_secs, _) = path_age_days(root_meta);
    if !root_meta.is_dir() {
        return Some((min_age_secs, min_age_secs / 86_400));
    }
    let mut seen: usize = 0;
    for entry_res in WalkDir::new(path).follow_links(false).skip_hidden(false) {
        let Ok(entry) = entry_res else {
            return None;
        };
        if entry.read_children_error.is_some() {
            return None;
        }
        if entry.depth == 0 {
            continue;
        }
        seen += 1;
        if seen > MAX_TMP_INSPECT_ENTRIES {
            return None;
        }
        if entry.file_type().is_symlink() {
            return None;
        }
        let Ok(meta) = entry.metadata() else {
            return None;
        };
        let (age_secs, _) = path_age_days(&meta);
        if age_secs < min_age_secs {
            min_age_secs = age_secs;
        }
    }
    Some((min_age_secs, min_age_secs / 86_400))
}

fn discover_stale_tmp(
    tmp_dir: &Path,
    active_mountpoints: &HashSet<String>,
    ctx: &ProtectionContext,
    stale_age_secs: u64,
) -> Vec<PathArtifact> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(tmp_dir) else {
        return out;
    };
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if is_protected_tmp_system_name(&name) {
            continue;
        }
        let p = ent.path();
        let p_str = p.to_string_lossy().into_owned();
        if active_mountpoints.contains(&p_str) {
            continue;
        }
        if let Ok(canon) = std::fs::canonicalize(&p) {
            if active_mountpoints.contains(canon.to_string_lossy().as_ref()) {
                continue;
            }
        }
        let Ok(meta) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            let ft = meta.file_type();
            if ft.is_socket() || ft.is_fifo() || ft.is_block_device() || ft.is_char_device() {
                continue;
            }
        }
        let Some((age_secs, age_days)) = effective_min_age_secs(&p, &meta) else {
            continue;
        };
        if age_secs < stale_age_secs {
            continue;
        }
        if check_path_protection_anchored(&p, ctx).protected {
            continue;
        }
        if meta.is_dir() && check_dir_descendants_safe(&p, ctx, 50_000).protected {
            continue;
        }
        let is_stale_mount_dir = name.starts_with(".mount_");
        if !is_stale_mount_dir && stale_age_secs == 0 && !name.starts_with("sj-") {
            // In zero-threshold fixture mode, focus on .mount_* unless aged
            continue;
        }
        let bytes = if meta.is_dir() {
            dir_size_bounded_no_follow(&p, 3)
        } else {
            meta.len()
        };
        out.push(PathArtifact {
            path: p_str,
            bytes,
            kind: "stale_tmp_entry".to_string(),
            age_days,
            manual_review_only: false,
            reason: if is_stale_mount_dir {
                "stale_unmounted_appimage_dir".to_string()
            } else {
                "stale_tmp_artifact".to_string()
            },
        });
    }
    out.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    out
}

fn discover_model_caches(home_dir: &Path) -> Vec<PathArtifact> {
    let mut roots: Vec<PathBuf> = vec![
        home_dir.join(".cache/huggingface/hub"),
        home_dir.join(".ollama/models"),
        home_dir.join(".cache/torch/hub"),
        home_dir.join(".cache/vllm"),
        home_dir.join(".cache/lm-studio/models"),
    ];
    if let Some(hf) = std::env::var_os("HF_HOME").filter(|v| !v.is_empty()) {
        roots.push(PathBuf::from(hf));
    }
    if let Some(ollama) = std::env::var_os("OLLAMA_MODELS").filter(|v| !v.is_empty()) {
        roots.push(PathBuf::from(ollama));
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for p in roots {
        if !p.exists() || !seen.insert(p.clone()) {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let bytes = if meta.is_dir() {
            dir_size_bounded_no_follow(&p, 4)
        } else {
            meta.len()
        };
        let (_, age_days) = path_age_days(&meta);
        out.push(PathArtifact {
            path: p.to_string_lossy().into_owned(),
            bytes,
            kind: "model_cache".to_string(),
            age_days,
            manual_review_only: true,
            reason: "manual_review_only:model_cache".to_string(),
        });
    }
    out.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    out
}

fn discover_old_backups(home_dir: &Path, min_age_secs: u64) -> Vec<PathArtifact> {
    let mut out = Vec::new();
    for rel in ["backups", "backup", ".local/share/backups"] {
        let dir = home_dir.join(rel);
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let p = ent.path();
            let Ok(meta) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            let (age_secs, age_days) = path_age_days(&meta);
            if age_secs < min_age_secs {
                continue;
            }
            let bytes = if meta.is_dir() {
                dir_size_bounded_no_follow(&p, 3)
            } else {
                meta.len()
            };
            out.push(PathArtifact {
                path: p.to_string_lossy().into_owned(),
                bytes,
                kind: "old_backup".to_string(),
                age_days,
                manual_review_only: true,
                reason: "manual_review_only:old_backup".to_string(),
            });
        }
    }
    out.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    out
}

pub fn discover_linux_audit_from_fixtures(fx: LinuxFixtures) -> LinuxAuditReport {
    let ctx = ProtectionContext::new(fx.home_dir.clone(), vec![]);
    let mounts = parse_proc_mounts(&fx.mounts_raw);
    let appimage_mounts: Vec<MountInfo> = mounts
        .iter()
        .filter(|m| m.kind == MountKind::AppImage)
        .cloned()
        .collect();
    let active_mountpoints: HashSet<String> =
        mounts.iter().map(|m| m.mountpoint.clone()).collect();

    let docker = build_container_audit(
        "docker",
        &fx.docker_df_raw,
        &fx.docker_ps_raw,
        &fx.docker_images_raw,
    );
    let podman = build_container_audit("podman", &fx.podman_df_raw, &fx.podman_ps_raw, "");
    let journald_bytes = parse_journald_disk_usage(&fx.journald_usage_raw);
    let journald = JournaldAudit {
        available: journald_bytes.is_some(),
        bytes: journald_bytes.unwrap_or(0),
        vacuum_target: "500M".to_string(),
    };
    let apt_path = fx
        .apt_archives_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("/var/cache/apt/archives"));
    let apt_archives_bytes = discover_apt_archives_bytes(&apt_path);
    let user_caches = discover_user_caches(&fx.home_dir, &ctx);
    let stale_tmp_entries =
        discover_stale_tmp(&fx.tmp_dir, &active_mountpoints, &ctx, fx.stale_age_secs);
    let model_caches = discover_model_caches(&fx.home_dir);
    let old_backups = discover_old_backups(&fx.home_dir, fx.stale_age_secs);

    let system_failed = parse_systemctl_failed(&fx.systemctl_system_raw, "system");
    let user_failed = parse_systemctl_failed(&fx.systemctl_user_raw, "user");
    let podman_healthcheck_issues: Vec<SystemdUnitIssue> = user_failed
        .iter()
        .filter(|u| u.is_podman_healthcheck)
        .cloned()
        .collect();

    LinuxAuditReport {
        schema: SCHEMA_LINUX_AUDIT_V1.to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        mounts,
        appimage_mounts,
        docker,
        podman,
        journald,
        package_caches: PackageCachesAudit {
            apt_archives_path: apt_path.to_string_lossy().into_owned(),
            apt_archives_bytes,
            user_caches,
        },
        stale_tmp_entries,
        model_caches,
        old_backups,
        systemd: SystemdAudit {
            available: !fx.systemctl_system_raw.is_empty() || !fx.systemctl_user_raw.is_empty(),
            user_bus_available: !fx.systemctl_user_raw.is_empty(),
            system_failed,
            user_failed,
            podman_healthcheck_issues,
        },
    }
}

pub fn discover_linux_audit(home_dir: &Path, tmp_dir: Option<&Path>) -> LinuxAuditReport {
    let ctx = ProtectionContext::new(home_dir.to_path_buf(), vec![]);
    let mounts = live_proc_mounts();
    let appimage_mounts: Vec<MountInfo> = mounts
        .iter()
        .filter(|m| m.kind == MountKind::AppImage)
        .cloned()
        .collect();
    let active_mountpoints: HashSet<String> =
        mounts.iter().map(|m| m.mountpoint.clone()).collect();

    let docker_df_raw = run_cmd_capture("docker", &["system", "df", "--format", "{{json .}}"])
        .unwrap_or_default();
    let docker_ps_raw =
        run_cmd_capture("docker", &["ps", "-a", "--format", "{{json .}}"]).unwrap_or_default();
    let docker_images_raw = run_cmd_capture(
        "docker",
        &["images", "--filter", "dangling=true", "--format", "{{json .}}"],
    )
    .unwrap_or_default();
    let docker = build_container_audit("docker", &docker_df_raw, &docker_ps_raw, &docker_images_raw);

    let podman_df_raw =
        run_cmd_capture("podman", &["system", "df", "--format", "json"]).unwrap_or_default();
    let podman_ps_raw =
        run_cmd_capture("podman", &["ps", "-a", "--format", "json"]).unwrap_or_default();
    let podman = build_container_audit("podman", &podman_df_raw, &podman_ps_raw, "");

    let journald_raw = if cfg!(target_os = "linux") {
        run_cmd_capture("journalctl", &["--disk-usage"]).unwrap_or_default()
    } else {
        String::new()
    };
    let journald_bytes = parse_journald_disk_usage(&journald_raw);
    let journald = JournaldAudit {
        available: journald_bytes.is_some(),
        bytes: journald_bytes.unwrap_or(0),
        vacuum_target: "500M".to_string(),
    };

    let apt_path = PathBuf::from("/var/cache/apt/archives");
    let apt_archives_bytes = if cfg!(target_os = "linux") {
        discover_apt_archives_bytes(&apt_path)
    } else {
        0
    };
    let user_caches = discover_user_caches(home_dir, &ctx);
    let effective_tmp = tmp_dir.unwrap_or_else(|| Path::new("/tmp"));
    let stale_tmp_entries = if cfg!(target_os = "linux") || tmp_dir.is_some() {
        discover_stale_tmp(
            effective_tmp,
            &active_mountpoints,
            &ctx,
            DEFAULT_STALE_TMP_SECS,
        )
    } else {
        Vec::new()
    };
    let model_caches = discover_model_caches(home_dir);
    let old_backups = discover_old_backups(home_dir, DEFAULT_BACKUP_AGE_SECS);
    let systemd = collect_systemd_audit();

    LinuxAuditReport {
        schema: SCHEMA_LINUX_AUDIT_V1.to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        mounts,
        appimage_mounts,
        docker,
        podman,
        journald,
        package_caches: PackageCachesAudit {
            apt_archives_path: apt_path.to_string_lossy().into_owned(),
            apt_archives_bytes,
            user_caches,
        },
        stale_tmp_entries,
        model_caches,
        old_backups,
        systemd,
    }
}

pub fn collect_systemd_audit() -> SystemdAudit {
    #[cfg(not(target_os = "linux"))]
    {
        SystemdAudit::default()
    }
    #[cfg(target_os = "linux")]
    {
        let sys_out = Command::new("systemctl")
            .args(["--failed", "--no-legend", "--no-pager", "--plain"])
            .output()
            .ok();
        let available = sys_out.as_ref().is_some_and(|o| o.status.success());
        let system_failed = sys_out
            .filter(|o| o.status.success())
            .map(|o| parse_systemctl_failed(&String::from_utf8_lossy(&o.stdout), "system"))
            .unwrap_or_default();

        let user_out = Command::new("systemctl")
            .args(["--user", "--failed", "--no-legend", "--no-pager", "--plain"])
            .output()
            .ok();
        let user_bus_available = user_out.as_ref().is_some_and(|o| o.status.success());
        let mut user_failed = user_out
            .filter(|o| o.status.success())
            .map(|o| parse_systemctl_failed(&String::from_utf8_lossy(&o.stdout), "user"))
            .unwrap_or_default();

        if user_bus_available {
            if let Ok(all_user) = Command::new("systemctl")
                .args([
                    "--user",
                    "list-units",
                    "--all",
                    "--type=service,timer",
                    "--no-legend",
                    "--no-pager",
                    "--plain",
                ])
                .output()
            {
                if all_user.status.success() {
                    let parsed =
                        parse_systemctl_failed(&String::from_utf8_lossy(&all_user.stdout), "user");
                    for u in parsed {
                        let sub = u.sub.to_ascii_lowercase();
                        let act = u.active.to_ascii_lowercase();
                        if u.is_podman_healthcheck
                            && (act == "failed" || sub == "auto-restart" || sub == "failed")
                            && !user_failed.iter().any(|e| e.unit == u.unit)
                        {
                            user_failed.push(u);
                        }
                    }
                }
            }
        }

        let podman_healthcheck_issues = user_failed
            .iter()
            .filter(|u| u.is_podman_healthcheck)
            .cloned()
            .collect();

        SystemdAudit {
            available,
            user_bus_available,
            system_failed,
            user_failed,
            podman_healthcheck_issues,
        }
    }
}

/// Check whether Linux command execution is permitted on the current host OS family.
/// Mirrors `safe_remove_plan_item_with_roots`: non-Unix platforms are dry-run only.
pub fn check_linux_command_platform_gate(is_unix: bool) -> Result<(), SjError> {
    if !is_unix {
        return Err(SjError::ExecutionGate(
            "safe execution is not supported on this platform; dry-run planning only".to_string(),
        ));
    }
    Ok(())
}

/// Execute an allowlisted, state-verified Linux maintenance command for a confirmed plan item.
/// Restricted to crate-internal plan execution so callers cannot bypass ExecutionGate/SelectionGate.
/// Never invokes a shell (`sh -c`). Re-verifies target identity and snapshot scope before mutating.
pub(crate) fn execute_linux_command_item(item: &crate::plan::PlanItem) -> Result<(), SjError> {
    check_linux_command_platform_gate(cfg!(unix))?;
    let kind = item.kind.as_str();
    let path = item.path.as_str();
    match kind {
        "docker_exited_container" => {
            let id = path
                .strip_prefix("docker://container/")
                .and_then(|rest| rest.split('/').next())
                .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                .ok_or_else(|| SjError::ExecutionGate(format!("invalid docker container ref: {path}")))?;
            let state = run_cmd_capture("docker", &["inspect", "-f", "{{.State.Status}}", id])
                .ok_or_else(|| SjError::ExecutionGate(format!("failed to re-verify docker container {id}")))?;
            let st = state.trim().to_ascii_lowercase();
            if !matches!(st.as_str(), "exited" | "created" | "dead") {
                return Err(SjError::ExecutionGate(format!(
                    "refusing docker container {id}: live state is '{st}', not exited/created/dead"
                )));
            }
            let out = Command::new("docker").args(["rm", id]).output()?;
            if !out.status.success() {
                return Err(SjError::ExecutionGate(format!(
                    "docker rm {id} failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }
            Ok(())
        }
        "docker_dangling_image" => {
            let id = path
                .strip_prefix("docker://image/")
                .filter(|s| {
                    !s.is_empty()
                        && s.chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '_' || c == '-')
                })
                .ok_or_else(|| SjError::ExecutionGate(format!("invalid docker image ref: {path}")))?;
            let dangling = run_cmd_capture(
                "docker",
                &["images", "--filter", "dangling=true", "--no-trunc", "--format", "{{.ID}}"],
            )
            .ok_or_else(|| SjError::ExecutionGate(format!("failed to re-verify dangling docker image {id}")))?;
            let short_dangling = run_cmd_capture(
                "docker",
                &["images", "--filter", "dangling=true", "--format", "{{.ID}}"],
            )
            .unwrap_or_default();
            let still_dangling = dangling
                .lines()
                .chain(short_dangling.lines())
                .any(|line| line.trim() == id);
            if !still_dangling {
                return Err(SjError::ExecutionGate(format!(
                    "docker image {id} is no longer dangling; regenerate plan and retry"
                )));
            }
            run_fixed_cmd("docker", &["rmi", id])
        }
        "docker_build_cache" => {
            // Build cache cannot be bound to individual object IDs; never auto-executed as bulk prune.
            Err(SjError::ExecutionGate(
                "docker_build_cache is manual_review_only; run `docker builder prune` manually".to_string(),
            ))
        }
        "podman_exited_container" => {
            let id = path
                .strip_prefix("podman://container/")
                .and_then(|rest| rest.split('/').next())
                .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                .ok_or_else(|| SjError::ExecutionGate(format!("invalid podman container ref: {path}")))?;
            let state = run_cmd_capture("podman", &["inspect", "-f", "{{.State.Status}}", id])
                .ok_or_else(|| SjError::ExecutionGate(format!("failed to re-verify podman container {id}")))?;
            let st = state.trim().to_ascii_lowercase();
            if !matches!(st.as_str(), "exited" | "created" | "dead") {
                return Err(SjError::ExecutionGate(format!(
                    "refusing podman container {id}: live state is '{st}', not exited/created/dead"
                )));
            }
            let out = Command::new("podman").args(["rm", id]).output()?;
            if !out.status.success() {
                return Err(SjError::ExecutionGate(format!(
                    "podman rm {id} failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }
            Ok(())
        }
        _ => Err(SjError::ExecutionGate(format!(
            "unsupported linux command plan item kind: {kind}"
        ))),
    }
}

fn run_fixed_cmd(cmd: &str, args: &[&str]) -> Result<(), SjError> {
    let out = Command::new(cmd).args(args).output()?;
    if !out.status.success() {
        return Err(SjError::ExecutionGate(format!(
            "{cmd} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

pub fn disk_status_for_bytes(free_bytes: u64, total_bytes: u64) -> &'static str {
    let free_gib = free_bytes / GIB;
    let by_gib = if free_gib < 20 {
        3
    } else if free_gib < 100 {
        2
    } else if free_gib < 150 {
        1
    } else {
        0
    };
    let by_pct = if total_bytes > 0 {
        let used_pct = ((total_bytes.saturating_sub(free_bytes)).saturating_mul(100)) / total_bytes;
        if used_pct >= 95 {
            3
        } else if used_pct >= 88 {
            2
        } else if used_pct >= 80 {
            1
        } else {
            0
        }
    } else {
        0
    };
    let rank = if total_bytes > 0 && total_bytes < 200 * GIB {
        by_pct
    } else {
        by_gib.max(by_pct)
    };
    match rank {
        3 => "CRITICAL",
        2 => "ALERT",
        1 => "CHECK",
        _ => "OK",
    }
}

#[allow(dead_code)]
fn _keep_duration_unused(_: Duration) {}
