use crate::protect::{check_path_protection, ProtectionContext};
use crate::{SjError, SCHEMA_STORAGE_V1};
use jwalk::WalkDir;
use serde::Serialize;
use std::collections::BTreeMap;
#[cfg(unix)]
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Ok,
    Check,
    Alert,
    Floor,
    Stop,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ScanThresholds {
    pub check_bytes: u64,
    pub alert_bytes: u64,
    pub floor_bytes: u64,
    pub stop_bytes: u64,
}

impl Default for ScanThresholds {
    fn default() -> Self {
        const GIB: u64 = 1024 * 1024 * 1024;
        Self {
            check_bytes: 10 * GIB,
            alert_bytes: 25 * GIB,
            floor_bytes: 50 * GIB,
            stop_bytes: 100 * GIB,
        }
    }
}

impl ScanThresholds {
    pub fn classify(&self, total_bytes: u64) -> ScanStatus {
        if total_bytes >= self.stop_bytes {
            ScanStatus::Stop
        } else if total_bytes >= self.floor_bytes {
            ScanStatus::Floor
        } else if total_bytes >= self.alert_bytes {
            ScanStatus::Alert
        } else if total_bytes >= self.check_bytes {
            ScanStatus::Check
        } else {
            ScanStatus::Ok
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub max_depth: usize,
    pub top_n: usize,
    pub same_filesystem: bool,
    pub thresholds: ScanThresholds,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_depth: 4,
            top_n: 20,
            same_filesystem: true,
            thresholds: ScanThresholds::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanEntry {
    pub path: String,
    pub bytes: u64,
    pub file_count: u64,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub schema: String,
    pub root: String,
    pub total_bytes: u64,
    pub file_count: u64,
    pub dir_count: u64,
    pub status: ScanStatus,
    pub entries: Vec<ScanEntry>,
    pub skipped_protected: Vec<String>,
}

pub fn scan_directory(
    root: &Path,
    ctx: &ProtectionContext,
    opts: &ScanOptions,
) -> Result<ScanReport, SjError> {
    if opts.max_depth == 0 {
        return Err(SjError::ExecutionGate("max_depth must be >= 1".to_string()));
    }

    let root_meta = std::fs::symlink_metadata(root)?;
    if root_meta.file_type().is_symlink() {
        return Err(SjError::ProtectedPath(format!(
            "refusing symlink scan root: {}",
            root.display()
        )));
    }

    let root_canon = std::fs::canonicalize(root)?;
    let home_canon = std::fs::canonicalize(&ctx.home_dir).ok();
    let is_home_root = home_canon
        .as_ref()
        .is_some_and(|hc| *hc == root_canon && hc != Path::new("/"));
    if !is_home_root {
        let verdict = check_path_protection(root, ctx);
        if verdict.protected {
            return Err(SjError::ProtectedPath(verdict.reason));
        }
    }

    #[cfg(unix)]
    let root_dev = root_meta.dev();

    let skipped_protected: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let skipped_clone = Arc::clone(&skipped_protected);
    let ctx_clone = ctx.clone();
    let same_fs = opts.same_filesystem;

    let mut top_agg: BTreeMap<String, (u64, u64, String)> = BTreeMap::new();
    let mut total_bytes: u64 = 0;
    let mut file_count: u64 = 0;
    let mut dir_count: u64 = 0;
    #[cfg(unix)]
    let mut seen_inodes: HashSet<(u64, u64)> = HashSet::new();

    let walker = WalkDir::new(root)
        .follow_links(false)
        .skip_hidden(false)
        .max_depth(opts.max_depth)
        .process_read_dir(move |depth, _path, _read_dir_state, children| {
            if depth.is_none() {
                return;
            }
            children.retain(|res| {
                let Ok(entry) = res else {
                    return false;
                };
                if entry.file_type().is_symlink() {
                    return false;
                }
                let p = entry.path();
                let verdict = check_path_protection(&p, &ctx_clone);
                if verdict.protected {
                    if let Ok(mut guard) = skipped_clone.lock() {
                        guard.push(p.to_string_lossy().into_owned());
                    }
                    return false;
                }
                #[cfg(unix)]
                if same_fs {
                    if let Ok(m) = entry.metadata() {
                        if m.dev() != root_dev {
                            return false;
                        }
                    }
                }
                let _ = same_fs;
                true
            });
        });

    for entry_res in walker {
        let Ok(entry) = entry_res else {
            continue;
        };
        if entry.depth == 0 {
            continue;
        }
        let path = entry.path();
        if entry.file_type().is_dir() {
            dir_count += 1;
            if entry.depth == 1 {
                let key = path.to_string_lossy().into_owned();
                top_agg.entry(key).or_insert((0, 0, "dir".to_string()));
            }
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };

        #[cfg(unix)]
        if meta.nlink() > 1 && !seen_inodes.insert((meta.dev(), meta.ino())) {
            continue;
        }

        let len = meta.len();
        total_bytes = total_bytes.saturating_add(len);
        file_count += 1;

        if let Ok(rel) = path.strip_prefix(root) {
            if let Some(first) = rel.components().next() {
                let top_path = root.join(first.as_os_str());
                let key = top_path.to_string_lossy().into_owned();
                let kind = if entry.depth == 1 { "file" } else { "dir" };
                let rec = top_agg.entry(key).or_insert((0, 0, kind.to_string()));
                rec.0 = rec.0.saturating_add(len);
                rec.1 += 1;
            }
        }
    }

    let mut entries: Vec<ScanEntry> = top_agg
        .into_iter()
        .map(|(path, (bytes, files, kind))| ScanEntry {
            path,
            bytes,
            file_count: files,
            kind,
        })
        .collect();

    entries.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    entries.truncate(opts.top_n);

    let mut skipped = skipped_protected
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    skipped.sort();
    skipped.dedup();

    Ok(ScanReport {
        schema: SCHEMA_STORAGE_V1.to_string(),
        root: root.to_string_lossy().into_owned(),
        total_bytes,
        file_count,
        dir_count,
        status: opts.thresholds.classify(total_bytes),
        entries,
        skipped_protected: skipped,
    })
}
