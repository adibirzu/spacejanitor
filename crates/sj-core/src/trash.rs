use crate::protect::{
    check_dir_descendants_safe, check_path_protection, is_symlink_path, ProtectionContext,
};
use crate::{SjError, SCHEMA_TRASH_V1};
use jwalk::WalkDir;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrashItem {
    pub path: String,
    pub bytes: u64,
    pub protected: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrashReport {
    pub schema: String,
    pub trash_path: String,
    pub exists: bool,
    pub item_count: u64,
    pub total_bytes: u64,
    pub reclaimable_bytes: u64,
    pub items: Vec<TrashItem>,
    pub protected_items: Vec<TrashItem>,
}

pub fn default_trash_paths(home_dir: &Path) -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        vec![home_dir.join(".Trash")]
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            if !xdg.is_empty() {
                return vec![PathBuf::from(xdg).join("Trash").join("files")];
            }
        }
        vec![home_dir
            .join(".local")
            .join("share")
            .join("Trash")
            .join("files")]
    }
    #[cfg(target_os = "windows")]
    {
        let _ = home_dir;
        let drive = std::env::var_os("SystemDrive")
            .map(|d| d.to_string_lossy().into_owned())
            .unwrap_or_else(|| "C:".to_string());
        vec![PathBuf::from(format!("{drive}\\$Recycle.Bin"))]
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        vec![home_dir.join(".Trash")]
    }
}

fn dir_size_no_follow(path: &Path) -> u64 {
    let mut sum: u64 = 0;
    for entry_res in WalkDir::new(path).follow_links(false).skip_hidden(false) {
        let Ok(entry) = entry_res else {
            continue;
        };
        if entry.file_type().is_file() {
            if let Ok(meta) = entry.metadata() {
                sum = sum.saturating_add(meta.len());
            }
        }
    }
    sum
}

pub fn discover_trash_at(
    trash_path: &Path,
    ctx: &ProtectionContext,
) -> Result<TrashReport, SjError> {
    if !trash_path.exists() {
        return Ok(TrashReport {
            schema: SCHEMA_TRASH_V1.to_string(),
            trash_path: trash_path.to_string_lossy().into_owned(),
            exists: false,
            item_count: 0,
            total_bytes: 0,
            reclaimable_bytes: 0,
            items: Vec::new(),
            protected_items: Vec::new(),
        });
    }

    if is_symlink_path(trash_path)? {
        return Err(SjError::ProtectedPath(format!(
            "refusing symlink trash root: {}",
            trash_path.display()
        )));
    }

    let mut items = Vec::new();
    let mut protected_items = Vec::new();
    let mut item_count: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut reclaimable_bytes: u64 = 0;

    for entry_res in std::fs::read_dir(trash_path)? {
        let Ok(entry) = entry_res else {
            continue;
        };
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };

        let is_sym = meta.file_type().is_symlink();
        let bytes = if is_sym {
            0
        } else if meta.is_dir() {
            dir_size_no_follow(&path)
        } else {
            meta.len()
        };

        item_count += 1;
        total_bytes = total_bytes.saturating_add(bytes);

        let verdict = check_path_protection(&path, ctx);
        let desc_verdict = if !is_sym && !verdict.protected && meta.is_dir() {
            Some(check_dir_descendants_safe(&path, ctx, 100_000))
        } else {
            None
        };
        if is_sym || verdict.protected || desc_verdict.as_ref().is_some_and(|v| v.protected) {
            let reason = if is_sym {
                "symlink_in_trash".to_string()
            } else if verdict.protected {
                verdict.reason
            } else {
                desc_verdict
                    .map(|v| v.reason)
                    .unwrap_or_else(|| "protected_descendant".to_string())
            };
            protected_items.push(TrashItem {
                path: path.to_string_lossy().into_owned(),
                bytes,
                protected: true,
                reason: Some(reason),
            });
        } else {
            reclaimable_bytes = reclaimable_bytes.saturating_add(bytes);
            items.push(TrashItem {
                path: path.to_string_lossy().into_owned(),
                bytes,
                protected: false,
                reason: None,
            });
        }
    }

    items.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    protected_items.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));

    Ok(TrashReport {
        schema: SCHEMA_TRASH_V1.to_string(),
        trash_path: trash_path.to_string_lossy().into_owned(),
        exists: true,
        item_count,
        total_bytes,
        reclaimable_bytes,
        items,
        protected_items,
    })
}
