//! Collect `.rs` files from a path (file or directory), skipping build output.

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub fn collect_rs_files(root: &Path) -> Vec<PathBuf> {
    if root.is_file() {
        return if is_rs(root) {
            vec![root.to_path_buf()]
        } else {
            vec![]
        };
    }

    WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| !is_skipped_dir(e.path()))
        .filter_map(|e| e.ok())
        .map(|e| e.into_path())
        .filter(|p| is_rs(p))
        .collect()
}

fn is_rs(p: &Path) -> bool {
    p.extension().map(|e| e == "rs").unwrap_or(false)
}

fn is_skipped_dir(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n == "target" || n == ".git" || n == "node_modules")
        .unwrap_or(false)
}
