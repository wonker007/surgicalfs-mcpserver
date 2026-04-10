use crate::errors::{ErrorCode, SurgicalError, SurgicalResult};
use crate::pathguard::PathGuard;
use serde_json::json;
use std::fs;
use walkdir::WalkDir;

/// List directory contents with metadata.
pub fn directory_list(
    path_guard: &PathGuard,
    path: &str,
    depth: Option<u32>,
    globs: Option<Vec<String>>,
    show_hidden: Option<bool>,
    sort_by: Option<String>,
    respect_gitignore: bool,
    show_ignored: Option<bool>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    if !canonical.is_dir() {
        return Err(SurgicalError::new(
            ErrorCode::NotADirectory,
            format!("'{}' is not a directory.", path),
            "Provide a directory path.",
        ));
    }

    let depth = depth.unwrap_or(1) as usize;
    let show_hidden = show_hidden.unwrap_or(false);
    let sort_by = sort_by.unwrap_or_else(|| "name".to_string());
    let globs = globs.unwrap_or_default();
    let use_gitignore = respect_gitignore && !show_ignored.unwrap_or(false);

    let glob_patterns: Vec<glob::Pattern> = globs
        .iter()
        .filter_map(|g| glob::Pattern::new(g).ok())
        .collect();

    let mut entries: Vec<serde_json::Value> = Vec::new();
    let mut total_size = 0u64;

    // Collect directory entries, optionally filtering by .gitignore
    let walk_entries: Vec<(std::path::PathBuf, String, std::fs::Metadata)> = if use_gitignore {
        let walker = ignore::WalkBuilder::new(&canonical)
            .max_depth(Some(depth + 1)) // +1 because ignore walker counts root as depth 0
            .hidden(!show_hidden)
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true)
            .build();
        walker
            .filter_map(|e| e.ok())
            .filter(|e| e.path() != canonical)
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                e.metadata().ok().map(|m| (e.into_path(), name, m))
            })
            .collect()
    } else {
        WalkDir::new(&canonical)
            .min_depth(1)
            .max_depth(depth)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy();
                show_hidden || !name.starts_with('.')
            })
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                e.metadata().ok().map(|m| (e.into_path(), name, m))
            })
            .collect()
    };

    for (path, name, metadata) in walk_entries {
        // Skip hidden files unless requested (already handled for WalkDir path, but
        // the ignore walker handles it via .hidden() flag)
        if !use_gitignore && !show_hidden && name.starts_with('.') {
            continue;
        }

        // Apply glob filter
        if !glob_patterns.is_empty() {
            let matches = glob_patterns.iter().any(|p| p.matches(&name));
            if !matches {
                continue;
            }
        }

        let size = metadata.len();
        total_size += size;

        let entry_type = if metadata.is_dir() {
            "directory"
        } else if metadata.file_type().is_symlink() {
            "symlink"
        } else {
            "file"
        };

        let modified = metadata.modified().ok().map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.to_rfc3339()
        });

        entries.push(json!({
            "name": name,
            "path": path.display().to_string(),
            "type": entry_type,
            "size_bytes": size,
            "modified_iso": modified,
        }));
    }

    // Sort entries
    match sort_by.as_str() {
        "size" => entries.sort_by(|a, b| {
            let sa = a["size_bytes"].as_u64().unwrap_or(0);
            let sb = b["size_bytes"].as_u64().unwrap_or(0);
            sb.cmp(&sa)
        }),
        "modified" => entries.sort_by(|a, b| {
            let ma = a["modified_iso"].as_str().unwrap_or("");
            let mb = b["modified_iso"].as_str().unwrap_or("");
            mb.cmp(ma)
        }),
        _ => entries.sort_by(|a, b| {
            let na = a["name"].as_str().unwrap_or("");
            let nb = b["name"].as_str().unwrap_or("");
            na.cmp(nb)
        }),
    }

    let total_entries = entries.len();

    Ok(json!({
        "entries": entries,
        "total_entries": total_entries,
        "total_size_bytes": total_size,
    }))
}

/// Generate ASCII tree representation of a directory.
pub fn directory_tree(
    path_guard: &PathGuard,
    path: &str,
    depth: Option<u32>,
    globs: Option<Vec<String>>,
    show_hidden: Option<bool>,
    show_size: Option<bool>,
    respect_gitignore: bool,
    show_ignored: Option<bool>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    if !canonical.is_dir() {
        return Err(SurgicalError::new(
            ErrorCode::NotADirectory,
            format!("'{}' is not a directory.", path),
            "Provide a directory path.",
        ));
    }

    let depth = depth.unwrap_or(3) as usize;
    let show_hidden = show_hidden.unwrap_or(false);
    let show_size = show_size.unwrap_or(false);
    let use_gitignore = respect_gitignore && !show_ignored.unwrap_or(false);
    let globs = globs.unwrap_or_default();

    let glob_patterns: Vec<glob::Pattern> = globs
        .iter()
        .filter_map(|g| glob::Pattern::new(g).ok())
        .collect();

    // Build gitignore matcher if needed
    let gitignore = if use_gitignore {
        let (gi, _) = ignore::gitignore::Gitignore::new(canonical.join(".gitignore"));
        Some(gi)
    } else {
        None
    };

    let mut tree = String::new();
    let root_name = canonical
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| canonical.display().to_string());
    tree.push_str(&root_name);
    tree.push('\n');

    let mut total_files = 0u32;
    let mut total_dirs = 0u32;

    build_tree(
        &canonical,
        &mut tree,
        "",
        depth,
        show_hidden,
        show_size,
        &glob_patterns,
        &mut total_files,
        &mut total_dirs,
        0,
        gitignore.as_ref(),
    );

    Ok(json!({
        "tree": tree,
        "total_files": total_files,
        "total_dirs": total_dirs,
    }))
}

fn build_tree(
    dir: &std::path::Path,
    tree: &mut String,
    prefix: &str,
    max_depth: usize,
    show_hidden: bool,
    show_size: bool,
    glob_patterns: &[glob::Pattern],
    total_files: &mut u32,
    total_dirs: &mut u32,
    current_depth: usize,
    gitignore: Option<&ignore::gitignore::Gitignore>,
) {
    if current_depth >= max_depth {
        return;
    }

    let mut entries: Vec<_> = match fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
        Err(_) => return,
    };
    entries.sort_by_key(|e| e.file_name());

    // Filter
    let entries: Vec<_> = entries
        .into_iter()
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if !show_hidden && name.starts_with('.') {
                return false;
            }
            // Apply gitignore
            if let Some(gi) = gitignore {
                let is_dir = e.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
                if gi.matched(e.path(), is_dir).is_ignore() {
                    return false;
                }
            }
            if !glob_patterns.is_empty() {
                return glob_patterns.iter().any(|p| p.matches(&name))
                    || e.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
            }
            true
        })
        .collect();

    let count = entries.len();
    for (i, entry) in entries.iter().enumerate() {
        let is_last = i == count - 1;
        let connector = if is_last { "└── " } else { "├── " };
        let name = entry.file_name().to_string_lossy().to_string();

        let size_str = if show_size {
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    format!(" ({})", format_size(meta.len()))
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        tree.push_str(&format!("{}{}{}{}\n", prefix, connector, name, size_str));

        if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            *total_dirs += 1;
            let new_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
            build_tree(
                &entry.path(),
                tree,
                &new_prefix,
                max_depth,
                show_hidden,
                show_size,
                glob_patterns,
                total_files,
                total_dirs,
                current_depth + 1,
                gitignore,
            );
        } else {
            *total_files += 1;
        }
    }
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1_048_576 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else if bytes < 1_073_741_824 {
        format!("{:.1}MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{:.1}GB", bytes as f64 / 1_073_741_824.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_guard() -> PathGuard {
        PathGuard::new(
            &[std::env::temp_dir().to_string_lossy().to_string()],
            false,
            5_242_880,
        )
        .unwrap()
    }

    #[test]
    fn test_directory_list() {
        let guard = test_guard();
        let dir = std::env::temp_dir().join("surgicalfs_dirlist_test");
        fs::create_dir_all(&dir).ok();
        fs::write(dir.join("a.txt"), "a").ok();
        fs::write(dir.join("b.txt"), "b").ok();

        let result = directory_list(
            &guard,
            &dir.to_string_lossy(),
            Some(1),
            None,
            None,
            None,
            false,
            None,
        )
        .unwrap();
        assert!(result["total_entries"].as_u64().unwrap() >= 2);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_directory_tree() {
        let guard = test_guard();
        let dir = std::env::temp_dir().join("surgicalfs_tree_test");
        fs::create_dir_all(dir.join("sub")).ok();
        fs::write(dir.join("file.txt"), "test").ok();
        fs::write(dir.join("sub").join("nested.txt"), "nested").ok();

        let result = directory_tree(
            &guard,
            &dir.to_string_lossy(),
            Some(2),
            None,
            None,
            None,
            false,
            None,
        )
        .unwrap();
        let tree = result["tree"].as_str().unwrap();
        assert!(tree.contains("file.txt"));
        assert!(tree.contains("sub"));

        fs::remove_dir_all(&dir).ok();
    }
}
