//! Backwards-compatible tool wrappers matching the default
//! @modelcontextprotocol/server-filesystem tool names and schemas.

use crate::config::Config;
use crate::encoding;
use crate::errors::{ErrorCode, SurgicalError, SurgicalResult};
use crate::pathguard::PathGuard;
use serde_json::json;
use std::fs;
use walkdir::WalkDir;

/// Read the complete contents of a file (default server: `read_file`).
pub fn read_file(
    path_guard: &PathGuard,
    config: &Config,
    path: &str,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let bytes = fs::read(&canonical).map_err(|e| SurgicalError::io_error(&e, "Read failed"))?;
    if encoding::is_binary(&bytes) {
        return Err(SurgicalError::binary_file(path));
    }
    let (text, _enc) = encoding::decode_bytes(&bytes, &config.defaults.encoding)?;

    Ok(json!(text))
}

/// Read a text file with optional offset/length/head/tail (default server: `read_text_file`).
pub fn read_text_file(
    path_guard: &PathGuard,
    config: &Config,
    path: &str,
    offset: Option<u64>,
    length: Option<u64>,
    head: Option<u32>,
    tail: Option<u32>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let bytes = fs::read(&canonical).map_err(|e| SurgicalError::io_error(&e, "Read failed"))?;
    if encoding::is_binary(&bytes) {
        return Err(SurgicalError::binary_file(path));
    }
    let (text, _enc) = encoding::decode_bytes(&bytes, &config.defaults.encoding)?;

    // If head is set, return first N lines
    if let Some(n) = head {
        let lines: Vec<&str> = text.lines().take(n as usize).collect();
        return Ok(json!(lines.join("\n")));
    }

    // If tail is set, return last N lines
    if let Some(n) = tail {
        let all_lines: Vec<&str> = text.lines().collect();
        let start = all_lines.len().saturating_sub(n as usize);
        let lines: Vec<&str> = all_lines[start..].to_vec();
        return Ok(json!(lines.join("\n")));
    }

    // If offset/length provided, byte-range read (ensure char-boundary safety)
    if offset.is_some() || length.is_some() {
        let off = offset.unwrap_or(0) as usize;
        let len = length.unwrap_or(text.len() as u64) as usize;
        let end = (off + len).min(text.len());
        if off < text.len() {
            // Adjust to valid char boundaries
            let safe_off = if text.is_char_boundary(off) {
                off
            } else {
                text.char_indices()
                    .map(|(i, _)| i)
                    .find(|&i| i >= off)
                    .unwrap_or(text.len())
            };
            let safe_end = if text.is_char_boundary(end) {
                end
            } else {
                text[..end]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(safe_off)
            };
            return Ok(json!(&text[safe_off..safe_end]));
        } else {
            return Ok(json!(""));
        }
    }

    Ok(json!(text))
}

/// Read a binary media file and return base64-encoded data (default server: `read_media_file`).
pub fn read_media_file(path_guard: &PathGuard, path: &str) -> SurgicalResult<serde_json::Value> {
    use base64::Engine;

    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let ext = canonical
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let mime_type = match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "svg" => "image/svg+xml",
        _ => {
            return Err(SurgicalError::new(
                ErrorCode::BinaryFile,
                format!("Unsupported media format '.{}'", ext),
                "Supported formats: PNG, JPEG, GIF, WebP, BMP, SVG.",
            ));
        }
    };

    let bytes = fs::read(&canonical).map_err(|e| SurgicalError::io_error(&e, "Read failed"))?;
    let size = bytes.len();
    let data_base64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

    Ok(json!({
        "path": canonical.display().to_string(),
        "mime_type": mime_type,
        "data_base64": data_base64,
        "size_bytes": size,
    }))
}

/// Read multiple files in a single call (default server: `read_multiple_files`).
pub fn read_multiple_files(
    path_guard: &PathGuard,
    config: &Config,
    paths: Vec<String>,
) -> SurgicalResult<serde_json::Value> {
    let mut files = Vec::new();

    for p in &paths {
        match read_file_entry(path_guard, config, p) {
            Ok(content) => {
                files.push(json!({
                    "path": p,
                    "content": content,
                }));
            }
            Err(e) => {
                files.push(json!({
                    "path": p,
                    "error": e.0.message,
                }));
            }
        }
    }

    Ok(json!({ "files": files }))
}

fn read_file_entry(
    path_guard: &PathGuard,
    config: &Config,
    path: &str,
) -> Result<String, SurgicalError> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let bytes = fs::read(&canonical).map_err(|e| SurgicalError::io_error(&e, "Read failed"))?;
    if encoding::is_binary(&bytes) {
        return Err(SurgicalError::binary_file(path));
    }
    let (text, _enc) = encoding::decode_bytes(&bytes, &config.defaults.encoding)?;
    Ok(text)
}

/// Create a directory (default server: `create_directory`).
pub fn create_directory(path_guard: &PathGuard, path: &str) -> SurgicalResult<serde_json::Value> {
    // For directories that may not exist yet, find the closest existing ancestor
    // and validate that it's within the allowlist.
    let target = std::path::Path::new(path);

    // If the directory already exists, validate it directly
    if target.exists() {
        let canonical = path_guard.validate(path)?;
        return Ok(json!({
            "created": true,
            "path": canonical.display().to_string(),
        }));
    }

    // Walk up to find the closest existing ancestor
    let mut ancestor = target.to_path_buf();
    while !ancestor.exists() {
        if let Some(parent) = ancestor.parent() {
            ancestor = parent.to_path_buf();
        } else {
            return Err(SurgicalError::new(
                ErrorCode::FileNotFound,
                format!("No existing ancestor directory found for '{}'", path),
                "Provide a path under an existing directory.",
            ));
        }
    }

    // Validate the existing ancestor is in the allowlist
    path_guard.validate(&ancestor.to_string_lossy())?;

    // Build the full target path under the canonical ancestor
    let canonical_ancestor = dunce::canonicalize(&ancestor)
        .map_err(|e| SurgicalError::io_error(&e, "Cannot canonicalize ancestor"))?;

    // Compute the remaining relative path
    let remaining = target.strip_prefix(&ancestor).unwrap_or(target);
    let full_path = canonical_ancestor.join(remaining);

    fs::create_dir_all(&full_path)
        .map_err(|e| SurgicalError::io_error(&e, "Create directory failed"))?;

    Ok(json!({
        "created": true,
        "path": full_path.display().to_string(),
    }))
}

/// List allowed directories from config (default server: `list_allowed_directories`).
pub fn list_allowed_directories(allowed: &[String]) -> serde_json::Value {
    json!({
        "allowed_directories": allowed,
    })
}

/// Write a file (default server: `write_file` — always overwrites).
pub fn write_file(
    path_guard: &PathGuard,
    path: &str,
    content: &str,
) -> SurgicalResult<serde_json::Value> {
    crate::tools::manage::file_write(path_guard, path, content, Some(true))
}

/// Edit a file using oldText/newText pairs (default server: `edit_file`).
/// Returns a unified diff string.
pub fn edit_file(
    path_guard: &PathGuard,
    config: &Config,
    path: &str,
    edits: Vec<serde_json::Value>,
    dry_run: Option<bool>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let bytes = fs::read(&canonical).map_err(|e| SurgicalError::io_error(&e, "Read failed"))?;
    if encoding::is_binary(&bytes) {
        return Err(SurgicalError::binary_file(path));
    }
    let (original_text, _enc) = encoding::decode_bytes(&bytes, &config.defaults.encoding)?;

    // Apply edits sequentially
    let mut text = original_text.clone();
    for edit in &edits {
        let old_text = edit["oldText"].as_str().unwrap_or("");
        let new_text = edit["newText"].as_str().unwrap_or("");
        if !old_text.is_empty() {
            text = text.replacen(old_text, new_text, 1);
        }
    }

    // Generate unified diff
    let diff = generate_unified_diff(path, &original_text, &text);

    if !dry_run.unwrap_or(false) {
        fs::write(&canonical, &text).map_err(|e| SurgicalError::io_error(&e, "Write failed"))?;
    }

    Ok(json!(diff))
}

/// List directory entries in "[FILE] name" / "[DIR] name" format.
pub fn list_directory(path_guard: &PathGuard, path: &str) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    if !canonical.is_dir() {
        return Err(SurgicalError::new(
            ErrorCode::NotADirectory,
            format!("'{}' is not a directory.", path),
            "Provide a directory path.",
        ));
    }

    let mut entries: Vec<String> = Vec::new();
    for entry in fs::read_dir(&canonical)
        .map_err(|e| SurgicalError::io_error(&e, "Read dir failed"))?
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().to_string();
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => match fs::metadata(entry.path()) {
                Ok(m) => m.file_type(),
                Err(_) => continue,
            },
        };
        if ft.is_dir() {
            entries.push(format!("[DIR] {}", name));
        } else {
            entries.push(format!("[FILE] {}", name));
        }
    }
    entries.sort();

    Ok(json!(entries.join("\n")))
}

/// List directory entries with sizes.
pub fn list_directory_with_sizes(
    path_guard: &PathGuard,
    path: &str,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    if !canonical.is_dir() {
        return Err(SurgicalError::new(
            ErrorCode::NotADirectory,
            format!("'{}' is not a directory.", path),
            "Provide a directory path.",
        ));
    }

    let mut entries: Vec<String> = Vec::new();
    for entry in fs::read_dir(&canonical)
        .map_err(|e| SurgicalError::io_error(&e, "Read dir failed"))?
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().to_string();
        let meta = entry.metadata().ok();
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => match fs::metadata(entry.path()) {
                Ok(m) => m.file_type(),
                Err(_) => continue,
            },
        };
        if ft.is_dir() {
            entries.push(format!("[DIR] {}", name));
        } else {
            let size = meta.map(|m| m.len()).unwrap_or(0);
            entries.push(format!("[FILE] {} ({})", name, format_size(size)));
        }
    }
    entries.sort();

    Ok(json!(entries.join("\n")))
}

/// directory_tree returning JSON tree structure (default server format).
pub fn directory_tree_json(
    path_guard: &PathGuard,
    path: &str,
    depth: Option<u32>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    if !canonical.is_dir() {
        return Err(SurgicalError::new(
            ErrorCode::NotADirectory,
            format!("'{}' is not a directory.", path),
            "Provide a directory path.",
        ));
    }

    let max_depth = depth.unwrap_or(3) as usize;
    let tree = build_json_tree(&canonical, 0, max_depth);

    Ok(tree)
}

fn build_json_tree(
    path: &std::path::Path,
    current_depth: usize,
    max_depth: usize,
) -> serde_json::Value {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string());

    if path.is_file() {
        return json!({
            "name": name,
            "type": "file",
        });
    }

    let mut children = Vec::new();
    if current_depth < max_depth {
        if let Ok(entries) = fs::read_dir(path) {
            let mut sorted: Vec<_> = entries.filter_map(|e| e.ok()).collect();
            sorted.sort_by_key(|e| e.file_name());
            for entry in sorted {
                children.push(build_json_tree(&entry.path(), current_depth + 1, max_depth));
            }
        }
    }

    json!({
        "name": name,
        "type": "directory",
        "children": children,
    })
}

/// Move a file (default server: `move_file` — overwrites by default).
pub fn move_file(
    path_guard: &PathGuard,
    source: &str,
    destination: &str,
) -> SurgicalResult<serde_json::Value> {
    crate::tools::manage::file_move(path_guard, source, destination, Some(true))
}

/// Search for files by glob pattern on filenames (default server: `search_files`).
/// This is NOT content search — it matches filenames.
pub fn search_files(
    path_guard: &PathGuard,
    path: &str,
    pattern: &str,
    exclude_patterns: Option<Vec<String>>,
    max_results: Option<u32>,
    respect_gitignore: bool,
    offset: Option<u32>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    let max_results = max_results.unwrap_or(200) as usize;
    let offset = offset.unwrap_or(0) as usize;

    let glob_pattern = glob::Pattern::new(pattern)
        .map_err(|e| SurgicalError::pattern_invalid(pattern, &e.to_string()))?;

    let exclude_globs: Vec<glob::Pattern> = exclude_patterns
        .unwrap_or_default()
        .iter()
        .filter_map(|p| glob::Pattern::new(p).ok())
        .collect();

    let mut results: Vec<String> = Vec::new();

    if respect_gitignore {
        let walker = ignore::WalkBuilder::new(&canonical)
            .hidden(true)
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true)
            .build();
        for entry in walker.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            let rel_path = entry
                .path()
                .strip_prefix(&canonical)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| entry.path().display().to_string());

            if exclude_globs
                .iter()
                .any(|p| p.matches(&name) || p.matches(&rel_path))
            {
                continue;
            }

            if glob_pattern.matches(&name) || glob_pattern.matches(&rel_path) {
                results.push(entry.path().display().to_string());
            }

            if results.len() >= offset + max_results {
                break;
            }
        }
    } else {
        for entry in WalkDir::new(&canonical).into_iter().filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            let rel_path = entry
                .path()
                .strip_prefix(&canonical)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| entry.path().display().to_string());

            if exclude_globs
                .iter()
                .any(|p| p.matches(&name) || p.matches(&rel_path))
            {
                continue;
            }

            if glob_pattern.matches(&name) || glob_pattern.matches(&rel_path) {
                results.push(entry.path().display().to_string());
            }

            if results.len() >= offset + max_results {
                break;
            }
        }
    }

    // Apply pagination
    let paginated: Vec<_> = results.into_iter().skip(offset).take(max_results).collect();

    Ok(json!(paginated))
}

/// Get file info (default server: `get_file_info`).
pub fn get_file_info(path_guard: &PathGuard, path: &str) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    let metadata = fs::metadata(&canonical).map_err(|e| {
        SurgicalError::io_error(&e, &format!("Cannot read metadata for '{}'", path))
    })?;

    let modified = metadata.modified().ok().map(|t| {
        let dt: chrono::DateTime<chrono::Utc> = t.into();
        dt.to_rfc3339()
    });
    let created = metadata.created().ok().map(|t| {
        let dt: chrono::DateTime<chrono::Utc> = t.into();
        dt.to_rfc3339()
    });
    let accessed = metadata.accessed().ok().map(|t| {
        let dt: chrono::DateTime<chrono::Utc> = t.into();
        dt.to_rfc3339()
    });

    Ok(json!({
        "size": metadata.len(),
        "created": created,
        "modified": modified,
        "accessed": accessed,
        "isDirectory": metadata.is_dir(),
        "isFile": metadata.is_file(),
        "permissions": if metadata.permissions().readonly() { "readonly" } else { "read-write" },
    }))
}

/// Generate a simple unified diff between two strings.
fn generate_unified_diff(path: &str, old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    let mut diff = String::new();
    diff.push_str(&format!("--- a/{}\n", path));
    diff.push_str(&format!("+++ b/{}\n", path));

    // Simple line-by-line diff: find changed regions
    let max_len = old_lines.len().max(new_lines.len());
    let mut i = 0;
    while i < max_len {
        let old_line = old_lines.get(i).copied();
        let new_line = new_lines.get(i).copied();

        if old_line != new_line {
            // Found a difference — emit a hunk
            let context_start = i.saturating_sub(3);
            let mut hunk_end = i + 1;
            // Extend hunk to include consecutive changes
            while hunk_end < max_len {
                let ol = old_lines.get(hunk_end).copied();
                let nl = new_lines.get(hunk_end).copied();
                if ol == nl {
                    break;
                }
                hunk_end += 1;
            }
            let context_end = (hunk_end + 3).min(max_len);

            let old_start = context_start + 1;
            let old_count = (context_end)
                .min(old_lines.len())
                .saturating_sub(context_start);
            let new_start = context_start + 1;
            let new_count = (context_end)
                .min(new_lines.len())
                .saturating_sub(context_start);

            diff.push_str(&format!(
                "@@ -{},{} +{},{} @@\n",
                old_start, old_count, new_start, new_count
            ));

            for j in context_start..context_end {
                let ol = old_lines.get(j).copied();
                let nl = new_lines.get(j).copied();

                if j < i || j >= hunk_end {
                    // Context line
                    if let Some(line) = ol.or(nl) {
                        diff.push_str(&format!(" {}\n", line));
                    }
                } else {
                    // Changed line
                    if let Some(line) = ol {
                        diff.push_str(&format!("-{}\n", line));
                    }
                    if let Some(line) = nl {
                        diff.push_str(&format!("+{}\n", line));
                    }
                }
            }

            i = context_end;
        } else {
            i += 1;
        }
    }

    if diff.lines().count() <= 2 {
        // No changes
        "No changes.".to_string()
    } else {
        diff
    }
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1_048_576 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1_073_741_824 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            security: crate::config::SecurityConfig {
                allowed_directories: vec![std::env::temp_dir().to_string_lossy().to_string()],
                follow_symlinks: false,
                max_file_size: 5_242_880,
                read_only: false,
            },
            search: Default::default(),
            defaults: Default::default(),
            response_budget: Default::default(),
            tools: Default::default(),
            runtime: Default::default(),
            server: Default::default(),
            logging: Default::default(),
        }
    }

    fn test_guard() -> PathGuard {
        PathGuard::new(
            &[std::env::temp_dir().to_string_lossy().to_string()],
            false,
            5_242_880,
        )
        .unwrap()
    }

    #[test]
    fn test_read_file() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_compat_read.txt");
        fs::write(&path, "hello\nworld").unwrap();

        let result = read_file(&guard, &config, &path.to_string_lossy()).unwrap();
        assert_eq!(result.as_str().unwrap(), "hello\nworld");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_edit_file_dry_run() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_compat_edit.txt");
        fs::write(&path, "line one\nline two\nline three").unwrap();

        let edits = vec![json!({"oldText": "line two", "newText": "LINE TWO"})];
        let result =
            edit_file(&guard, &config, &path.to_string_lossy(), edits, Some(true)).unwrap();
        let diff = result.as_str().unwrap();
        assert!(diff.contains("-line two"));
        assert!(diff.contains("+LINE TWO"));

        // Verify file unchanged (dry run)
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("line two"));

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_edit_file_multiple_edits() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_compat_multiedit.txt");
        fs::write(&path, "aaa\nbbb\nccc").unwrap();

        let edits = vec![
            json!({"oldText": "aaa", "newText": "AAA"}),
            json!({"oldText": "ccc", "newText": "CCC"}),
        ];
        let result =
            edit_file(&guard, &config, &path.to_string_lossy(), edits, Some(false)).unwrap();
        assert!(result.as_str().unwrap().contains("+AAA"));

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("AAA"));
        assert!(content.contains("CCC"));

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_search_files_glob() {
        let guard = test_guard();
        let dir = std::env::temp_dir().join("surgicalfs_compat_search");
        fs::create_dir_all(&dir).ok();
        fs::write(dir.join("test.txt"), "hello").ok();
        fs::write(dir.join("test.rs"), "fn main()").ok();
        fs::write(dir.join("data.csv"), "a,b").ok();

        let result = search_files(
            &guard,
            &dir.to_string_lossy(),
            "*.txt",
            None,
            None,
            false,
            None,
        )
        .unwrap();
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert!(arr[0].as_str().unwrap().contains("test.txt"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_list_directory_format() {
        let guard = test_guard();
        let dir = std::env::temp_dir().join("surgicalfs_compat_listdir");
        fs::create_dir_all(dir.join("subdir")).ok();
        fs::write(dir.join("file.txt"), "x").ok();

        let result = list_directory(&guard, &dir.to_string_lossy()).unwrap();
        let text = result.as_str().unwrap();
        assert!(text.contains("[FILE] file.txt"));
        assert!(text.contains("[DIR] subdir"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_directory_tree_json_format() {
        let guard = test_guard();
        let dir = std::env::temp_dir().join("surgicalfs_compat_tree");
        fs::create_dir_all(dir.join("sub")).ok();
        fs::write(dir.join("a.txt"), "a").ok();
        fs::write(dir.join("sub").join("b.txt"), "b").ok();

        let result = directory_tree_json(&guard, &dir.to_string_lossy(), Some(2)).unwrap();
        assert_eq!(result["type"], "directory");
        let children = result["children"].as_array().unwrap();
        assert!(children.len() >= 2);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_read_multiple_files_partial() {
        let config = test_config();
        let guard = test_guard();
        let p1 = std::env::temp_dir().join("surgicalfs_multi_1.txt");
        fs::write(&p1, "content1").unwrap();
        let p2 = std::env::temp_dir().join("surgicalfs_multi_nonexistent.txt");
        fs::remove_file(&p2).ok(); // ensure doesn't exist

        let result = read_multiple_files(
            &guard,
            &config,
            vec![
                p1.to_string_lossy().to_string(),
                p2.to_string_lossy().to_string(),
            ],
        )
        .unwrap();
        let files = result["files"].as_array().unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0]["content"], "content1");
        assert!(files[1].get("error").is_some());

        fs::remove_file(&p1).ok();
    }

    #[test]
    fn test_read_media_file_png() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_media.png");
        // Minimal 1x1 PNG
        let png_bytes: Vec<u8> = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90,
            0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08, 0xD7, 0x63,
            0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xE2, 0x21, 0xBC, 0x33, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
        ];
        fs::write(&path, &png_bytes).unwrap();

        let result = read_media_file(&guard, &path.to_string_lossy()).unwrap();
        assert_eq!(result["mime_type"], "image/png");
        assert!(!result["data_base64"].as_str().unwrap().is_empty());
        assert_eq!(result["size_bytes"], png_bytes.len());

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_create_directory_idempotent() {
        let guard = test_guard();
        let dir = std::env::temp_dir()
            .join("surgicalfs_compat_mkdir")
            .join("nested");

        // First call creates
        let result = create_directory(&guard, &dir.to_string_lossy()).unwrap();
        assert_eq!(result["created"], true);
        assert!(dir.exists());

        // Second call succeeds silently
        let result2 = create_directory(&guard, &dir.to_string_lossy()).unwrap();
        assert_eq!(result2["created"], true);

        fs::remove_dir_all(std::env::temp_dir().join("surgicalfs_compat_mkdir")).ok();
    }

    #[test]
    fn test_get_file_info_compat() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_compat_info.txt");
        fs::write(&path, "test content").unwrap();

        let result = get_file_info(&guard, &path.to_string_lossy()).unwrap();
        assert!(result["size"].as_u64().unwrap() > 0);
        assert_eq!(result["isFile"], true);
        assert_eq!(result["isDirectory"], false);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_list_allowed_directories() {
        let dirs = vec!["C:\\Test".to_string(), "D:\\Data".to_string()];
        let result = list_allowed_directories(&dirs);
        let arr = result["allowed_directories"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }
}
