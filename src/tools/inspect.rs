use crate::config::Config;
use crate::encoding;
use crate::errors::{SurgicalError, SurgicalResult};
use crate::pathguard::PathGuard;
use serde_json::json;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Get file metadata without reading content.
pub fn file_info(
    path_guard: &PathGuard,
    config: &Config,
    path: &str,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    let metadata = fs::metadata(&canonical).map_err(|e| {
        SurgicalError::io_error(&e, &format!("Cannot read metadata for '{}'", path))
    })?;

    let size = metadata.len();

    // Count lines and detect encoding (only for non-binary, reasonably sized files)
    let (line_count, encoding_detected) = if size <= path_guard.max_file_size() {
        let bytes = fs::read(&canonical).unwrap_or_default();
        if encoding::is_binary(&bytes) {
            (None, "binary".to_string())
        } else {
            let (text, enc) = encoding::decode_bytes(&bytes, &config.defaults.encoding)?;
            let lines = text.lines().count();
            (Some(lines), enc.to_string())
        }
    } else {
        (None, "unknown".to_string())
    };

    let mime = guess_mime(&canonical);
    let modified = metadata.modified().ok().map(|t| {
        let dt: chrono::DateTime<chrono::Utc> = t.into();
        dt.to_rfc3339()
    });
    let created = metadata.created().ok().map(|t| {
        let dt: chrono::DateTime<chrono::Utc> = t.into();
        dt.to_rfc3339()
    });

    Ok(json!({
        "size_bytes": size,
        "line_count": line_count,
        "encoding_detected": encoding_detected,
        "mime_type": mime,
        "modified_iso": modified,
        "created_iso": created,
        "is_readonly": metadata.permissions().readonly(),
        "is_symlink": fs::symlink_metadata(&canonical).map(|m| m.is_symlink()).unwrap_or(false),
    }))
}

/// Read the first N lines of a file.
pub fn file_head(
    path_guard: &PathGuard,
    config: &Config,
    path: &str,
    lines: Option<u32>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;
    check_binary(&canonical)?;

    let n = lines.unwrap_or(config.defaults.head_lines) as usize;
    let bytes = fs::read(&canonical).map_err(|e| SurgicalError::io_error(&e, "Read failed"))?;
    let (text, _enc) = encoding::decode_bytes(&bytes, &config.defaults.encoding)?;

    let all_lines: Vec<&str> = text.lines().collect();
    let total = all_lines.len();
    let taken: Vec<&str> = all_lines.into_iter().take(n).collect();
    let returned = taken.len();
    let content = taken.join("\n");

    Ok(json!({
        "content": content,
        "lines_returned": returned,
        "total_lines": total,
        "truncated": returned < total,
    }))
}

/// Read the last N lines of a file.
pub fn file_tail(
    path_guard: &PathGuard,
    config: &Config,
    path: &str,
    lines: Option<u32>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;
    check_binary(&canonical)?;

    let n = lines.unwrap_or(config.defaults.tail_lines) as usize;
    let bytes = fs::read(&canonical).map_err(|e| SurgicalError::io_error(&e, "Read failed"))?;
    let (text, _enc) = encoding::decode_bytes(&bytes, &config.defaults.encoding)?;

    let all_lines: Vec<&str> = text.lines().collect();
    let total = all_lines.len();
    let start = total.saturating_sub(n);
    let taken: Vec<&str> = all_lines[start..].to_vec();
    let returned = taken.len();
    let content = taken.join("\n");

    Ok(json!({
        "content": content,
        "lines_returned": returned,
        "total_lines": total,
        "start_line": start + 1,  // 1-indexed
    }))
}

/// Read a specific line range (1-indexed, inclusive).
pub fn file_read_lines(
    path_guard: &PathGuard,
    config: &Config,
    path: &str,
    start_line: u32,
    end_line: u32,
) -> SurgicalResult<serde_json::Value> {
    if start_line == 0 || end_line == 0 {
        return Err(SurgicalError::line_range_invalid(
            "Line numbers must be >= 1.",
        ));
    }
    if start_line > end_line {
        return Err(SurgicalError::line_range_invalid(format!(
            "start_line ({}) must be <= end_line ({}).",
            start_line, end_line
        )));
    }
    let range = end_line - start_line + 1;
    if range > config.defaults.max_read_lines {
        return Err(SurgicalError::line_range_invalid(format!(
            "Requested {} lines exceeds max_read_lines limit of {}.",
            range, config.defaults.max_read_lines
        )));
    }

    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;
    check_binary(&canonical)?;

    let file =
        fs::File::open(&canonical).map_err(|e| SurgicalError::io_error(&e, "Open failed"))?;
    let reader = BufReader::new(file);

    let mut collected = Vec::new();
    let mut total_lines = 0u32;

    for (idx, line_result) in reader.lines().enumerate() {
        total_lines = (idx + 1) as u32;
        let line_num = (idx + 1) as u32;

        if line_num > end_line {
            // Count remaining lines
            // For efficiency, we stop reading content but we need total lines
            // We'll just report what we know and note there might be more
            break;
        }

        let line = line_result.map_err(|e| SurgicalError::io_error(&e, "Read line failed"))?;

        if line_num >= start_line {
            collected.push(line);
        }
    }

    // If we broke early, count remaining lines
    if total_lines == end_line + 1 || total_lines >= end_line {
        // Need to count total — read through to count
        let bytes = fs::read(&canonical).map_err(|e| SurgicalError::io_error(&e, "Read failed"))?;
        let (text, _) = encoding::decode_bytes(&bytes, &config.defaults.encoding)?;
        total_lines = text.lines().count() as u32;
    }

    let content = collected.join("\n");
    let lines_returned = collected.len() as u32;

    Ok(json!({
        "content": content,
        "lines_returned": lines_returned,
        "total_lines": total_lines,
    }))
}

fn check_binary(path: &Path) -> SurgicalResult<()> {
    let file = fs::File::open(path).map_err(|e| SurgicalError::io_error(&e, "Open failed"))?;
    let mut reader = BufReader::new(file);
    let mut buf = [0u8; 8192];
    let n = std::io::Read::read(&mut reader, &mut buf).unwrap_or(0);
    if encoding::is_binary(&buf[..n]) {
        return Err(SurgicalError::binary_file(&path.display().to_string()));
    }
    Ok(())
}

fn guess_mime(path: &Path) -> String {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext.to_lowercase().as_str() {
        "rs" => "text/x-rust",
        "py" => "text/x-python",
        "js" => "text/javascript",
        "ts" => "text/typescript",
        "json" => "application/json",
        "toml" => "application/toml",
        "yaml" | "yml" => "application/yaml",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "md" => "text/markdown",
        "txt" => "text/plain",
        "csv" => "text/csv",
        "pdf" => "application/pdf",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "xls" => "application/vnd.ms-excel",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "zip" => "application/zip",
        "gz" | "tar" => "application/gzip",
        "exe" => "application/x-executable",
        "dll" => "application/x-sharedlib",
        _ => "application/octet-stream",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
    fn test_file_info() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_info_test.txt");
        fs::write(&path, "line1\nline2\nline3").unwrap();

        let result = file_info(&guard, &config, &path.to_string_lossy()).unwrap();
        assert_eq!(result["line_count"], 3);
        assert_eq!(result["encoding_detected"], "utf-8");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_head() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_head_test.txt");
        let content = (1..=10)
            .map(|i| format!("line{}", i))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&path, &content).unwrap();

        let result = file_head(&guard, &config, &path.to_string_lossy(), Some(3)).unwrap();
        assert_eq!(result["lines_returned"], 3);
        assert_eq!(result["total_lines"], 10);
        assert_eq!(result["truncated"], true);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_tail() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_tail_test.txt");
        let content = (1..=10)
            .map(|i| format!("line{}", i))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&path, &content).unwrap();

        let result = file_tail(&guard, &config, &path.to_string_lossy(), Some(3)).unwrap();
        assert_eq!(result["lines_returned"], 3);
        assert_eq!(result["start_line"], 8);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_read_lines() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_readlines_test.txt");
        let content = (1..=20)
            .map(|i| format!("line{}", i))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&path, &content).unwrap();

        let result = file_read_lines(&guard, &config, &path.to_string_lossy(), 5, 10).unwrap();
        assert_eq!(result["lines_returned"], 6);
        let text = result["content"].as_str().unwrap();
        assert!(text.starts_with("line5"));
        assert!(text.ends_with("line10"));

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_line_range_validation() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_range_test.txt");
        fs::write(&path, "test").unwrap();

        assert!(file_read_lines(&guard, &config, &path.to_string_lossy(), 0, 5).is_err());
        assert!(file_read_lines(&guard, &config, &path.to_string_lossy(), 10, 5).is_err());

        fs::remove_file(&path).ok();
    }
}
