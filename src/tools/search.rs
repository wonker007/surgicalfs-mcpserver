use crate::config::Config;
use crate::encoding;
use crate::errors::{ErrorCode, SurgicalError, SurgicalResult};
use crate::pathguard::PathGuard;
use crate::search_backend::SearchBackend;
use regex::Regex;
use serde_json::json;
use std::fs;

/// Search for text patterns across files using ripgrep or native fallback.
///
/// return_mode controls output verbosity:
/// - "full" (default): matching lines + context (highest token cost)
/// - "lines": line numbers + file paths only (lowest token cost)
/// - "count": match count per file only
pub fn file_search(
    path_guard: &PathGuard,
    config: &Config,
    search_backend: &SearchBackend,
    pattern: &str,
    path: &str,
    is_regex: Option<bool>,
    case_sensitive: Option<bool>,
    file_globs: Option<Vec<String>>,
    context_lines: Option<u32>,
    max_results: Option<u32>,
    return_mode: Option<String>,
    offset: Option<u32>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;

    let is_regex = is_regex.unwrap_or(true);
    let case_sensitive = case_sensitive.unwrap_or(true);
    let file_globs = file_globs.unwrap_or_default();
    let max_results = max_results.unwrap_or(config.search.max_results);
    let offset = offset.unwrap_or(0) as usize;
    let return_mode = return_mode.unwrap_or_else(|| "full".to_string());

    // For compact modes, force context_lines to 0 unless explicitly set
    let context_lines = match return_mode.as_str() {
        "lines" | "count" => context_lines.unwrap_or(0),
        _ => context_lines.unwrap_or(config.search.default_context_lines),
    };

    // Validate regex
    if is_regex {
        Regex::new(pattern).map_err(|e| SurgicalError::pattern_invalid(pattern, &e.to_string()))?;
    }

    // Request offset + max_results from backend so we can skip then paginate
    let backend_limit = max_results.saturating_add(offset as u32);

    let result = search_backend
        .search(
            pattern,
            &canonical.to_string_lossy(),
            is_regex,
            case_sensitive,
            &file_globs,
            context_lines,
            backend_limit,
            config.search.respect_gitignore,
        )
        .map_err(|e| {
            SurgicalError::new(
                ErrorCode::InternalError,
                e,
                "Check that ripgrep is installed or available on PATH.",
            )
        })?;

    // Apply pagination: skip offset, take max_results
    let total = result.total_matches;
    let paginated: Vec<_> = result
        .matches
        .into_iter()
        .skip(offset)
        .take(max_results as usize)
        .collect();

    match return_mode.as_str() {
        "lines" => {
            let hits: Vec<serde_json::Value> = paginated
                .iter()
                .map(|m| json!({ "file": m.file, "line": m.line_number }))
                .collect();
            Ok(json!({
                "hits": hits,
                "total_matches": total,
                "truncated": result.truncated,
                "offset": offset,
            }))
        }
        "count" => {
            // Match count per file — smallest possible response
            let mut counts: std::collections::BTreeMap<&str, u32> =
                std::collections::BTreeMap::new();
            for m in &paginated {
                *counts.entry(&m.file).or_insert(0) += 1;
            }
            let files: Vec<serde_json::Value> = counts
                .into_iter()
                .map(|(f, c)| json!({ "file": f, "count": c }))
                .collect();
            Ok(json!({
                "files": files,
                "total_matches": total,
                "truncated": result.truncated,
                "offset": offset,
            }))
        }
        _ => {
            // "full" — matching lines + context (original behavior)
            Ok(json!({
                "matches": paginated,
                "total_matches": total,
                "truncated": result.truncated,
                "offset": offset,
            }))
        }
    }
}

/// Lightweight single-file grep. Returns only line numbers (and optionally
/// matching line text). Reads the file directly — no ripgrep subprocess overhead.
/// Ideal for "where does X appear in this file?" queries at minimal token cost.
pub fn file_grep(
    path_guard: &PathGuard,
    config: &Config,
    path: &str,
    pattern: &str,
    is_regex: Option<bool>,
    case_sensitive: Option<bool>,
    max_results: Option<u32>,
    include_content: Option<bool>,
    offset: Option<u32>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    if !canonical.is_file() {
        return Err(SurgicalError::new(
            ErrorCode::InternalError,
            format!(
                "'{}' is not a file. Use file_search for directory searches.",
                path
            ),
            "Provide a file path, not a directory.",
        ));
    }

    let is_regex = is_regex.unwrap_or(false);
    let case_sensitive = case_sensitive.unwrap_or(true);
    let max_results = max_results.unwrap_or(100);
    let include_content = include_content.unwrap_or(false);
    let offset = offset.unwrap_or(0);

    let bytes = fs::read(&canonical).map_err(|e| SurgicalError::io_error(&e, "Read failed"))?;
    if encoding::is_binary(&bytes) {
        return Err(SurgicalError::binary_file(path));
    }
    let (text, _enc) = encoding::decode_bytes(&bytes, &config.defaults.encoding)?;

    let matcher: Box<dyn Fn(&str) -> bool> = if is_regex {
        let re_pat = if case_sensitive {
            pattern.to_string()
        } else {
            format!("(?i){}", pattern)
        };
        let re = Regex::new(&re_pat)
            .map_err(|e| SurgicalError::pattern_invalid(pattern, &e.to_string()))?;
        Box::new(move |line: &str| re.is_match(line))
    } else if case_sensitive {
        let pat = pattern.to_string();
        Box::new(move |line: &str| line.contains(pat.as_str()))
    } else {
        let pat = pattern.to_lowercase();
        Box::new(move |line: &str| line.to_lowercase().contains(pat.as_str()))
    };

    let mut line_numbers: Vec<u32> = Vec::new();
    let mut hits: Vec<serde_json::Value> = Vec::new();
    let mut total = 0u32;
    let limit = offset.saturating_add(max_results);

    for (idx, line) in text.lines().enumerate() {
        if matcher(line) {
            total += 1;
            if total > offset && total <= limit {
                let ln = (idx + 1) as u32;
                line_numbers.push(ln);
                if include_content {
                    hits.push(json!({ "line": ln, "content": line }));
                }
            }
        }
    }

    if include_content {
        Ok(json!({
            "hits": hits,
            "total_matches": total,
            "truncated": total > limit,
            "offset": offset,
        }))
    } else {
        Ok(json!({
            "line_numbers": line_numbers,
            "total_matches": total,
            "truncated": total > limit,
            "offset": offset,
        }))
    }
}

/// Dry-run a find-and-replace showing what would change without modifying the file.
pub fn file_search_replace_preview(
    path_guard: &PathGuard,
    config: &Config,
    path: &str,
    find: &str,
    replace: &str,
    is_regex: Option<bool>,
    max_previews: Option<u32>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let is_regex = is_regex.unwrap_or(false);
    let max_previews = max_previews.unwrap_or(10) as usize;

    let bytes = fs::read(&canonical).map_err(|e| SurgicalError::io_error(&e, "Read failed"))?;
    if encoding::is_binary(&bytes) {
        return Err(SurgicalError::binary_file(path));
    }
    let (text, _enc) = encoding::decode_bytes(&bytes, &config.defaults.encoding)?;

    let mut previews = Vec::new();
    let mut total_matches = 0u32;

    if is_regex {
        let re =
            Regex::new(find).map_err(|e| SurgicalError::pattern_invalid(find, &e.to_string()))?;
        for (idx, line) in text.lines().enumerate() {
            if re.is_match(line) {
                total_matches += 1;
                if previews.len() < max_previews {
                    let after = re.replace_all(line, replace).to_string();
                    previews.push(json!({
                        "line_number": idx + 1,
                        "before": line,
                        "after": after,
                    }));
                }
            }
        }
    } else {
        for (idx, line) in text.lines().enumerate() {
            if line.contains(find) {
                total_matches += 1;
                if previews.len() < max_previews {
                    let after = line.replace(find, replace);
                    previews.push(json!({
                        "line_number": idx + 1,
                        "before": line,
                        "after": after,
                    }));
                }
            }
        }
    }

    Ok(json!({
        "previews": previews,
        "total_matches": total_matches,
    }))
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
    fn test_search_replace_preview_literal() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_preview_test.txt");
        fs::write(&path, "hello world\ngoodbye world\nhello again").unwrap();

        let result = file_search_replace_preview(
            &guard,
            &config,
            &path.to_string_lossy(),
            "hello",
            "hi",
            Some(false),
            Some(10),
        )
        .unwrap();

        assert_eq!(result["total_matches"], 2);
        let previews = result["previews"].as_array().unwrap();
        assert_eq!(previews.len(), 2);
        assert_eq!(previews[0]["after"], "hi world");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_search_replace_preview_regex() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_preview_regex.txt");
        fs::write(&path, "foo123bar\nfoo456bar\nbaz").unwrap();

        let result = file_search_replace_preview(
            &guard,
            &config,
            &path.to_string_lossy(),
            r"foo(\d+)bar",
            "replaced_$1",
            Some(true),
            Some(10),
        )
        .unwrap();

        assert_eq!(result["total_matches"], 2);
        let previews = result["previews"].as_array().unwrap();
        assert_eq!(previews[0]["after"], "replaced_123");

        fs::remove_file(&path).ok();
    }

    // ── file_grep tests ──

    #[test]
    fn test_file_grep_line_numbers_only() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_grep_lines.txt");
        fs::write(&path, "alpha\nbeta\nalpha again\ndelta\nalpha three").unwrap();

        let result = file_grep(
            &guard,
            &config,
            &path.to_string_lossy(),
            "alpha",
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(result["total_matches"], 3);
        let lines = result["line_numbers"].as_array().unwrap();
        assert_eq!(lines, &[1, 3, 5]);
        assert!(result.get("hits").is_none());

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_grep_with_content() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_grep_content.txt");
        fs::write(&path, "fn main() {}\nfn helper() {}\nstruct Foo").unwrap();

        let result = file_grep(
            &guard,
            &config,
            &path.to_string_lossy(),
            "fn ",
            None,
            None,
            None,
            Some(true),
            None,
        )
        .unwrap();

        assert_eq!(result["total_matches"], 2);
        let hits = result["hits"].as_array().unwrap();
        assert_eq!(hits[0]["line"], 1);
        assert_eq!(hits[0]["content"], "fn main() {}");
        assert_eq!(hits[1]["line"], 2);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_grep_case_insensitive() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_grep_ci.txt");
        fs::write(&path, "Hello\nhello\nHELLO\nworld").unwrap();

        let result = file_grep(
            &guard,
            &config,
            &path.to_string_lossy(),
            "hello",
            None,
            Some(false),
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(result["total_matches"], 3);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_grep_regex() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_grep_regex.txt");
        fs::write(&path, "error: something\nwarn: other\nerror: again").unwrap();

        let result = file_grep(
            &guard,
            &config,
            &path.to_string_lossy(),
            r"^error:",
            Some(true),
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(result["total_matches"], 2);
        let lines = result["line_numbers"].as_array().unwrap();
        assert_eq!(lines, &[1, 3]);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_grep_max_results() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_grep_max.txt");
        let content = (0..20)
            .map(|i| format!("match {}", i))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&path, &content).unwrap();

        let result = file_grep(
            &guard,
            &config,
            &path.to_string_lossy(),
            "match",
            None,
            None,
            Some(3),
            None,
            None,
        )
        .unwrap();

        assert_eq!(result["total_matches"], 20);
        let lines = result["line_numbers"].as_array().unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(result["truncated"], true);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_grep_rejects_directory() {
        let config = test_config();
        let guard = test_guard();
        let dir = std::env::temp_dir();

        let result = file_grep(
            &guard,
            &config,
            &dir.to_string_lossy(),
            "pattern",
            None,
            None,
            None,
            None,
            None,
        );

        assert!(result.is_err());
    }
}
