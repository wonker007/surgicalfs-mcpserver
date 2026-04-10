use regex::Regex;
use serde::Serialize;
use std::path::Path;
use std::process::Command;
use walkdir::WalkDir;

#[derive(Debug, Serialize)]
pub struct SearchMatch {
    pub file: String,
    pub line_number: u32,
    pub content: String,
    pub context_before: Vec<String>,
    pub context_after: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub matches: Vec<SearchMatch>,
    pub total_matches: u32,
    pub truncated: bool,
}

pub enum SearchBackend {
    Ripgrep(String), // path to rg binary
    Native,
}

impl std::fmt::Display for SearchBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SearchBackend::Ripgrep(path) => write!(f, "ripgrep ({})", path),
            SearchBackend::Native => write!(f, "native"),
        }
    }
}

impl SearchBackend {
    /// Detect the best available search backend.
    pub fn detect(ripgrep_path: &str) -> Self {
        if ripgrep_path != "auto" {
            if Path::new(ripgrep_path).exists() {
                tracing::info!(
                    "Search backend: ripgrep (configured path: {})",
                    ripgrep_path
                );
                return SearchBackend::Ripgrep(ripgrep_path.to_string());
            }
            tracing::warn!(
                "Configured ripgrep path '{}' does not exist, trying auto-detect",
                ripgrep_path
            );
        }

        // Check PATH
        if let Ok(output) = Command::new("rg").arg("--version").output() {
            if output.status.success() {
                let version = String::from_utf8_lossy(&output.stdout);
                tracing::info!("Search backend: ripgrep on PATH ({})", version.trim());
                return SearchBackend::Ripgrep("rg".to_string());
            }
        }

        // Check next to exe
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let rg_path = dir.join("rg.exe");
                if rg_path.exists() {
                    tracing::info!("Search backend: ripgrep beside exe ({})", rg_path.display());
                    return SearchBackend::Ripgrep(rg_path.to_string_lossy().to_string());
                }
            }
        }

        tracing::info!("Search backend: native (ripgrep not found)");
        SearchBackend::Native
    }

    /// Execute a search and return structured results.
    pub fn search(
        &self,
        pattern: &str,
        path: &str,
        is_regex: bool,
        case_sensitive: bool,
        file_globs: &[String],
        context_lines: u32,
        max_results: u32,
        respect_gitignore: bool,
    ) -> Result<SearchResult, String> {
        match self {
            SearchBackend::Ripgrep(rg) => {
                match self.search_ripgrep(
                    rg,
                    pattern,
                    path,
                    is_regex,
                    case_sensitive,
                    file_globs,
                    context_lines,
                    max_results,
                    respect_gitignore,
                ) {
                    Ok(result) => Ok(result),
                    Err(e) => {
                        tracing::warn!(
                            "Ripgrep search failed: {}. Falling back to native search.",
                            e
                        );
                        search_native(
                            pattern,
                            path,
                            is_regex,
                            case_sensitive,
                            file_globs,
                            context_lines,
                            max_results,
                            respect_gitignore,
                        )
                    }
                }
            }
            SearchBackend::Native => search_native(
                pattern,
                path,
                is_regex,
                case_sensitive,
                file_globs,
                context_lines,
                max_results,
                respect_gitignore,
            ),
        }
    }

    fn search_ripgrep(
        &self,
        rg_path: &str,
        pattern: &str,
        path: &str,
        is_regex: bool,
        case_sensitive: bool,
        file_globs: &[String],
        context_lines: u32,
        max_results: u32,
        respect_gitignore: bool,
    ) -> Result<SearchResult, String> {
        let mut cmd = Command::new(rg_path);
        cmd.arg("--json");
        cmd.arg("--max-count").arg(max_results.to_string());
        cmd.arg("--context").arg(context_lines.to_string());

        if !respect_gitignore {
            cmd.arg("--no-ignore");
        }

        if !case_sensitive {
            cmd.arg("--ignore-case");
        }

        if !is_regex {
            cmd.arg("--fixed-strings");
        }

        for g in file_globs {
            cmd.arg("--glob").arg(g);
        }

        cmd.arg(pattern);
        cmd.arg(path);

        let output = cmd
            .output()
            .map_err(|e| format!("Failed to execute ripgrep: {}", e))?;

        // Log stderr if present
        if !output.stderr.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("ripgrep stderr: {}", stderr.trim());
        }

        // Exit code: 0 = matches found, 1 = no matches, 2+ = error
        if output.status.code().unwrap_or(2) >= 2 {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "ripgrep error (exit {}): {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_ripgrep_json(&stdout, max_results)
    }
}

// ─── Native Rust search backend ──────────────────────────────────────────────

/// Pure Rust search implementation — no external dependencies required.
/// Used as the primary backend when ripgrep is not available, or as a
/// fallback when ripgrep fails.
fn search_native(
    pattern: &str,
    path: &str,
    is_regex: bool,
    case_sensitive: bool,
    file_globs: &[String],
    context_lines: u32,
    max_results: u32,
    respect_gitignore: bool,
) -> Result<SearchResult, String> {
    let target = Path::new(path);

    // Build the matcher
    let matcher: Box<dyn Fn(&str) -> bool + Send> = if is_regex {
        let re_pattern = if case_sensitive {
            pattern.to_string()
        } else {
            format!("(?i){}", pattern)
        };
        let re = Regex::new(&re_pattern).map_err(|e| format!("Invalid regex: {}", e))?;
        Box::new(move |line: &str| re.is_match(line))
    } else if case_sensitive {
        let pat = pattern.to_string();
        Box::new(move |line: &str| line.contains(pat.as_str()))
    } else {
        let pat = pattern.to_lowercase();
        Box::new(move |line: &str| line.to_lowercase().contains(pat.as_str()))
    };

    // Collect files to search
    let files: Vec<std::path::PathBuf> = if target.is_file() {
        vec![target.to_path_buf()]
    } else if target.is_dir() {
        collect_search_files(target, file_globs, respect_gitignore)
    } else {
        return Err(format!("Path '{}' is neither a file nor a directory", path));
    };

    let mut all_matches = Vec::new();
    let ctx = context_lines as usize;

    'outer: for file_path in &files {
        // Read file
        let bytes = match std::fs::read(file_path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Skip binary files (null byte in first 8KB)
        let check_len = bytes.len().min(8192);
        if bytes[..check_len].contains(&0) {
            continue;
        }

        // Decode as UTF-8 (lossy — replacement chars won't match patterns)
        let text = String::from_utf8_lossy(&bytes);
        let lines: Vec<&str> = text.lines().collect();
        let file_str = file_path.display().to_string();

        for (idx, line) in lines.iter().enumerate() {
            if matcher(line) {
                let ctx_start = idx.saturating_sub(ctx);
                let ctx_end = (idx + 1 + ctx).min(lines.len());

                all_matches.push(SearchMatch {
                    file: file_str.clone(),
                    line_number: (idx + 1) as u32,
                    content: line.to_string(),
                    context_before: (ctx_start..idx).map(|i| lines[i].to_string()).collect(),
                    context_after: ((idx + 1)..ctx_end).map(|i| lines[i].to_string()).collect(),
                });

                if all_matches.len() >= max_results as usize {
                    break 'outer;
                }
            }
        }
    }

    let total = all_matches.len() as u32;
    Ok(SearchResult {
        matches: all_matches,
        total_matches: total,
        truncated: total >= max_results,
    })
}

/// Collect files for directory search, respecting glob filters.
/// When `respect_gitignore` is true, uses the `ignore` crate which respects
/// `.gitignore`, `.ignore`, and global gitignore files.
fn collect_search_files(
    dir: &Path,
    file_globs: &[String],
    respect_gitignore: bool,
) -> Vec<std::path::PathBuf> {
    let glob_patterns: Vec<glob::Pattern> = file_globs
        .iter()
        .filter_map(|g| glob::Pattern::new(g).ok())
        .collect();

    let mut files = Vec::new();

    if respect_gitignore {
        // Use the `ignore` crate which respects .gitignore
        let walker = ignore::WalkBuilder::new(dir)
            .hidden(true) // skip hidden files/dirs
            .git_ignore(true) // respect .gitignore
            .git_global(true) // respect global gitignore
            .git_exclude(true) // respect .git/info/exclude
            .build();

        for entry in walker.filter_map(|e| e.ok()) {
            if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                continue;
            }

            if !glob_patterns.is_empty() {
                let name = entry.file_name().to_string_lossy();
                if !glob_patterns.iter().any(|g| g.matches(&name)) {
                    continue;
                }
            }

            if let Ok(meta) = entry.metadata() {
                if meta.len() > 10_485_760 {
                    continue;
                }
            }

            files.push(entry.into_path());
            if files.len() >= 10_000 {
                tracing::warn!("Native search hit 10,000 file limit in {}", dir.display());
                break;
            }
        }
    } else {
        // Original walkdir-based walker (no gitignore)
        for entry in WalkDir::new(dir)
            .into_iter()
            .filter_entry(|e| {
                if e.file_type().is_dir() {
                    let name = e.file_name().to_string_lossy();
                    !name.starts_with('.')
                        && name != "node_modules"
                        && name != "target"
                        && name != "__pycache__"
                        && name != ".git"
                } else {
                    true
                }
            })
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }

            if !glob_patterns.is_empty() {
                let name = entry.file_name().to_string_lossy();
                if !glob_patterns.iter().any(|g| g.matches(&name)) {
                    continue;
                }
            }

            if let Ok(meta) = entry.metadata() {
                if meta.len() > 10_485_760 {
                    continue;
                }
            }

            files.push(entry.into_path());
            if files.len() >= 10_000 {
                tracing::warn!("Native search hit 10,000 file limit in {}", dir.display());
                break;
            }
        }
    }

    files
}

// ─── Ripgrep JSON parser ─────────────────────────────────────────────────────

fn parse_ripgrep_json(output: &str, max_results: u32) -> Result<SearchResult, String> {
    let mut matches = Vec::new();
    let mut context_before: Vec<String> = Vec::new();
    let mut pending_match: Option<SearchMatch> = None;
    let mut collecting_after = 0u32;
    let mut max_after = 0u32;

    for line in output.lines() {
        let parsed: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let msg_type = parsed["type"].as_str().unwrap_or("");

        match msg_type {
            "context" => {
                let text = parsed["data"]["lines"]["text"]
                    .as_str()
                    .unwrap_or("")
                    .trim_end()
                    .to_string();
                if let Some(ref mut m) = pending_match {
                    m.context_after.push(text);
                    collecting_after += 1;
                    if collecting_after >= max_after {
                        if let Some(m) = pending_match.take() {
                            matches.push(m);
                        }
                        context_before.clear();
                        collecting_after = 0;
                    }
                } else {
                    context_before.push(text);
                }
            }
            "match" => {
                // Finalize previous match if still pending
                if let Some(m) = pending_match.take() {
                    matches.push(m);
                }

                let line_number = parsed["data"]["line_number"].as_u64().unwrap_or(0) as u32;
                let text = parsed["data"]["lines"]["text"]
                    .as_str()
                    .unwrap_or("")
                    .trim_end()
                    .to_string();
                let file = parsed["data"]["path"]["text"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();

                // Determine expected context_after lines from submatches or global setting
                max_after = parsed["data"]["context_lines_after"].as_u64().unwrap_or(0) as u32;

                pending_match = Some(SearchMatch {
                    file,
                    line_number,
                    content: text,
                    context_before: context_before.clone(),
                    context_after: Vec::new(),
                });
                context_before.clear();
                collecting_after = 0;
            }
            "begin" => {
                // New file, finalize any pending match
                if let Some(m) = pending_match.take() {
                    matches.push(m);
                }
                context_before.clear();
            }
            "end" => {
                if let Some(m) = pending_match.take() {
                    matches.push(m);
                }
                context_before.clear();
            }
            _ => {}
        }
    }

    // Finalize any remaining match
    if let Some(m) = pending_match.take() {
        matches.push(m);
    }

    let total = matches.len() as u32;
    let truncated = total >= max_results;

    Ok(SearchResult {
        matches,
        total_matches: total,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_backend() {
        let backend = SearchBackend::detect("auto");
        match backend {
            SearchBackend::Ripgrep(_) => {}
            SearchBackend::Native => {}
        }
    }

    #[test]
    fn test_parse_ripgrep_json_empty() {
        let result = parse_ripgrep_json("", 100).unwrap();
        assert_eq!(result.matches.len(), 0);
        assert!(!result.truncated);
    }

    #[test]
    fn test_parse_ripgrep_json_match() {
        let json_line = r#"{"type":"match","data":{"path":{"text":"test.txt"},"lines":{"text":"hello world"},"line_number":5,"submatches":[]}}"#;
        let result = parse_ripgrep_json(json_line, 100).unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].line_number, 5);
        assert_eq!(result.matches[0].content, "hello world");
    }

    #[test]
    fn test_native_search_literal() {
        let dir = std::env::temp_dir().join("surgicalfs_native_search");
        std::fs::create_dir_all(&dir).ok();
        let file = dir.join("test.txt");
        std::fs::write(&file, "hello world\ngoodbye world\nhello again\nfoo bar").unwrap();

        let result = search_native(
            "hello",
            &file.to_string_lossy(),
            false,
            true,
            &[],
            0,
            100,
            false,
        )
        .unwrap();

        assert_eq!(result.total_matches, 2);
        assert_eq!(result.matches[0].line_number, 1);
        assert_eq!(result.matches[1].line_number, 3);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_native_search_regex() {
        let dir = std::env::temp_dir().join("surgicalfs_native_regex");
        std::fs::create_dir_all(&dir).ok();
        let file = dir.join("test.rs");
        std::fs::write(&file, "pub fn foo() {}\nfn bar() {}\npub fn baz() {}").unwrap();

        let result = search_native(
            r"^pub fn",
            &file.to_string_lossy(),
            true,
            true,
            &[],
            0,
            100,
            false,
        )
        .unwrap();

        assert_eq!(result.total_matches, 2);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_native_search_case_insensitive() {
        let dir = std::env::temp_dir().join("surgicalfs_native_ci");
        std::fs::create_dir_all(&dir).ok();
        let file = dir.join("test.txt");
        std::fs::write(&file, "Hello World\nhello world\nHELLO WORLD").unwrap();

        let result = search_native(
            "hello",
            &file.to_string_lossy(),
            false,
            false,
            &[],
            0,
            100,
            false,
        )
        .unwrap();

        assert_eq!(result.total_matches, 3);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_native_search_context_lines() {
        let dir = std::env::temp_dir().join("surgicalfs_native_ctx");
        std::fs::create_dir_all(&dir).ok();
        let file = dir.join("test.txt");
        std::fs::write(&file, "line1\nline2\nMATCH\nline4\nline5").unwrap();

        let result = search_native(
            "MATCH",
            &file.to_string_lossy(),
            false,
            true,
            &[],
            1,
            100,
            false,
        )
        .unwrap();

        assert_eq!(result.total_matches, 1);
        assert_eq!(result.matches[0].context_before, vec!["line2"]);
        assert_eq!(result.matches[0].context_after, vec!["line4"]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_native_search_directory() {
        let dir = std::env::temp_dir().join("surgicalfs_native_dir");
        std::fs::create_dir_all(dir.join("sub")).ok();
        std::fs::write(dir.join("a.txt"), "findme here").unwrap();
        std::fs::write(dir.join("sub").join("b.txt"), "also findme").unwrap();
        std::fs::write(dir.join("c.rs"), "no match here").unwrap();

        // Search all files
        let result = search_native(
            "findme",
            &dir.to_string_lossy(),
            false,
            true,
            &[],
            0,
            100,
            false,
        )
        .unwrap();
        assert_eq!(result.total_matches, 2);

        // Search with glob filter
        let result_filtered = search_native(
            "findme",
            &dir.to_string_lossy(),
            false,
            true,
            &["*.txt".to_string()],
            0,
            100,
            false,
        )
        .unwrap();
        assert_eq!(result_filtered.total_matches, 2);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_native_search_max_results() {
        let dir = std::env::temp_dir().join("surgicalfs_native_max");
        std::fs::create_dir_all(&dir).ok();
        let content = (0..20)
            .map(|i| format!("match line {}", i))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(dir.join("test.txt"), &content).unwrap();

        let result = search_native(
            "match",
            &dir.join("test.txt").to_string_lossy(),
            false,
            true,
            &[],
            0,
            5,
            false,
        )
        .unwrap();

        assert_eq!(result.total_matches, 5);
        assert!(result.truncated);

        std::fs::remove_dir_all(&dir).ok();
    }
}
