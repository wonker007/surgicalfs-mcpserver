use crate::config::Config;
use crate::encoding;
use crate::errors::{ErrorCode, SurgicalError, SurgicalResult};
use crate::pathguard::PathGuard;
use regex::Regex;
use serde_json::json;
use std::fs;

/// Find and replace text in a file in-place.
pub fn file_replace(
    path_guard: &PathGuard,
    config: &Config,
    path: &str,
    find: &str,
    replace: &str,
    is_regex: Option<bool>,
    occurrence: Option<String>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let is_regex = is_regex.unwrap_or(false);
    let occurrence = occurrence.unwrap_or_else(|| "all".to_string());

    let bytes = fs::read(&canonical).map_err(|e| SurgicalError::io_error(&e, "Read failed"))?;
    if encoding::is_binary(&bytes) {
        return Err(SurgicalError::binary_file(path));
    }
    let (text, _enc) = encoding::decode_bytes(&bytes, &config.defaults.encoding)?;

    // Normalize line endings to \n for matching, and normalize the find pattern too
    let normalized_text = text.replace("\r\n", "\n");
    let normalized_find = find.replace("\r\n", "\n");

    // Check if this is a multi-line find pattern
    let is_multiline = normalized_find.contains('\n');

    if is_multiline {
        // Multi-line matching: operate on the full text as a single string
        return file_replace_multiline(
            &canonical,
            &normalized_text,
            &normalized_find,
            replace,
            is_regex,
            &occurrence,
            text.ends_with('\n'),
        );
    }

    let lines: Vec<&str> = normalized_text.lines().collect();
    let mut new_lines: Vec<String> = Vec::with_capacity(lines.len());
    let mut modified_line_nums: Vec<u32> = Vec::new();
    let mut replacements_made = 0u32;

    if is_regex {
        let re =
            Regex::new(find).map_err(|e| SurgicalError::pattern_invalid(find, &e.to_string()))?;

        for (idx, line) in lines.iter().enumerate() {
            if re.is_match(line) {
                let should_replace = match occurrence.as_str() {
                    "first" => replacements_made == 0,
                    "last" => false, // handled in second pass
                    _ => true,       // "all"
                };

                if should_replace {
                    let new_line = re.replace_all(line, replace).to_string();
                    if new_line != *line {
                        replacements_made += 1;
                        modified_line_nums.push((idx + 1) as u32);
                    }
                    new_lines.push(new_line);
                } else {
                    new_lines.push(line.to_string());
                }
            } else {
                new_lines.push(line.to_string());
            }
        }

        // Handle "last" occurrence
        if occurrence == "last" {
            new_lines.clear();
            modified_line_nums.clear();
            replacements_made = 0;
            let mut last_match_idx: Option<usize> = None;

            for (idx, line) in lines.iter().enumerate() {
                if re.is_match(line) {
                    last_match_idx = Some(idx);
                }
            }

            for (idx, line) in lines.iter().enumerate() {
                if Some(idx) == last_match_idx {
                    let new_line = re.replace_all(line, replace).to_string();
                    if new_line != *line {
                        replacements_made = 1;
                        modified_line_nums.push((idx + 1) as u32);
                    }
                    new_lines.push(new_line);
                } else {
                    new_lines.push(line.to_string());
                }
            }
        }
    } else {
        // Literal replacement
        if occurrence == "last" {
            let mut last_match_idx: Option<usize> = None;
            for (idx, line) in lines.iter().enumerate() {
                if line.contains(find) {
                    last_match_idx = Some(idx);
                }
            }
            for (idx, line) in lines.iter().enumerate() {
                if Some(idx) == last_match_idx {
                    let new_line = line.replace(find, replace);
                    if new_line != *line {
                        replacements_made = 1;
                        modified_line_nums.push((idx + 1) as u32);
                    }
                    new_lines.push(new_line);
                } else {
                    new_lines.push(line.to_string());
                }
            }
        } else {
            for (idx, line) in lines.iter().enumerate() {
                if line.contains(find) {
                    let should_replace = match occurrence.as_str() {
                        "first" => replacements_made == 0,
                        _ => true,
                    };
                    if should_replace {
                        let new_line = line.replace(find, replace);
                        if new_line != *line {
                            replacements_made += 1;
                            modified_line_nums.push((idx + 1) as u32);
                        }
                        new_lines.push(new_line);
                    } else {
                        new_lines.push(line.to_string());
                    }
                } else {
                    new_lines.push(line.to_string());
                }
            }
        }
    }

    let new_content = new_lines.join("\n");
    // Preserve trailing newline if original had one
    let final_content = if text.ends_with('\n') && !new_content.ends_with('\n') {
        new_content + "\n"
    } else {
        new_content
    };

    super::atomic_write(&canonical, final_content.as_bytes())?;

    Ok(json!({
        "replacements_made": replacements_made,
        "modified_lines": modified_line_nums,
    }))
}

/// Multi-line find-and-replace: operates on the full text as a single string.
fn file_replace_multiline(
    canonical: &std::path::Path,
    text: &str,
    find: &str,
    replace: &str,
    is_regex: bool,
    occurrence: &str,
    had_trailing_newline: bool,
) -> SurgicalResult<serde_json::Value> {
    let mut replacements_made = 0u32;
    let mut modified_line_nums: Vec<u32> = Vec::new();

    // Also normalize replace text line endings
    let normalized_replace = replace.replace("\r\n", "\n");

    let new_text = if is_regex {
        let re =
            Regex::new(find).map_err(|e| SurgicalError::pattern_invalid(find, &e.to_string()))?;
        match occurrence {
            "first" => {
                if let Some(m) = re.find(text) {
                    let start_line = text[..m.start()].matches('\n').count() + 1;
                    let end_line = text[..m.end()].matches('\n').count() + 1;
                    for ln in start_line..=end_line {
                        modified_line_nums.push(ln as u32);
                    }
                    replacements_made = 1;
                    let mut result = String::with_capacity(text.len());
                    result.push_str(&text[..m.start()]);
                    result.push_str(&re.replace(m.as_str(), normalized_replace.as_str()));
                    result.push_str(&text[m.end()..]);
                    result
                } else {
                    text.to_string()
                }
            }
            "last" => {
                let matches: Vec<regex::Match> = re.find_iter(text).collect();
                if let Some(m) = matches.last() {
                    let start_line = text[..m.start()].matches('\n').count() + 1;
                    let end_line = text[..m.end()].matches('\n').count() + 1;
                    for ln in start_line..=end_line {
                        modified_line_nums.push(ln as u32);
                    }
                    replacements_made = 1;
                    let mut result = String::with_capacity(text.len());
                    result.push_str(&text[..m.start()]);
                    result.push_str(&re.replace(m.as_str(), normalized_replace.as_str()));
                    result.push_str(&text[m.end()..]);
                    result
                } else {
                    text.to_string()
                }
            }
            _ => {
                // "all"
                let mut result = String::new();
                let mut last_end = 0;
                for m in re.find_iter(text) {
                    let start_line = text[..m.start()].matches('\n').count() + 1;
                    let end_line = text[..m.end()].matches('\n').count() + 1;
                    for ln in start_line..=end_line {
                        if !modified_line_nums.contains(&(ln as u32)) {
                            modified_line_nums.push(ln as u32);
                        }
                    }
                    replacements_made += 1;
                    result.push_str(&text[last_end..m.start()]);
                    result.push_str(&re.replace(m.as_str(), normalized_replace.as_str()));
                    last_end = m.end();
                }
                result.push_str(&text[last_end..]);
                result
            }
        }
    } else {
        // Literal multi-line replacement
        let match_positions: Vec<usize> = text.match_indices(find).map(|(pos, _)| pos).collect();

        if match_positions.is_empty() {
            text.to_string()
        } else {
            let targets: Vec<usize> = match occurrence {
                "first" => match_positions.into_iter().take(1).collect(),
                "last" => match_positions.last().copied().into_iter().collect(),
                _ => match_positions, // "all"
            };

            let mut result = String::new();
            let mut last_end = 0;
            for &pos in &targets {
                let end = pos + find.len();
                let start_line = text[..pos].matches('\n').count() + 1;
                let end_line = text[..end].matches('\n').count() + 1;
                for ln in start_line..=end_line {
                    if !modified_line_nums.contains(&(ln as u32)) {
                        modified_line_nums.push(ln as u32);
                    }
                }
                replacements_made += 1;
                result.push_str(&text[last_end..pos]);
                result.push_str(&normalized_replace);
                last_end = end;
            }
            result.push_str(&text[last_end..]);
            result
        }
    };

    let final_content = if had_trailing_newline && !new_text.ends_with('\n') {
        new_text + "\n"
    } else {
        new_text
    };

    super::atomic_write(canonical, final_content.as_bytes())?;

    modified_line_nums.sort();
    Ok(json!({
        "replacements_made": replacements_made,
        "modified_lines": modified_line_nums,
    }))
}

/// Insert text at a specified anchor point.
pub fn file_insert(
    path_guard: &PathGuard,
    config: &Config,
    path: &str,
    content: &str,
    anchor: serde_json::Value,
    occurrence: Option<String>,
    expected_content: Option<String>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let bytes = fs::read(&canonical).map_err(|e| SurgicalError::io_error(&e, "Read failed"))?;
    if encoding::is_binary(&bytes) {
        return Err(SurgicalError::binary_file(path));
    }
    let (text, _enc) = encoding::decode_bytes(&bytes, &config.defaults.encoding)?;

    let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    let insert_lines: Vec<&str> = content.lines().collect();
    let lines_added = insert_lines.len() as u32;
    let occurrence = occurrence.unwrap_or_else(|| "first".to_string());

    // If anchor arrived as a JSON string (some MCP clients serialize nested objects
    // as strings), try to parse it into an object.
    let anchor = match &anchor {
        serde_json::Value::String(s) => {
            serde_json::from_str::<serde_json::Value>(s).unwrap_or(anchor)
        }
        _ => anchor,
    };

    let mut inserted_at: Vec<u32> = Vec::new();

    if let Some(line_num) = anchor.get("line").and_then(|v| v.as_u64()) {
        // Content verification for line-number anchors
        if let Some(ref expected) = expected_content {
            let idx = (line_num as usize).min(lines.len());
            if idx < lines.len() {
                let actual = &lines[idx];
                let expected_normalized = expected.replace("\r\n", "\n");
                if actual != &expected_normalized {
                    let preview = |s: &str| -> String {
                        if s.len() > 100 {
                            format!("{}...", &s[..100])
                        } else {
                            s.to_string()
                        }
                    };
                    return Err(SurgicalError::new(
                        ErrorCode::InternalError,
                        format!(
                            "Content verification failed: line {} has changed since last read. Expected: \"{}\", Actual: \"{}\"",
                            line_num, preview(&expected_normalized), preview(actual)
                        ),
                        "Re-read the file to get current content before editing.",
                    ));
                }
            }
        }
        // Insert at specific line number
        let idx = (line_num as usize).min(lines.len());
        for (i, insert_line) in insert_lines.iter().enumerate() {
            lines.insert(idx + i, insert_line.to_string());
        }
        inserted_at.push(line_num as u32);
    } else if let Some(pattern) = anchor.get("before").and_then(|v| v.as_str()) {
        let matches: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.contains(pattern))
            .map(|(i, _)| i)
            .collect();

        let targets: Vec<usize> = match occurrence.as_str() {
            "all" => matches,
            _ => matches.into_iter().take(1).collect(),
        };

        // Insert in reverse order to preserve indices (later insertions don't shift earlier ones)
        for &idx in targets.iter().rev() {
            for (i, insert_line) in insert_lines.iter().enumerate() {
                lines.insert(idx + i, insert_line.to_string());
            }
            inserted_at.push((idx + 1) as u32);
        }
        inserted_at.reverse();
    } else if let Some(pattern) = anchor.get("after").and_then(|v| v.as_str()) {
        let matches: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.contains(pattern))
            .map(|(i, _)| i)
            .collect();

        let targets: Vec<usize> = match occurrence.as_str() {
            "all" => matches,
            _ => matches.into_iter().take(1).collect(),
        };

        // Insert in reverse order to preserve indices
        for &idx in targets.iter().rev() {
            let insert_idx = idx + 1;
            for (i, insert_line) in insert_lines.iter().enumerate() {
                lines.insert(insert_idx + i, insert_line.to_string());
            }
            inserted_at.push((idx + 2) as u32);
        }
        inserted_at.reverse();
    } else if let Some(pos) = anchor.get("position").and_then(|v| v.as_str()) {
        match pos {
            "start" => {
                for (i, insert_line) in insert_lines.iter().enumerate() {
                    lines.insert(i, insert_line.to_string());
                }
                inserted_at.push(1);
            }
            "end" => {
                let start = lines.len() + 1;
                for insert_line in &insert_lines {
                    lines.push(insert_line.to_string());
                }
                inserted_at.push(start as u32);
            }
            _ => {
                return Err(SurgicalError::new(
                    ErrorCode::InternalError,
                    format!("Invalid position: '{}'. Use 'start' or 'end'.", pos),
                    "Use anchor: {\"position\": \"start\"} or {\"position\": \"end\"}.",
                ));
            }
        }
    } else {
        return Err(SurgicalError::new(
            ErrorCode::InternalError,
            "Invalid anchor. Expected one of: line, before, after, position.",
            "Use anchor like {\"line\": 5}, {\"before\": \"pattern\"}, {\"after\": \"pattern\"}, or {\"position\": \"start\"}.",
        ));
    }

    let new_content = lines.join("\n");
    let final_content = if text.ends_with('\n') && !new_content.ends_with('\n') {
        new_content + "\n"
    } else {
        new_content
    };

    super::atomic_write(&canonical, final_content.as_bytes())?;

    Ok(json!({
        "inserted_at_lines": inserted_at,
        "lines_added": lines_added,
    }))
}

/// Append text to the end of a file.
pub fn file_append(
    path_guard: &PathGuard,
    path: &str,
    content: &str,
    newline: Option<bool>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;

    let newline = newline.unwrap_or(true);
    let existing = fs::read_to_string(&canonical).unwrap_or_default();

    let to_append = if newline && !existing.is_empty() && !existing.ends_with('\n') {
        format!("\n{}", content)
    } else {
        content.to_string()
    };

    use std::io::Write;
    // Non-atomic: append cannot use temp+rename without losing existing content.
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&canonical)
        .map_err(|e| SurgicalError::io_error(&e, "Open for append failed"))?;
    file.write_all(to_append.as_bytes())
        .map_err(|e| SurgicalError::io_error(&e, "Append failed"))?;

    let new_total = fs::read_to_string(&canonical)
        .unwrap_or_default()
        .lines()
        .count();

    Ok(json!({
        "new_line_count": new_total,
        "bytes_appended": to_append.len(),
    }))
}

/// Replace a specific line range with new content.
pub fn file_patch_lines(
    path_guard: &PathGuard,
    config: &Config,
    path: &str,
    start_line: u32,
    end_line: u32,
    content: &str,
    expected_content: Option<String>,
) -> SurgicalResult<serde_json::Value> {
    if start_line == 0 || end_line == 0 || start_line > end_line {
        return Err(SurgicalError::line_range_invalid(
            "Invalid line range for patch_lines.",
        ));
    }

    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let bytes = fs::read(&canonical).map_err(|e| SurgicalError::io_error(&e, "Read failed"))?;
    if encoding::is_binary(&bytes) {
        return Err(SurgicalError::binary_file(path));
    }
    let (text, _enc) = encoding::decode_bytes(&bytes, &config.defaults.encoding)?;

    let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    let old_count = end_line - start_line + 1;

    if start_line as usize > lines.len() {
        return Err(SurgicalError::line_range_invalid(format!(
            "start_line {} exceeds file length of {} lines.",
            start_line,
            lines.len()
        )));
    }

    let end_idx = (end_line as usize).min(lines.len());
    let start_idx = (start_line - 1) as usize;

    // Content verification: check that target lines match expected content
    if let Some(ref expected) = expected_content {
        let actual: String = lines[start_idx..end_idx].join("\n");
        let expected_normalized = expected.replace("\r\n", "\n");
        if actual != expected_normalized {
            let preview = |s: &str| -> String {
                if s.len() > 100 {
                    format!("{}...", &s[..100])
                } else {
                    s.to_string()
                }
            };
            return Err(SurgicalError::new(
                ErrorCode::InternalError,
                format!(
                    "Content verification failed: lines {}-{} have changed since last read. Expected: \"{}\", Actual: \"{}\"",
                    start_line, end_line, preview(&expected_normalized), preview(&actual)
                ),
                "Re-read the file to get current content before editing.",
            ));
        }
    }

    // Remove old lines
    lines.drain(start_idx..end_idx);

    // Insert new content
    let new_lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    let new_count = new_lines.len() as u32;
    for (i, line) in new_lines.into_iter().enumerate() {
        lines.insert(start_idx + i, line);
    }

    let new_content = lines.join("\n");
    let final_content = if text.ends_with('\n') && !new_content.ends_with('\n') {
        new_content + "\n"
    } else {
        new_content
    };

    super::atomic_write(&canonical, final_content.as_bytes())?;

    Ok(json!({
        "old_line_count": old_count,
        "new_line_count": new_count,
        "lines_changed": (new_count as i64 - old_count as i64).abs(),
    }))
}

/// Apply multiple edits in a single atomic operation.
pub fn file_batch_edit(
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
    let (text, _enc) = encoding::decode_bytes(&bytes, &config.defaults.encoding)?;

    let dry_run = dry_run.unwrap_or(false);
    let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut edits_applied = 0u32;

    // Resolve all edits to line-based operations with line numbers, then sort descending
    #[derive(Debug)]
    struct ResolvedEdit {
        #[allow(dead_code)]
        index: usize,
        op: String,
        start_line: usize, // 0-indexed
        end_line: usize,   // 0-indexed, inclusive
        new_content: Option<Vec<String>>,
    }

    let mut resolved: Vec<ResolvedEdit> = Vec::new();

    for (idx, edit) in edits.iter().enumerate() {
        let op = edit["op"].as_str().unwrap_or("unknown").to_string();

        match op.as_str() {
            "replace" => {
                let find = edit["find"].as_str().unwrap_or("");
                let replace_with = edit["replace"].as_str().unwrap_or("");
                let is_regex = edit["is_regex"].as_bool().unwrap_or(false);
                let occ = edit["occurrence"].as_str().unwrap_or("first");

                // Find matching lines
                let mut match_indices: Vec<usize> = Vec::new();
                for (i, line) in lines.iter().enumerate() {
                    let matches = if is_regex {
                        Regex::new(find)
                            .map(|re| re.is_match(line))
                            .unwrap_or(false)
                    } else {
                        line.contains(find)
                    };
                    if matches {
                        match_indices.push(i);
                    }
                }

                let targets: Vec<usize> = match occ {
                    "all" => match_indices,
                    "last" => match_indices.last().copied().into_iter().collect(),
                    _ => match_indices.into_iter().take(1).collect(),
                };

                for &line_idx in targets.iter().rev() {
                    let new_line = if is_regex {
                        if let Ok(re) = Regex::new(find) {
                            re.replace_all(&lines[line_idx], replace_with).to_string()
                        } else {
                            lines[line_idx].clone()
                        }
                    } else {
                        lines[line_idx].replace(find, replace_with)
                    };
                    resolved.push(ResolvedEdit {
                        index: idx,
                        op: op.clone(),
                        start_line: line_idx,
                        end_line: line_idx,
                        new_content: Some(vec![new_line]),
                    });
                }
            }
            "insert" => {
                let anchor = &edit["anchor"];
                let insert_content = edit["content"].as_str().unwrap_or("");
                let insert_lines: Vec<String> =
                    insert_content.lines().map(|s| s.to_string()).collect();

                let insert_at = if let Some(line_num) = anchor.get("line").and_then(|v| v.as_u64())
                {
                    Some((line_num as usize).saturating_sub(1))
                } else if let Some(pattern) = anchor.get("after").and_then(|v| v.as_str()) {
                    lines
                        .iter()
                        .position(|l| l.contains(pattern))
                        .map(|i| i + 1)
                } else if let Some(pattern) = anchor.get("before").and_then(|v| v.as_str()) {
                    lines.iter().position(|l| l.contains(pattern))
                } else if let Some(pos) = anchor.get("position").and_then(|v| v.as_str()) {
                    match pos {
                        "start" => Some(0),
                        "end" => Some(lines.len()),
                        _ => None,
                    }
                } else {
                    None
                };

                if let Some(at) = insert_at {
                    resolved.push(ResolvedEdit {
                        index: idx,
                        op: op.clone(),
                        start_line: at,
                        end_line: at, // insertion point
                        new_content: Some(insert_lines),
                    });
                } else {
                    results.push(json!({
                        "op": op,
                        "success": false,
                        "lines_affected": 0,
                        "error": "Anchor pattern not found.",
                    }));
                }
            }
            "patch_lines" => {
                let start = edit["start_line"].as_u64().unwrap_or(0) as usize;
                let end = edit["end_line"].as_u64().unwrap_or(0) as usize;
                let content_str = edit["content"].as_str().unwrap_or("");
                let new_lines: Vec<String> = content_str.lines().map(|s| s.to_string()).collect();

                if start > 0 && end >= start && start <= lines.len() {
                    resolved.push(ResolvedEdit {
                        index: idx,
                        op: op.clone(),
                        start_line: start - 1,
                        end_line: (end - 1).min(lines.len() - 1),
                        new_content: Some(new_lines),
                    });
                } else {
                    results.push(json!({
                        "op": op,
                        "success": false,
                        "lines_affected": 0,
                        "error": "Invalid line range.",
                    }));
                }
            }
            "delete_lines" => {
                let start = edit["start_line"].as_u64().unwrap_or(0) as usize;
                let end = edit["end_line"].as_u64().unwrap_or(0) as usize;

                if start > 0 && end >= start && start <= lines.len() {
                    resolved.push(ResolvedEdit {
                        index: idx,
                        op: op.clone(),
                        start_line: start - 1,
                        end_line: (end - 1).min(lines.len() - 1),
                        new_content: None,
                    });
                } else {
                    results.push(json!({
                        "op": op,
                        "success": false,
                        "lines_affected": 0,
                        "error": "Invalid line range.",
                    }));
                }
            }
            _ => {
                results.push(json!({
                    "op": op,
                    "success": false,
                    "lines_affected": 0,
                    "error": format!("Unknown operation: {}", op),
                }));
            }
        }
    }

    // Sort resolved edits by start_line descending (bottom-to-top)
    resolved.sort_by(|a, b| b.start_line.cmp(&a.start_line));

    // Apply edits (or preview)
    for edit in &resolved {
        let lines_affected;
        match edit.op.as_str() {
            "replace" => {
                if let Some(ref new_content) = edit.new_content {
                    if !dry_run {
                        lines[edit.start_line] = new_content[0].clone();
                    }
                    lines_affected = 1;
                } else {
                    lines_affected = 0;
                }
            }
            "insert" => {
                if let Some(ref new_content) = edit.new_content {
                    lines_affected = new_content.len();
                    if !dry_run {
                        for (i, line) in new_content.iter().enumerate() {
                            let pos = edit.start_line + i;
                            if pos <= lines.len() {
                                lines.insert(pos, line.clone());
                            } else {
                                lines.push(line.clone());
                            }
                        }
                    }
                } else {
                    lines_affected = 0;
                }
            }
            "patch_lines" => {
                let old_range = edit.end_line - edit.start_line + 1;
                if let Some(ref new_content) = edit.new_content {
                    lines_affected = old_range.max(new_content.len());
                    if !dry_run {
                        let end_idx = (edit.end_line + 1).min(lines.len());
                        lines.drain(edit.start_line..end_idx);
                        for (i, line) in new_content.iter().enumerate() {
                            lines.insert(edit.start_line + i, line.clone());
                        }
                    }
                } else {
                    lines_affected = old_range;
                }
            }
            "delete_lines" => {
                lines_affected = edit.end_line - edit.start_line + 1;
                if !dry_run {
                    let end_idx = (edit.end_line + 1).min(lines.len());
                    lines.drain(edit.start_line..end_idx);
                }
            }
            _ => {
                lines_affected = 0;
            }
        }

        edits_applied += 1;
        results.push(json!({
            "op": edit.op,
            "success": true,
            "lines_affected": lines_affected,
        }));
    }

    if !dry_run {
        let new_content = lines.join("\n");
        let final_content = if text.ends_with('\n') && !new_content.ends_with('\n') {
            new_content + "\n"
        } else {
            new_content
        };
        super::atomic_write(&canonical, final_content.as_bytes())?;
    }

    // Sort results back by original index
    // (results from resolved edits were added in reverse order)
    // We'll just return them as-is since the order is informational

    Ok(json!({
        "edits_applied": edits_applied,
        "results": results,
        "dry_run": dry_run,
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
            runtime: Default::default(),
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
    fn test_file_replace_literal() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_replace_test.txt");
        fs::write(&path, "hello world\nhello again\ngoodbye").unwrap();

        let result = file_replace(
            &guard,
            &config,
            &path.to_string_lossy(),
            "hello",
            "hi",
            Some(false),
            Some("all".into()),
        )
        .unwrap();

        assert_eq!(result["replacements_made"], 2);
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("hi world"));
        assert!(content.contains("hi again"));

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_replace_first_only() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_replace_first.txt");
        fs::write(&path, "aaa\naaa\naaa").unwrap();

        let result = file_replace(
            &guard,
            &config,
            &path.to_string_lossy(),
            "aaa",
            "bbb",
            Some(false),
            Some("first".into()),
        )
        .unwrap();

        assert_eq!(result["replacements_made"], 1);
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("bbb"));
        assert!(content.contains("aaa"));

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_insert_after() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_insert_test.txt");
        fs::write(&path, "line1\nline2\nline3").unwrap();

        let result = file_insert(
            &guard,
            &config,
            &path.to_string_lossy(),
            "INSERTED",
            json!({"after": "line2"}),
            None,
            None,
        )
        .unwrap();

        assert_eq!(result["lines_added"], 1);
        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines[2], "INSERTED");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_append() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_append_test.txt");
        fs::write(&path, "line1\nline2").unwrap();

        let result = file_append(&guard, &path.to_string_lossy(), "line3", Some(true)).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("line3"));
        assert!(result["bytes_appended"].as_u64().unwrap() > 0);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_patch_lines() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_patch_test.txt");
        fs::write(&path, "line1\nline2\nline3\nline4\nline5").unwrap();

        let result = file_patch_lines(
            &guard,
            &config,
            &path.to_string_lossy(),
            2,
            4,
            "new2\nnew3",
            None,
        )
        .unwrap();

        assert_eq!(result["old_line_count"], 3);
        assert_eq!(result["new_line_count"], 2);
        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[1], "new2");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_batch_edit() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_batch_test.txt");
        fs::write(&path, "alpha\nbeta\ngamma\ndelta\nepsilon").unwrap();

        let edits = vec![
            json!({"op": "replace", "find": "alpha", "replace": "ALPHA"}),
            json!({"op": "delete_lines", "start_line": 4, "end_line": 4}),
        ];

        let result =
            file_batch_edit(&guard, &config, &path.to_string_lossy(), edits, Some(false)).unwrap();

        assert_eq!(result["edits_applied"], 2);
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("ALPHA"));
        assert!(!content.contains("delta"));

        fs::remove_file(&path).ok();
    }

    // ── Bug fix tests ──

    #[test]
    fn test_file_replace_multiline_literal() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_replace_multiline.txt");
        fs::write(&path, "line1\nline2\nline3\nline4\nline5").unwrap();

        let result = file_replace(
            &guard,
            &config,
            &path.to_string_lossy(),
            "line2\nline3",
            "REPLACED",
            Some(false),
            Some("all".into()),
        )
        .unwrap();

        assert_eq!(result["replacements_made"], 1);
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("REPLACED"));
        assert!(!content.contains("line2"));
        assert!(!content.contains("line3"));
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 4); // line1, REPLACED, line4, line5

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_replace_multiline_with_crlf() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_replace_multiline_crlf.txt");
        // File has \r\n line endings (Windows)
        fs::write(&path, "line1\r\nline2\r\nline3\r\nline4").unwrap();

        // Find pattern uses \n (as sent by MCP client)
        let result = file_replace(
            &guard,
            &config,
            &path.to_string_lossy(),
            "line2\nline3",
            "REPLACED",
            Some(false),
            Some("all".into()),
        )
        .unwrap();

        assert_eq!(result["replacements_made"], 1);
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("REPLACED"));

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_replace_multiline_with_replacement_newlines() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_replace_ml_repl.txt");
        fs::write(&path, "AAA\nBBB\nCCC\nDDD").unwrap();

        let result = file_replace(
            &guard,
            &config,
            &path.to_string_lossy(),
            "BBB\nCCC",
            "XXX\nYYY\nZZZ",
            Some(false),
            Some("all".into()),
        )
        .unwrap();

        assert_eq!(result["replacements_made"], 1);
        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines, vec!["AAA", "XXX", "YYY", "ZZZ", "DDD"]);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_replace_multiline_first_occurrence() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_replace_ml_first.txt");
        fs::write(&path, "AB\nCD\nAB\nCD\nEF").unwrap();

        let result = file_replace(
            &guard,
            &config,
            &path.to_string_lossy(),
            "AB\nCD",
            "XX",
            Some(false),
            Some("first".into()),
        )
        .unwrap();

        assert_eq!(result["replacements_made"], 1);
        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines, vec!["XX", "AB", "CD", "EF"]);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_replace_multiline_last_occurrence() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_replace_ml_last.txt");
        fs::write(&path, "AB\nCD\nAB\nCD\nEF").unwrap();

        let result = file_replace(
            &guard,
            &config,
            &path.to_string_lossy(),
            "AB\nCD",
            "XX",
            Some(false),
            Some("last".into()),
        )
        .unwrap();

        assert_eq!(result["replacements_made"], 1);
        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines, vec!["AB", "CD", "XX", "EF"]);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_insert_anchor_as_string() {
        // Bug 2: anchor arrives as a JSON string from some MCP clients
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_insert_str_anchor.txt");
        fs::write(&path, "line1\nline2\nline3").unwrap();

        // Simulate anchor serialized as a string (as Claude Web UI sends it)
        let anchor = serde_json::Value::String(r#"{"after": "line2"}"#.to_string());
        let result = file_insert(
            &guard,
            &config,
            &path.to_string_lossy(),
            "INSERTED",
            anchor,
            None,
            None,
        )
        .unwrap();

        assert_eq!(result["lines_added"], 1);
        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines[2], "INSERTED");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_insert_anchor_string_line() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_insert_str_line.txt");
        fs::write(&path, "line1\nline2\nline3").unwrap();

        let anchor = serde_json::Value::String(r#"{"line": 2}"#.to_string());
        let result = file_insert(
            &guard,
            &config,
            &path.to_string_lossy(),
            "INSERTED",
            anchor,
            None,
            None,
        )
        .unwrap();

        assert_eq!(result["lines_added"], 1);
        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines[2], "INSERTED"); // line param is used as direct index (0-indexed insert position)

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_insert_anchor_string_position() {
        let config = test_config();
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_insert_str_pos.txt");
        fs::write(&path, "line1\nline2").unwrap();

        let anchor = serde_json::Value::String(r#"{"position": "end"}"#.to_string());
        let result = file_insert(
            &guard,
            &config,
            &path.to_string_lossy(),
            "APPENDED",
            anchor,
            None,
            None,
        )
        .unwrap();

        assert_eq!(result["lines_added"], 1);
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.ends_with("APPENDED"));

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_atomic_write_creates_file_no_temp() {
        let path = std::env::temp_dir().join("surgicalfs_atomic_create.txt");
        let tmp = std::env::temp_dir().join("surgicalfs_atomic_create.txt.surgicalfs-tmp");
        fs::remove_file(&path).ok();
        fs::remove_file(&tmp).ok();

        crate::tools::atomic_write(&path, b"hello world").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello world");
        assert!(
            !tmp.exists(),
            "temp file must not remain after a successful write"
        );

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_atomic_write_overwrites_existing_no_temp() {
        let path = std::env::temp_dir().join("surgicalfs_atomic_overwrite.txt");
        let tmp = std::env::temp_dir().join("surgicalfs_atomic_overwrite.txt.surgicalfs-tmp");
        fs::remove_file(&tmp).ok();
        fs::write(&path, "old content").unwrap();

        crate::tools::atomic_write(&path, b"new content").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new content");
        assert!(
            !tmp.exists(),
            "temp file must not remain after an overwrite"
        );

        fs::remove_file(&path).ok();
    }
}
