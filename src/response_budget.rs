use crate::config::ResponseBudgetConfig;
use serde_json::json;

/// Apply response budget limits to tool output text.
/// Truncates if the text exceeds max_response_lines or max_response_bytes.
/// Appends a `_truncated` metadata JSON object when truncation occurs.
pub fn apply_response_budget(response: String, config: &ResponseBudgetConfig) -> String {
    let max_lines = config.max_response_lines;
    let max_bytes = config.max_response_bytes;

    // 0 means unlimited
    if max_lines == 0 && max_bytes == 0 {
        return response;
    }

    let lines: Vec<&str> = response.lines().collect();
    let total_lines = lines.len() as u32;
    let total_bytes = response.len() as u32;

    let over_lines = max_lines > 0 && total_lines > max_lines;
    let over_bytes = max_bytes > 0 && total_bytes > max_bytes;

    if !over_lines && !over_bytes {
        return response;
    }

    match config.truncation_mode.as_str() {
        "hard" => truncate_hard(&response, total_lines, max_lines, max_bytes),
        _ => truncate_smart(&response, &lines, total_lines, max_lines, max_bytes),
    }
}

fn truncate_smart(
    response: &str,
    lines: &[&str],
    total_lines: u32,
    max_lines: u32,
    max_bytes: u32,
) -> String {
    // First apply line limit
    let line_limited = if max_lines > 0 && total_lines > max_lines {
        let kept: Vec<&str> = lines.iter().take(max_lines as usize).copied().collect();
        kept.join("\n")
    } else {
        response.to_string()
    };

    // Then apply byte limit (find last newline before the limit)
    let result = if max_bytes > 0 && line_limited.len() as u32 > max_bytes {
        let bytes = line_limited.as_bytes();
        let limit = max_bytes as usize;
        // Find last newline before limit
        let cut_point = bytes[..limit]
            .iter()
            .rposition(|&b| b == b'\n')
            .unwrap_or_else(|| {
                // No newline found — find a valid char boundary at or before limit
                let mut cut = limit;
                while cut > 0 && !line_limited.is_char_boundary(cut) {
                    cut -= 1;
                }
                cut
            });
        line_limited[..cut_point].to_string()
    } else {
        line_limited
    };

    let returned_lines = result.lines().count() as u32;
    let remaining_from = returned_lines + 1;

    let truncated_meta = json!({
        "_truncated": {
            "original_lines": total_lines,
            "returned_lines": returned_lines,
            "remaining_from_line": remaining_from,
            "hint": format!("Use file_read_lines(path, {}, {}) to continue reading.", remaining_from, remaining_from + max_lines.max(200) - 1)
        }
    });

    format!(
        "{}\n{}",
        result,
        serde_json::to_string(&truncated_meta).unwrap_or_else(|_| {
            r#"{"_truncated":{"error":"failed to serialize metadata"}}"#.to_string()
        })
    )
}

fn truncate_hard(response: &str, total_lines: u32, max_lines: u32, max_bytes: u32) -> String {
    let mut result = response.to_string();

    // Apply line limit
    if max_lines > 0 && total_lines > max_lines {
        let lines: Vec<&str> = response.lines().take(max_lines as usize).collect();
        result = lines.join("\n");
    }

    // Apply byte limit (ensure we cut at a valid char boundary)
    if max_bytes > 0 && result.len() as u32 > max_bytes {
        let mut cut = max_bytes as usize;
        while cut > 0 && !result.is_char_boundary(cut) {
            cut -= 1;
        }
        result = result[..cut].to_string();
    }

    let returned_lines = result.lines().count() as u32;
    let remaining_from = returned_lines + 1;

    let truncated_meta = json!({
        "_truncated": {
            "original_lines": total_lines,
            "returned_lines": returned_lines,
            "remaining_from_line": remaining_from,
            "hint": format!("Use file_read_lines(path, {}, {}) to continue reading.", remaining_from, remaining_from + max_lines.max(200) - 1)
        }
    });

    format!(
        "{}\n{}",
        result,
        serde_json::to_string(&truncated_meta).unwrap_or_else(|_| {
            r#"{"_truncated":{"error":"failed to serialize metadata"}}"#.to_string()
        })
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(lines: u32, bytes: u32, mode: &str) -> ResponseBudgetConfig {
        ResponseBudgetConfig {
            max_response_lines: lines,
            max_response_bytes: bytes,
            truncation_mode: mode.to_string(),
        }
    }

    #[test]
    fn test_within_budget_unchanged() {
        let config = make_config(10, 1000, "smart");
        let input = "line1\nline2\nline3".to_string();
        let result = apply_response_budget(input.clone(), &config);
        assert_eq!(result, input);
    }

    #[test]
    fn test_unlimited_unchanged() {
        let config = make_config(0, 0, "smart");
        let long = (0..1000)
            .map(|i| format!("line {}", i))
            .collect::<Vec<_>>()
            .join("\n");
        let result = apply_response_budget(long.clone(), &config);
        assert_eq!(result, long);
    }

    #[test]
    fn test_smart_truncation_by_lines() {
        let config = make_config(3, 0, "smart");
        let input = "line1\nline2\nline3\nline4\nline5".to_string();
        let result = apply_response_budget(input, &config);
        assert!(result.contains("line1"));
        assert!(result.contains("line3"));
        assert!(result.contains("_truncated"));
        assert!(result.contains("\"original_lines\":5"));
    }

    #[test]
    fn test_hard_truncation_by_bytes() {
        let config = make_config(0, 20, "hard");
        let input = "abcdefghij\nklmnopqrst\nuvwxyz".to_string();
        let result = apply_response_budget(input, &config);
        assert!(result.contains("_truncated"));
    }

    #[test]
    fn test_smart_truncation_cuts_at_newline() {
        let config = make_config(0, 15, "smart");
        let input = "short\nlonger line here\nthird".to_string();
        let result = apply_response_budget(input, &config);
        // Should cut at newline before byte 15
        assert!(result.starts_with("short"));
        assert!(result.contains("_truncated"));
    }
}
