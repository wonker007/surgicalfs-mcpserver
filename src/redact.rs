//! Positive-allowlist arg redaction for the `/events` SSE stream (DEC-DRAFT-N).
//! NEVER emit raw file content, search patterns, or replacement text.
//!
//! The activity feed shows *what kind* of call happened, not its payload. Only an
//! explicit allowlist of non-sensitive metadata fields passes through verbatim;
//! paths are reduced to their basename; known content-bearing fields are shown as
//! a byte count; everything else is dropped. This is a positive allowlist (a new
//! tool param can never accidentally leak) plus a redaction list for the common
//! content fields so they at least show a size rather than vanishing silently.
//!
//! The arg map is rmcp's `CallToolRequestParams.arguments`
//! (`Option<serde_json::Map<String, Value>>`), passed straight through from
//! `server::call_tool` before the request is consumed.

/// Produce a compact, safe summary of tool-call arguments.
/// Only non-sensitive metadata fields pass through; everything else is elided.
pub fn summarize_args(
    _tool: &str,
    args: Option<&serde_json::Map<String, serde_json::Value>>,
) -> String {
    let obj = match args {
        Some(o) => o,
        None => return String::new(),
    };

    let mut parts: Vec<String> = Vec::new();

    // Path — basename only (DEC-DRAFT-N: "Paths: basename only by default").
    if let Some(p) = obj.get("path").and_then(|v| v.as_str()) {
        let basename = std::path::Path::new(p)
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_else(|| p.to_string());
        parts.push(format!("path:{basename}"));
    }

    // Safe numeric/string/bool metadata fields (positive allowlist).
    for key in ALLOWED_FIELDS {
        if let Some(v) = obj.get(*key) {
            if let Some(s) = v.as_str() {
                parts.push(format!("{key}:{s}"));
            } else if v.is_number() || v.is_boolean() {
                parts.push(format!("{key}:{v}"));
            }
        }
    }

    // Redacted content fields — show size only, never the value.
    for key in REDACTED_FIELDS {
        if let Some(v) = obj.get(*key) {
            let size = match v {
                serde_json::Value::String(s) => s.len(),
                other => other.to_string().len(),
            };
            parts.push(format!("{key}:<{size} bytes>"));
        }
    }

    parts.join(", ")
}

/// Fields safe to emit as-is (non-sensitive metadata).
const ALLOWED_FIELDS: &[&str] = &[
    "start_line",
    "end_line",
    "lines",
    "max_results",
    "offset",
    "depth",
    "mode",
    "encoding",
    "key",
    "sheet",
    "range",
    "include_content",
    "case_sensitive",
    "is_regex",
    "recursive",
    "follow_symlinks",
    "return_mode",
    "head",
    "tail",
];

/// Fields that MUST be redacted (sensitive content).
const REDACTED_FIELDS: &[&str] = &[
    "content",
    "find",
    "replace",
    "pattern",
    "value",
    "rows",
    "edits",
    "operations",
    "old_text",
    "new_text",
    "old_content",
    "new_content",
    "file_text",
    "text",
];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Helper: build a `&Map` from a JSON object literal.
    fn obj(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn none_args_is_empty() {
        assert_eq!(summarize_args("file_info", None), "");
    }

    #[test]
    fn empty_map_is_empty() {
        let m = obj(json!({}));
        assert_eq!(summarize_args("file_info", Some(&m)), "");
    }

    #[test]
    fn path_is_basename_only() {
        let m = obj(json!({ "path": "C:\\Users\\secret\\projects\\db.sqlite" }));
        let s = summarize_args("file_info", Some(&m));
        assert_eq!(s, "path:db.sqlite");
        // The directory portion (which may be sensitive) must not leak.
        assert!(!s.contains("secret"));
        assert!(!s.contains("Users"));
    }

    #[test]
    fn unix_path_is_basename_only() {
        let m = obj(json!({ "path": "/home/user/.ssh/id_rsa" }));
        let s = summarize_args("read_file", Some(&m));
        assert_eq!(s, "path:id_rsa");
    }

    #[test]
    fn content_is_redacted_to_size() {
        let secret = "TOP SECRET PAYLOAD";
        let m = obj(json!({ "path": "/a/b.txt", "content": secret }));
        let s = summarize_args("file_write", Some(&m));
        assert!(s.contains("path:b.txt"), "got: {s}");
        assert!(
            s.contains(&format!("content:<{} bytes>", secret.len())),
            "got: {s}"
        );
        // The actual content must never appear.
        assert!(!s.contains("SECRET"), "leaked content: {s}");
    }

    #[test]
    fn mixed_allowed_and_redacted_fields() {
        let m = obj(json!({
            "path": "/proj/src/main.rs",
            "start_line": 10,
            "end_line": 20,
            "max_results": 100,
            "case_sensitive": true,
            "mode": "lines",
            "find": "needle",
            "replace": "haystack"
        }));
        let s = summarize_args("file_replace", Some(&m));
        assert!(s.contains("path:main.rs"), "got: {s}");
        assert!(s.contains("start_line:10"), "got: {s}");
        assert!(s.contains("end_line:20"), "got: {s}");
        assert!(s.contains("max_results:100"), "got: {s}");
        assert!(s.contains("case_sensitive:true"), "got: {s}");
        assert!(s.contains("mode:lines"), "got: {s}");
        assert!(s.contains("find:<6 bytes>"), "got: {s}"); // "needle" = 6
        assert!(s.contains("replace:<8 bytes>"), "got: {s}"); // "haystack" = 8
                                                              // Neither the search nor the replacement text may leak.
        assert!(!s.contains("needle"), "leaked find: {s}");
        assert!(!s.contains("haystack"), "leaked replace: {s}");
    }

    #[test]
    fn nested_object_value_is_redacted_by_size() {
        let m = obj(json!({ "value": { "deep": { "secret": 42 } } }));
        let s = summarize_args("json_mutate", Some(&m));
        assert!(s.starts_with("value:<"), "got: {s}");
        assert!(s.ends_with(" bytes>"), "got: {s}");
        assert!(!s.contains("secret"), "leaked nested key: {s}");
        assert!(!s.contains("42"), "leaked nested value: {s}");
    }

    #[test]
    fn unknown_fields_are_dropped() {
        // A field that is neither allowlisted nor in the redaction list (e.g. a
        // future param) must not pass through at all.
        let m = obj(json!({ "surprise_new_param": "leak me", "max_results": 5 }));
        let s = summarize_args("file_search", Some(&m));
        assert_eq!(s, "max_results:5");
        assert!(!s.contains("leak me"), "leaked unknown field: {s}");
    }
}
