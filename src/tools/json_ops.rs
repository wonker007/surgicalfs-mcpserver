use crate::errors::{ErrorCode, SurgicalError, SurgicalResult};
use crate::pathguard::PathGuard;
use serde_json::json;
use serde_json_path::JsonPath;
use std::fs;

/// Query a JSON file using JSONPath (RFC 9535).
pub fn json_query(
    path_guard: &PathGuard,
    path: &str,
    query: &str,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let content =
        fs::read_to_string(&canonical).map_err(|e| SurgicalError::io_error(&e, "Read failed"))?;

    let json_value: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
        SurgicalError::new(
            ErrorCode::InternalError,
            format!("Invalid JSON: {}", e),
            "Ensure the file contains valid JSON.",
        )
    })?;

    let json_path = JsonPath::parse(query).map_err(|e| {
        SurgicalError::new(
            ErrorCode::JsonPathInvalid,
            format!("Invalid JSONPath '{}': {}", query, e),
            "Check JSONPath syntax (RFC 9535). Example: $.store.book[0].title",
        )
    })?;

    let node_list = json_path.query(&json_value);
    let results: Vec<serde_json::Value> = node_list
        .all()
        .iter()
        .map(|node| {
            json!({
                "value": *node,
            })
        })
        .collect();

    let count = results.len();

    if count == 0 {
        return Err(SurgicalError::new(
            ErrorCode::JsonPathNoMatch,
            format!("JSONPath '{}' matched no nodes.", query),
            "Verify the path exists in the JSON structure. Use $.* to explore top-level keys.",
        ));
    }

    Ok(json!({
        "results": results,
        "count": count,
    }))
}

/// Mutate a JSON file at specific JSONPath locations.
pub fn json_mutate(
    path_guard: &PathGuard,
    path: &str,
    operations: Vec<serde_json::Value>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let content =
        fs::read_to_string(&canonical).map_err(|e| SurgicalError::io_error(&e, "Read failed"))?;

    let mut json_value: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
        SurgicalError::new(
            ErrorCode::InternalError,
            format!("Invalid JSON: {}", e),
            "Ensure the file contains valid JSON.",
        )
    })?;

    let mut mutations: Vec<serde_json::Value> = Vec::new();
    let mut ops_applied = 0u32;

    for op_def in &operations {
        let op = op_def["op"].as_str().unwrap_or("unknown");
        let query = op_def["query"].as_str().unwrap_or("$");

        let result = match op {
            "set" => {
                let value = op_def
                    .get("value")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                apply_set(&mut json_value, query, value)
            }
            "delete" => apply_delete(&mut json_value, query),
            "insert" => {
                let value = op_def
                    .get("value")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let index = op_def["index"].as_u64().map(|i| i as usize);
                apply_array_insert(&mut json_value, query, value, index)
            }
            "append" => {
                let value = op_def
                    .get("value")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                apply_array_append(&mut json_value, query, value)
            }
            _ => Err(format!("Unknown operation: {}", op)),
        };

        match result {
            Ok(()) => {
                ops_applied += 1;
                mutations.push(json!({
                    "op": op,
                    "query": query,
                    "success": true,
                }));
            }
            Err(e) => {
                mutations.push(json!({
                    "op": op,
                    "query": query,
                    "success": false,
                    "error": e,
                }));
            }
        }
    }

    // Write back with pretty printing (2-space indent)
    let output = serde_json::to_string_pretty(&json_value).map_err(|e| {
        SurgicalError::new(
            ErrorCode::InternalError,
            format!("JSON serialization failed: {}", e),
            "Internal error.",
        )
    })?;

    super::atomic_write(&canonical, output.as_bytes())?;

    Ok(json!({
        "operations_applied": ops_applied,
        "mutations": mutations,
    }))
}

/// Navigate a JSON value using path segments and set a value.
fn apply_set(
    root: &mut serde_json::Value,
    query: &str,
    value: serde_json::Value,
) -> Result<(), String> {
    let segments = parse_json_path_segments(query)?;
    if segments.is_empty() {
        *root = value;
        return Ok(());
    }

    let target = navigate_mut(root, &segments[..segments.len() - 1])?;
    let last = &segments[segments.len() - 1];

    match last {
        PathSegment::Key(key) => {
            if let serde_json::Value::Object(map) = target {
                map.insert(key.clone(), value);
                Ok(())
            } else {
                Err(format!("Cannot set key '{}' on non-object.", key))
            }
        }
        PathSegment::Index(idx) => {
            if let serde_json::Value::Array(arr) = target {
                if *idx < arr.len() {
                    arr[*idx] = value;
                    Ok(())
                } else {
                    Err(format!(
                        "Index {} out of bounds (array has {} elements).",
                        idx,
                        arr.len()
                    ))
                }
            } else {
                Err("Cannot index into non-array.".into())
            }
        }
    }
}

fn apply_delete(root: &mut serde_json::Value, query: &str) -> Result<(), String> {
    let segments = parse_json_path_segments(query)?;
    if segments.is_empty() {
        return Err("Cannot delete root.".into());
    }

    let target = navigate_mut(root, &segments[..segments.len() - 1])?;
    let last = &segments[segments.len() - 1];

    match last {
        PathSegment::Key(key) => {
            if let serde_json::Value::Object(map) = target {
                map.remove(key)
                    .ok_or_else(|| format!("Key '{}' not found.", key))?;
                Ok(())
            } else {
                Err("Cannot delete key from non-object.".into())
            }
        }
        PathSegment::Index(idx) => {
            if let serde_json::Value::Array(arr) = target {
                if *idx < arr.len() {
                    arr.remove(*idx);
                    Ok(())
                } else {
                    Err(format!("Index {} out of bounds.", idx))
                }
            } else {
                Err("Cannot delete index from non-array.".into())
            }
        }
    }
}

fn apply_array_insert(
    root: &mut serde_json::Value,
    query: &str,
    value: serde_json::Value,
    index: Option<usize>,
) -> Result<(), String> {
    let segments = parse_json_path_segments(query)?;
    let target = navigate_mut(root, &segments)?;

    if let serde_json::Value::Array(arr) = target {
        let idx = index.unwrap_or(0).min(arr.len());
        arr.insert(idx, value);
        Ok(())
    } else {
        Err("Target is not an array.".into())
    }
}

fn apply_array_append(
    root: &mut serde_json::Value,
    query: &str,
    value: serde_json::Value,
) -> Result<(), String> {
    let segments = parse_json_path_segments(query)?;
    let target = navigate_mut(root, &segments)?;

    if let serde_json::Value::Array(arr) = target {
        arr.push(value);
        Ok(())
    } else {
        Err("Target is not an array.".into())
    }
}

#[derive(Debug)]
enum PathSegment {
    Key(String),
    Index(usize),
}

/// Parse a JSONPath-like string into segments.
/// Supports: $.key1.key2[0].key3
fn parse_json_path_segments(query: &str) -> Result<Vec<PathSegment>, String> {
    let query = query.trim();
    if query == "$" {
        return Ok(vec![]);
    }

    let stripped = query.strip_prefix('$').unwrap_or(query);
    let stripped = stripped.strip_prefix('.').unwrap_or(stripped);

    let mut segments = Vec::new();
    let mut current = String::new();

    let chars: Vec<char> = stripped.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '.' => {
                if !current.is_empty() {
                    segments.push(PathSegment::Key(current.clone()));
                    current.clear();
                }
            }
            '[' => {
                if !current.is_empty() {
                    segments.push(PathSegment::Key(current.clone()));
                    current.clear();
                }
                // Parse index
                i += 1;
                let mut idx_str = String::new();
                while i < chars.len() && chars[i] != ']' {
                    idx_str.push(chars[i]);
                    i += 1;
                }
                // Remove quotes if present (for ['key'] notation)
                let idx_str = idx_str.trim_matches(|c: char| c == '\'' || c == '"');
                if let Ok(idx) = idx_str.parse::<usize>() {
                    segments.push(PathSegment::Index(idx));
                } else {
                    segments.push(PathSegment::Key(idx_str.to_string()));
                }
            }
            _ => {
                current.push(chars[i]);
            }
        }
        i += 1;
    }

    if !current.is_empty() {
        segments.push(PathSegment::Key(current));
    }

    Ok(segments)
}

fn navigate_mut<'a>(
    root: &'a mut serde_json::Value,
    segments: &[PathSegment],
) -> Result<&'a mut serde_json::Value, String> {
    let mut current = root;
    for segment in segments {
        match segment {
            PathSegment::Key(key) => {
                current = current
                    .get_mut(key)
                    .ok_or_else(|| format!("Key '{}' not found.", key))?;
            }
            PathSegment::Index(idx) => {
                current = current
                    .get_mut(*idx)
                    .ok_or_else(|| format!("Index {} out of bounds.", idx))?;
            }
        }
    }
    Ok(current)
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
    fn test_json_query() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_json_query.json");
        let data = json!({"name": "test", "items": [1, 2, 3]});
        fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();

        let result = json_query(&guard, &path.to_string_lossy(), "$.name").unwrap();
        assert_eq!(result["count"], 1);
        assert_eq!(result["results"][0]["value"], "test");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_json_mutate_set() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_json_mutate.json");
        let data = json!({"name": "old", "count": 1});
        fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();

        let ops = vec![json!({"op": "set", "query": "$.name", "value": "new"})];
        let result = json_mutate(&guard, &path.to_string_lossy(), ops).unwrap();
        assert_eq!(result["operations_applied"], 1);

        let content = fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["name"], "new");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_json_mutate_delete() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_json_delete.json");
        let data = json!({"keep": true, "remove": false});
        fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();

        let ops = vec![json!({"op": "delete", "query": "$.remove"})];
        let result = json_mutate(&guard, &path.to_string_lossy(), ops).unwrap();
        assert_eq!(result["operations_applied"], 1);

        let content = fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(parsed.get("remove").is_none());

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_json_mutate_array_append() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_json_append.json");
        let data = json!({"items": [1, 2]});
        fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();

        let ops = vec![json!({"op": "append", "query": "$.items", "value": 3})];
        let result = json_mutate(&guard, &path.to_string_lossy(), ops).unwrap();
        assert_eq!(result["operations_applied"], 1);

        let content = fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["items"].as_array().unwrap().len(), 3);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_parse_json_path_segments() {
        let segments = parse_json_path_segments("$.store.book[0].title").unwrap();
        assert_eq!(segments.len(), 4);
        if let PathSegment::Key(k) = &segments[0] {
            assert_eq!(k, "store");
        }
        if let PathSegment::Key(k) = &segments[1] {
            assert_eq!(k, "book");
        }
        if let PathSegment::Index(i) = &segments[2] {
            assert_eq!(*i, 0);
        }
        if let PathSegment::Key(k) = &segments[3] {
            assert_eq!(k, "title");
        }
    }
}
