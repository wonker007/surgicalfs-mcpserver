//! Comprehensive smoke tests for SurgicalFS MCP tool functions.
//!
//! These tests exercise the tool functions directly (not through the MCP server),
//! validating security guards, file operations, JSON/CSV ops, and compat wrappers.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;
use surgicalfs_mcp::config::{
    self, Config, DefaultsConfig, ResponseBudgetConfig, SearchConfig, SecurityConfig, ToolsConfig,
};
use surgicalfs_mcp::pathguard::PathGuard;
use surgicalfs_mcp::response_budget::apply_response_budget;
use surgicalfs_mcp::tools::{
    compat, csv_ops, directory, inspect, json_ops, manage, mutate, utility,
};

// ─── Fixture Setup / Teardown ────────────────────────────────────────────────

use std::sync::atomic::{AtomicU32, Ordering};
static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Build the complete fixture tree and return (root, allowed_dir, forbidden_dir).
/// Each call gets a unique directory to avoid parallel test interference.
fn setup_fixtures() -> (PathBuf, PathBuf, PathBuf) {
    let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let root = std::env::temp_dir().join(format!("surgicalfs_smoke_{}", id));
    let allowed = root.join("allowed");
    let forbidden = root.join("forbidden");

    // Clean up any prior run
    let _ = fs::remove_dir_all(&root);

    // Create directory structure
    fs::create_dir_all(allowed.join("text_files")).unwrap();
    fs::create_dir_all(allowed.join("code_files")).unwrap();
    fs::create_dir_all(allowed.join("json_files")).unwrap();
    fs::create_dir_all(allowed.join("csv_files")).unwrap();
    fs::create_dir_all(allowed.join("binary_files")).unwrap();
    fs::create_dir_all(allowed.join("nested").join("deep")).unwrap();
    fs::create_dir_all(allowed.join("subdir")).unwrap();
    fs::create_dir_all(&forbidden).unwrap();

    // ── Text files ──
    let small_content: String = (1..=10)
        .map(|i| format!("Line {}", i))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(allowed.join("text_files").join("small.txt"), &small_content).unwrap();

    let medium_content: String = (1..=200)
        .map(|i| format!("Medium line {}", i))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(
        allowed.join("text_files").join("medium.txt"),
        &medium_content,
    )
    .unwrap();

    fs::write(allowed.join("text_files").join("empty.txt"), "").unwrap();

    // ── Code file ──
    let rust_code = r#"fn main() {
    let x = 42;
    println!("The answer is {}", x);
}

struct Point {
    x: f64,
    y: f64,
}

impl Point {
    fn distance(&self) -> f64 {
        (self.x * self.x + self.y * self.y).sqrt()
    }
}
"#;
    fs::write(allowed.join("code_files").join("example.rs"), rust_code).unwrap();

    // ── JSON files ──
    let config_json = json!({
        "name": "test-project",
        "version": "1.0.0",
        "database": {
            "host": "localhost",
            "port": 5432,
            "credentials": {
                "user": "admin",
                "password": "secret"
            }
        },
        "features": ["alpha", "beta", "gamma"]
    });
    fs::write(
        allowed.join("json_files").join("config.json"),
        serde_json::to_string_pretty(&config_json).unwrap(),
    )
    .unwrap();

    let array_json = json!([
        {"id": 1, "name": "Alice"},
        {"id": 2, "name": "Bob"},
        {"id": 3, "name": "Charlie"}
    ]);
    fs::write(
        allowed.join("json_files").join("array.json"),
        serde_json::to_string_pretty(&array_json).unwrap(),
    )
    .unwrap();

    // ── CSV file (20 rows, 3 columns) ──
    let mut csv_content = String::from("name,age,city\n");
    let names = [
        "Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace", "Hank", "Ivy", "Jack", "Kate",
        "Leo", "Mia", "Nick", "Olivia", "Paul", "Quinn", "Rose", "Sam", "Tina",
    ];
    let cities = ["NYC", "LA", "Chicago", "Houston", "Phoenix"];
    for (i, name) in names.iter().enumerate() {
        let age = 20 + i;
        let city = cities[i % cities.len()];
        csv_content.push_str(&format!("{},{},{}\n", name, age, city));
    }
    fs::write(allowed.join("csv_files").join("data.csv"), &csv_content).unwrap();

    // ── Binary file ──
    let binary_data: Vec<u8> = (0..256).map(|b| b as u8).collect();
    fs::write(
        allowed.join("binary_files").join("binary.dat"),
        &binary_data,
    )
    .unwrap();

    // ── Nested files ──
    fs::write(
        allowed.join("nested").join("deep").join("file.txt"),
        "deep content",
    )
    .unwrap();
    fs::write(allowed.join("subdir").join("file_a.txt"), "content A").unwrap();
    fs::write(allowed.join("subdir").join("file_b.txt"), "content B").unwrap();

    // ── Forbidden file ──
    fs::write(forbidden.join("secret.txt"), "TOP SECRET DATA").unwrap();

    (root, allowed, forbidden)
}

/// Remove the entire fixture tree.
fn cleanup(root: &Path) {
    let _ = fs::remove_dir_all(root);
}

/// Build a Config pointing at the allowed directory.
fn make_config(allowed: &Path) -> Config {
    Config {
        security: SecurityConfig {
            allowed_directories: vec![allowed.to_string_lossy().to_string()],
            follow_symlinks: false,
            max_file_size: 5_242_880,
            read_only: false,
        },
        search: SearchConfig::default(),
        defaults: DefaultsConfig::default(),
        response_budget: ResponseBudgetConfig::default(),
        tools: Default::default(),
    }
}

/// Build a PathGuard for the allowed directory.
fn make_guard(allowed: &Path) -> PathGuard {
    PathGuard::new(&[allowed.to_string_lossy().to_string()], false, 5_242_880)
        .expect("PathGuard creation should succeed")
}

/// Build a PathGuard with a custom max_file_size.
fn make_guard_with_size(allowed: &Path, max_size: u64) -> PathGuard {
    PathGuard::new(&[allowed.to_string_lossy().to_string()], false, max_size)
        .expect("PathGuard creation should succeed")
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn security_forbidden_directory_rejected() {
    let (root, allowed, forbidden) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);
    let secret = forbidden.join("secret.txt");
    let secret_str = secret.to_string_lossy().to_string();

    // file_info must fail
    let r = inspect::file_info(&guard, &config, &secret_str);
    assert!(r.is_err(), "file_info should reject forbidden path");

    // file_head must fail
    let r = inspect::file_head(&guard, &config, &secret_str, Some(5));
    assert!(r.is_err(), "file_head should reject forbidden path");

    // file_read_lines must fail
    let r = inspect::file_read_lines(&guard, &config, &secret_str, 1, 5);
    assert!(r.is_err(), "file_read_lines should reject forbidden path");

    cleanup(&root);
}

#[test]
fn security_traversal_blocked() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);

    // Attempt to escape using ../../../
    let traversal = allowed
        .join("..")
        .join("..")
        .join("..")
        .join("Windows")
        .join("System32")
        .join("cmd.exe");
    let traversal_str = traversal.to_string_lossy().to_string();

    let r = inspect::file_info(&guard, &config, &traversal_str);
    assert!(r.is_err(), "Traversal path should be denied");

    cleanup(&root);
}

#[test]
fn security_binary_file_guard() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);
    let binary_path = allowed.join("binary_files").join("binary.dat");
    let binary_str = binary_path.to_string_lossy().to_string();

    let r = inspect::file_head(&guard, &config, &binary_str, Some(5));
    assert!(
        r.is_err(),
        "file_head on binary should return BINARY_FILE error"
    );

    // Verify it's specifically the BINARY_FILE error
    let err = r.unwrap_err();
    let err_json = err.0.to_json();
    assert!(
        err_json.contains("BINARY_FILE"),
        "Error should be BINARY_FILE, got: {}",
        err_json
    );

    cleanup(&root);
}

#[test]
fn security_file_size_guard() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    // Use a tiny limit of 100 bytes
    let guard = make_guard_with_size(&allowed, 100);
    let medium_path = allowed.join("text_files").join("medium.txt");
    let medium_str = medium_path.to_string_lossy().to_string();

    // file_head checks file size before reading
    let r = inspect::file_head(&guard, &config, &medium_str, Some(5));
    assert!(
        r.is_err(),
        "file_head should reject file exceeding max_file_size"
    );

    let err = r.unwrap_err();
    let err_json = err.0.to_json();
    assert!(
        err_json.contains("FILE_TOO_LARGE"),
        "Error should be FILE_TOO_LARGE, got: {}",
        err_json
    );

    cleanup(&root);
}

#[test]
fn security_response_budget_truncation() {
    let (root, _allowed, _) = setup_fixtures();

    // Build a response with many actual newlines (one per line), exceeding 10 lines.
    // The response budget operates on real newlines in the string, not JSON-escaped \n.
    let long_response: String = (1..=50)
        .map(|i| format!("output line {}", i))
        .collect::<Vec<_>>()
        .join("\n");

    // Apply a budget of 10 lines
    let budget_config = ResponseBudgetConfig {
        max_response_lines: 10,
        max_response_bytes: 0,
        truncation_mode: "smart".to_string(),
    };
    let truncated = apply_response_budget(long_response, &budget_config);
    assert!(
        truncated.contains("_truncated"),
        "Truncated output should contain _truncated metadata"
    );
    // First 10 lines should be present
    assert!(truncated.contains("output line 1"));
    assert!(truncated.contains("output line 10"));
    // Line 11 should not be present (it was truncated)
    assert!(!truncated.contains("output line 11\n"));

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOOL SMOKE TESTS — Inspect
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn smoke_file_info() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);
    let path = allowed.join("text_files").join("small.txt");
    let path_str = path.to_string_lossy().to_string();

    let result = inspect::file_info(&guard, &config, &path_str).unwrap();

    assert!(
        result["size_bytes"].as_u64().unwrap() > 0,
        "size_bytes should be > 0"
    );
    assert_eq!(result["line_count"], 10, "small.txt should have 10 lines");
    assert_eq!(result["encoding_detected"], "utf-8");

    cleanup(&root);
}

#[test]
fn smoke_file_head() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);
    let path = allowed.join("text_files").join("medium.txt");
    let path_str = path.to_string_lossy().to_string();

    let result = inspect::file_head(&guard, &config, &path_str, Some(3)).unwrap();

    assert_eq!(result["lines_returned"], 3);
    assert_eq!(result["total_lines"], 200);
    assert_eq!(result["truncated"], true);

    cleanup(&root);
}

#[test]
fn smoke_file_tail() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);
    let path = allowed.join("text_files").join("medium.txt");
    let path_str = path.to_string_lossy().to_string();

    let result = inspect::file_tail(&guard, &config, &path_str, Some(3)).unwrap();

    assert_eq!(result["lines_returned"], 3);
    let content = result["content"].as_str().unwrap();
    assert!(
        content.contains("Medium line 200"),
        "Tail should include last line"
    );

    cleanup(&root);
}

#[test]
fn smoke_file_read_lines() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);
    let path = allowed.join("text_files").join("medium.txt");
    let path_str = path.to_string_lossy().to_string();

    let result = inspect::file_read_lines(&guard, &config, &path_str, 5, 10).unwrap();

    assert_eq!(
        result["lines_returned"], 6,
        "Lines 5-10 inclusive = 6 lines"
    );
    let content = result["content"].as_str().unwrap();
    assert!(content.contains("Medium line 5"));
    assert!(content.contains("Medium line 10"));

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOOL SMOKE TESTS — Mutate
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn smoke_file_replace() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);

    // Work on a copy
    let src = allowed.join("text_files").join("small.txt");
    let copy = allowed.join("text_files").join("small_replace_copy.txt");
    fs::copy(&src, &copy).unwrap();
    let path_str = copy.to_string_lossy().to_string();

    let result = mutate::file_replace(
        &guard,
        &config,
        &path_str,
        "Line 1",
        "REPLACED 1",
        Some(false),
        Some("all".into()),
    )
    .unwrap();

    assert!(
        result["replacements_made"].as_u64().unwrap() >= 1,
        "Should have at least 1 replacement"
    );
    let content = fs::read_to_string(&copy).unwrap();
    assert!(content.contains("REPLACED 1"));

    cleanup(&root);
}

#[test]
fn smoke_file_insert() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);

    let src = allowed.join("text_files").join("small.txt");
    let copy = allowed.join("text_files").join("small_insert_copy.txt");
    fs::copy(&src, &copy).unwrap();
    let path_str = copy.to_string_lossy().to_string();

    let result = mutate::file_insert(
        &guard,
        &config,
        &path_str,
        "INSERTED LINE",
        json!({"after": "Line 3"}),
        None,
        None,
    )
    .unwrap();

    let inserted_at = result["inserted_at_lines"].as_array().unwrap();
    assert!(
        !inserted_at.is_empty(),
        "Should report inserted line numbers"
    );
    let content = fs::read_to_string(&copy).unwrap();
    assert!(content.contains("INSERTED LINE"));

    cleanup(&root);
}

#[test]
fn smoke_file_append() {
    let (root, allowed, _) = setup_fixtures();
    let guard = make_guard(&allowed);

    let src = allowed.join("text_files").join("small.txt");
    let copy = allowed.join("text_files").join("small_append_copy.txt");
    fs::copy(&src, &copy).unwrap();
    let path_str = copy.to_string_lossy().to_string();

    let result = mutate::file_append(&guard, &path_str, "APPENDED TEXT", Some(true)).unwrap();

    assert!(
        result["bytes_appended"].as_u64().unwrap() > 0,
        "bytes_appended should be > 0"
    );
    let content = fs::read_to_string(&copy).unwrap();
    assert!(content.contains("APPENDED TEXT"));

    cleanup(&root);
}

#[test]
fn smoke_file_patch_lines() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);

    let src = allowed.join("text_files").join("small.txt");
    let copy = allowed.join("text_files").join("small_patch_copy.txt");
    fs::copy(&src, &copy).unwrap();
    let path_str = copy.to_string_lossy().to_string();

    let result = mutate::file_patch_lines(
        &guard,
        &config,
        &path_str,
        2,
        3,
        "PATCHED LINE A\nPATCHED LINE B",
        None,
    )
    .unwrap();

    assert_eq!(result["old_line_count"], 2);
    assert_eq!(result["new_line_count"], 2);

    let content = fs::read_to_string(&copy).unwrap();
    assert!(content.contains("PATCHED LINE A"));
    assert!(content.contains("PATCHED LINE B"));

    cleanup(&root);
}

#[test]
fn smoke_file_batch_edit_dry_run() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);

    let src = allowed.join("text_files").join("small.txt");
    let copy = allowed.join("text_files").join("small_batch_copy.txt");
    fs::copy(&src, &copy).unwrap();
    let path_str = copy.to_string_lossy().to_string();

    let original = fs::read_to_string(&copy).unwrap();

    let edits = vec![
        json!({"op": "replace", "find": "Line 1", "replace": "EDITED_1"}),
        json!({"op": "replace", "find": "Line 5", "replace": "EDITED_5"}),
    ];

    let result = mutate::file_batch_edit(&guard, &config, &path_str, edits, Some(true)).unwrap();

    assert_eq!(result["dry_run"], true);
    assert!(result["edits_applied"].as_u64().unwrap() >= 1);

    // File should be unchanged because dry_run=true
    let after = fs::read_to_string(&copy).unwrap();
    assert_eq!(original, after, "File must not be modified during dry_run");

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOOL SMOKE TESTS — JSON
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn smoke_json_query() {
    let (root, allowed, _) = setup_fixtures();
    let guard = make_guard(&allowed);
    let path = allowed.join("json_files").join("config.json");
    let path_str = path.to_string_lossy().to_string();

    let result = json_ops::json_query(&guard, &path_str, "$.name").unwrap();

    assert_eq!(result["count"], 1);
    assert_eq!(result["results"][0]["value"], "test-project");

    cleanup(&root);
}

#[test]
fn smoke_json_mutate() {
    let (root, allowed, _) = setup_fixtures();
    let guard = make_guard(&allowed);

    // Work on a copy
    let src = allowed.join("json_files").join("config.json");
    let copy = allowed.join("json_files").join("config_mutate_copy.json");
    fs::copy(&src, &copy).unwrap();
    let path_str = copy.to_string_lossy().to_string();

    let ops = vec![json!({"op": "set", "query": "$.version", "value": "2.0.0"})];
    let result = json_ops::json_mutate(&guard, &path_str, ops).unwrap();

    assert_eq!(result["operations_applied"], 1);

    let content = fs::read_to_string(&copy).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["version"], "2.0.0");

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOOL SMOKE TESTS — CSV
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn smoke_csv_info() {
    let (root, allowed, _) = setup_fixtures();
    let guard = make_guard(&allowed);
    let path = allowed.join("csv_files").join("data.csv");
    let path_str = path.to_string_lossy().to_string();

    let result = csv_ops::csv_info(&guard, &path_str, None).unwrap();

    let columns = result["columns"].as_array().unwrap();
    assert_eq!(columns.len(), 3, "data.csv has 3 columns (name, age, city)");
    assert_eq!(result["row_count"], 20);

    cleanup(&root);
}

#[test]
fn smoke_csv_read() {
    let (root, allowed, _) = setup_fixtures();
    let guard = make_guard(&allowed);
    let path = allowed.join("csv_files").join("data.csv");
    let path_str = path.to_string_lossy().to_string();

    let result = csv_ops::csv_read(&guard, &path_str, None, Some(1), Some(5), None).unwrap();

    assert_eq!(result["rows_returned"], 5);
    let rows = result["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 5);

    cleanup(&root);
}

#[test]
fn smoke_csv_query() {
    let (root, allowed, _) = setup_fixtures();
    let guard = make_guard(&allowed);
    let path = allowed.join("csv_files").join("data.csv");
    let path_str = path.to_string_lossy().to_string();

    let result =
        csv_ops::csv_query(&guard, &path_str, "city", "eq", "NYC", None, None, None).unwrap();

    assert!(
        result["matched_rows"].as_u64().unwrap() > 0,
        "Should find rows with city=NYC"
    );

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOOL SMOKE TESTS — Manage
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn smoke_file_write_and_delete() {
    let (root, allowed, _) = setup_fixtures();
    let guard = make_guard(&allowed);
    let new_path = allowed.join("text_files").join("write_test.txt");
    let path_str = new_path.to_string_lossy().to_string();

    // Write
    let result = manage::file_write(&guard, &path_str, "hello world\nsecond line", None).unwrap();
    assert!(result["bytes_written"].as_u64().unwrap() > 0);
    assert!(new_path.exists(), "File should exist after write");

    // Delete
    let result = manage::file_delete(&guard, &path_str).unwrap();
    assert_eq!(result["deleted"], true);
    assert!(!new_path.exists(), "File should not exist after delete");

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOOL SMOKE TESTS — Utility
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn smoke_file_checksum() {
    let (root, allowed, _) = setup_fixtures();
    let guard = make_guard(&allowed);
    let path = allowed.join("text_files").join("small.txt");
    let path_str = path.to_string_lossy().to_string();

    let result = utility::file_checksum(&guard, &path_str, Some("sha256".into())).unwrap();

    assert_eq!(result["algorithm"], "sha256");
    let checksum = result["checksum"].as_str().unwrap();
    assert_eq!(
        checksum.len(),
        64,
        "SHA-256 hex digest should be 64 characters"
    );

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOOL SMOKE TESTS — Directory
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn smoke_directory_list() {
    let (root, allowed, _) = setup_fixtures();
    let guard = make_guard(&allowed);
    let path_str = allowed.to_string_lossy().to_string();

    let result =
        directory::directory_list(&guard, &path_str, Some(1), None, None, None, false, None)
            .unwrap();

    assert!(
        result["total_entries"].as_u64().unwrap() >= 5,
        "allowed/ should have at least 5 entries (text_files, code_files, json_files, csv_files, binary_files, ...)"
    );

    cleanup(&root);
}

#[test]
fn smoke_directory_tree() {
    let (root, allowed, _) = setup_fixtures();
    let guard = make_guard(&allowed);
    let path_str = allowed.to_string_lossy().to_string();

    let result =
        directory::directory_tree(&guard, &path_str, Some(2), None, None, None, false, None)
            .unwrap();

    let tree = result["tree"].as_str().unwrap();
    assert!(
        tree.contains("text_files"),
        "Tree should list text_files subdirectory"
    );
    assert!(result["total_files"].as_u64().unwrap() > 0);
    assert!(result["total_dirs"].as_u64().unwrap() > 0);

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPAT TOOL TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn smoke_read_file_compat() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);
    let path = allowed.join("text_files").join("small.txt");
    let path_str = path.to_string_lossy().to_string();

    let result = compat::read_file(&guard, &config, &path_str).unwrap();

    let text = result.as_str().unwrap();
    assert!(
        text.contains("Line 1"),
        "Full read should contain first line"
    );
    assert!(
        text.contains("Line 10"),
        "Full read should contain last line"
    );

    cleanup(&root);
}

#[test]
fn smoke_edit_file_compat() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);

    let src = allowed.join("text_files").join("small.txt");
    let copy = allowed
        .join("text_files")
        .join("small_edit_compat_copy.txt");
    fs::copy(&src, &copy).unwrap();
    let path_str = copy.to_string_lossy().to_string();

    let edits = vec![json!({"oldText": "Line 5", "newText": "EDITED LINE 5"})];
    let result = compat::edit_file(&guard, &config, &path_str, edits, Some(false)).unwrap();

    let diff = result.as_str().unwrap();
    assert!(
        diff.contains("-Line 5") || diff.contains("+EDITED LINE 5"),
        "Diff output should show old/new text, got: {}",
        diff
    );

    let content = fs::read_to_string(&copy).unwrap();
    assert!(content.contains("EDITED LINE 5"));

    cleanup(&root);
}

#[test]
fn smoke_list_directory_compat() {
    let (root, allowed, _) = setup_fixtures();
    let guard = make_guard(&allowed);
    let subdir = allowed.join("subdir");
    let path_str = subdir.to_string_lossy().to_string();

    let result = compat::list_directory(&guard, &path_str).unwrap();

    let text = result.as_str().unwrap();
    assert!(
        text.contains("[FILE]"),
        "Output should contain [FILE] prefix"
    );
    assert!(text.contains("file_a.txt"), "Output should list file_a.txt");

    cleanup(&root);
}

#[test]
fn smoke_search_files_compat() {
    let (root, allowed, _) = setup_fixtures();
    let guard = make_guard(&allowed);
    let path_str = allowed.to_string_lossy().to_string();

    let result = compat::search_files(&guard, &path_str, "*.txt", None, None, false, None).unwrap();

    let arr = result.as_array().unwrap();
    assert!(arr.len() >= 3, "Should find at least 3 .txt files");

    cleanup(&root);
}

#[test]
fn smoke_create_directory_compat() {
    let (root, allowed, _) = setup_fixtures();
    let guard = make_guard(&allowed);
    let new_dir = allowed.join("compat_new_dir").join("nested_deep");
    let path_str = new_dir.to_string_lossy().to_string();

    let result = compat::create_directory(&guard, &path_str).unwrap();

    assert_eq!(result["created"], true);
    assert!(new_dir.exists(), "Nested directory should be created");

    cleanup(&root);
}

#[test]
fn smoke_list_allowed_directories_compat() {
    let (root, allowed, _) = setup_fixtures();
    let dirs = vec![allowed.to_string_lossy().to_string()];

    let result = compat::list_allowed_directories(&dirs);

    let arr = result["allowed_directories"].as_array().unwrap();
    assert_eq!(arr.len(), 1);

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════════
// v0.4.0 FEATURE INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn v040_tool_category_filtering() {
    let tools_cfg = ToolsConfig {
        enable: Some(vec!["inspect".to_string()]),
    };
    let enabled = config::enabled_tool_names(&tools_cfg);
    assert!(enabled.contains("file_info"));
    assert!(enabled.contains("file_head"));
    assert!(enabled.contains("file_tail"));
    assert!(enabled.contains("file_read_lines"));
    assert_eq!(enabled.len(), 4);
    assert!(!enabled.contains("file_search"));
    assert!(!enabled.contains("file_replace"));
    assert!(!enabled.contains("file_write"));
}

#[test]
fn v040_tool_category_disabled_not_in_set() {
    let tools_cfg = ToolsConfig {
        enable: Some(vec!["inspect".to_string()]),
    };
    let enabled = config::enabled_tool_names(&tools_cfg);
    assert!(!enabled.contains("file_search"));
    assert!(!enabled.contains("file_grep"));

    let category = config::ALL_TOOL_CATEGORIES
        .iter()
        .find(|cat| config::tools_in_category(cat).contains(&"file_search"))
        .unwrap();
    assert_eq!(*category, "search");
}

#[test]
fn v040_read_only_mode() {
    let tools_cfg = ToolsConfig { enable: None };
    let mut enabled = config::enabled_tool_names(&tools_cfg);
    for name in config::WRITE_TOOL_NAMES {
        enabled.remove(*name);
    }
    assert!(!enabled.contains("file_replace"));
    assert!(!enabled.contains("file_write"));
    assert!(!enabled.contains("file_delete"));
    assert!(!enabled.contains("json_mutate"));
    assert!(!enabled.contains("csv_write"));
    assert!(enabled.contains("file_info"));
    assert!(enabled.contains("file_search"));
    assert!(enabled.contains("json_query"));
    assert!(enabled.contains("directory_list"));
}

#[test]
fn v040_read_only_plus_categories() {
    let tools_cfg = ToolsConfig {
        enable: Some(vec!["inspect".to_string(), "mutate".to_string()]),
    };
    let mut enabled = config::enabled_tool_names(&tools_cfg);
    assert!(enabled.contains("file_info"));
    assert!(enabled.contains("file_replace"));

    for name in config::WRITE_TOOL_NAMES {
        enabled.remove(*name);
    }
    assert!(enabled.contains("file_info"));
    assert!(!enabled.contains("file_replace"));
    assert!(!enabled.contains("file_insert"));
    assert!(!enabled.contains("file_append"));
}

#[test]
fn v040_gitignore_directory_list() {
    let dir = std::env::temp_dir().join("surgicalfs_gitignore_integ");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("ignored_dir")).unwrap();
    fs::create_dir_all(dir.join("visible_dir")).unwrap();
    fs::write(dir.join("ignored_dir").join("file.txt"), "hidden").unwrap();
    fs::write(dir.join("visible_dir").join("file.txt"), "visible").unwrap();
    fs::write(dir.join(".gitignore"), "ignored_dir/\n").unwrap();
    let _ = std::process::Command::new("git")
        .args(["init"])
        .current_dir(&dir)
        .output();

    let guard = PathGuard::new(&[dir.to_string_lossy().to_string()], false, 5_242_880).unwrap();

    let result = directory::directory_list(
        &guard,
        &dir.to_string_lossy(),
        Some(1),
        None,
        None,
        None,
        true,
        None,
    )
    .unwrap();

    let entries = result["entries"].as_array().unwrap();
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"visible_dir"),
        "visible_dir should appear: {:?}",
        names
    );
    assert!(
        !names.contains(&"ignored_dir"),
        "ignored_dir should be filtered: {:?}",
        names
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn v040_gitignore_show_ignored_override() {
    let dir = std::env::temp_dir().join("surgicalfs_gitignore_show_integ");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("ignored_dir")).unwrap();
    fs::create_dir_all(dir.join("visible_dir")).unwrap();
    fs::write(dir.join("ignored_dir").join("file.txt"), "hidden").unwrap();
    fs::write(dir.join("visible_dir").join("file.txt"), "visible").unwrap();
    fs::write(dir.join(".gitignore"), "ignored_dir/\n").unwrap();
    let _ = std::process::Command::new("git")
        .args(["init"])
        .current_dir(&dir)
        .output();

    let guard = PathGuard::new(&[dir.to_string_lossy().to_string()], false, 5_242_880).unwrap();

    let result = directory::directory_list(
        &guard,
        &dir.to_string_lossy(),
        Some(1),
        None,
        Some(true),
        None,
        true,
        Some(true),
    )
    .unwrap();

    let entries = result["entries"].as_array().unwrap();
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"ignored_dir"),
        "ignored_dir should appear with show_ignored=true: {:?}",
        names
    );
    assert!(
        names.contains(&"visible_dir"),
        "visible_dir should appear: {:?}",
        names
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn v040_search_pagination() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);

    let content = (1..=20)
        .map(|i| format!("match line {}", i))
        .collect::<Vec<_>>()
        .join("\n");
    let path = allowed.join("text_files").join("pagination_test.txt");
    fs::write(&path, &content).unwrap();
    let path_str = path.to_string_lossy().to_string();

    use surgicalfs_mcp::tools::search::file_grep;

    // Page 1: offset=0, max_results=5 — file_grep uses native backend (scans all matches)
    let r1 = file_grep(
        &guard,
        &config,
        &path_str,
        "match",
        Some(false),
        None,
        Some(5),
        None,
        Some(0),
    )
    .unwrap();
    assert_eq!(r1["total_matches"], 20);
    assert_eq!(r1["line_numbers"].as_array().unwrap().len(), 5);

    // Page 3: offset=10, max_results=5
    let r2 = file_grep(
        &guard,
        &config,
        &path_str,
        "match",
        Some(false),
        None,
        Some(5),
        None,
        Some(10),
    )
    .unwrap();
    let lines2 = r2["line_numbers"].as_array().unwrap();
    assert_eq!(lines2.len(), 5);
    assert_eq!(lines2[0], 11); // first match at line 11

    // Beyond total: offset=25
    let r3 = file_grep(
        &guard,
        &config,
        &path_str,
        "match",
        Some(false),
        None,
        Some(5),
        None,
        Some(25),
    )
    .unwrap();
    assert_eq!(r3["line_numbers"].as_array().unwrap().len(), 0);
    assert_eq!(r3["total_matches"], 20);

    cleanup(&root);
}

#[test]
fn v040_content_verification_patch_lines() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);
    let path = allowed.join("text_files").join("verify_patch.txt");
    fs::write(&path, "line1\nline2\nline3\nline4\nline5").unwrap();
    let path_str = path.to_string_lossy().to_string();

    // Correct expected_content — edit succeeds
    let r1 = mutate::file_patch_lines(
        &guard,
        &config,
        &path_str,
        2,
        3,
        "NEW2\nNEW3",
        Some("line2\nline3".to_string()),
    )
    .unwrap();
    assert_eq!(r1["old_line_count"], 2);

    // Wrong expected_content (file changed) — edit fails
    let r2 = mutate::file_patch_lines(
        &guard,
        &config,
        &path_str,
        2,
        3,
        "WRONG",
        Some("line2\nline3".to_string()),
    );
    assert!(r2.is_err());
    let err = r2.unwrap_err().0.to_json();
    assert!(
        err.contains("Content verification failed"),
        "Error: {}",
        err
    );

    cleanup(&root);
}

#[test]
fn v040_content_verification_insert() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);
    let path = allowed.join("text_files").join("verify_insert.txt");
    fs::write(&path, "line1\nline2\nline3").unwrap();
    let path_str = path.to_string_lossy().to_string();

    // Correct expected_content at line 2 (0-indexed index 2 = "line3")
    let r1 = mutate::file_insert(
        &guard,
        &config,
        &path_str,
        "INSERTED",
        json!({"line": 2}),
        None,
        Some("line3".to_string()),
    )
    .unwrap();
    assert_eq!(r1["lines_added"], 1);

    // Wrong expected_content — should fail
    let r2 = mutate::file_insert(
        &guard,
        &config,
        &path_str,
        "INSERTED2",
        json!({"line": 2}),
        None,
        Some("WRONG".to_string()),
    );
    assert!(r2.is_err());

    cleanup(&root);
}

#[test]
fn v040_content_verification_backwards_compatible() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);
    let path = allowed.join("text_files").join("verify_compat.txt");
    fs::write(&path, "line1\nline2\nline3\nline4\nline5").unwrap();
    let path_str = path.to_string_lossy().to_string();

    // Without expected_content — should work (backwards compatible)
    let r = mutate::file_patch_lines(&guard, &config, &path_str, 2, 3, "REPLACED", None).unwrap();
    assert_eq!(r["old_line_count"], 2);
    assert_eq!(r["new_line_count"], 1);

    let content = fs::read_to_string(&path).unwrap();
    assert!(content.contains("REPLACED"));

    cleanup(&root);
}

// ── Edge case tests from security audit ──

#[test]
fn v040_expected_content_crlf_normalization() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);
    let path = allowed.join("text_files").join("verify_crlf.txt");
    // File has Unix line endings
    fs::write(&path, "line1\nline2\nline3\nline4\nline5").unwrap();
    let path_str = path.to_string_lossy().to_string();

    // Pass expected_content with \r\n (Windows line endings) — should still match
    let r = mutate::file_patch_lines(
        &guard,
        &config,
        &path_str,
        2,
        3,
        "REPLACED",
        Some("line2\r\nline3".to_string()),
    )
    .unwrap();
    assert_eq!(r["old_line_count"], 2);

    cleanup(&root);
}

#[test]
fn v040_pagination_overflow_saturating() {
    let (root, allowed, _) = setup_fixtures();
    let config = make_config(&allowed);
    let guard = make_guard(&allowed);
    let path = allowed.join("text_files").join("overflow_test.txt");
    fs::write(&path, "line1\nline2\nline3").unwrap();
    let path_str = path.to_string_lossy().to_string();

    use surgicalfs_mcp::tools::search::file_grep;

    // offset=u32::MAX, max_results=10 — should not panic from overflow
    let r = file_grep(
        &guard,
        &config,
        &path_str,
        "line",
        Some(false),
        None,
        Some(10),
        None,
        Some(u32::MAX),
    )
    .unwrap();

    // No results (offset beyond any file), but should not panic
    assert_eq!(r["line_numbers"].as_array().unwrap().len(), 0);
    assert_eq!(r["total_matches"], 3);

    cleanup(&root);
}
