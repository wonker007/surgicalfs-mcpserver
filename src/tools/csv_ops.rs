use crate::errors::{ErrorCode, SurgicalError, SurgicalResult};
use crate::pathguard::PathGuard;
use regex::Regex;
use serde_json::json;
use std::fs;

/// Get CSV file structure without loading all data.
pub fn csv_info(
    path_guard: &PathGuard,
    path: &str,
    delimiter: Option<String>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let content = fs::read_to_string(&canonical)
        .map_err(|e| SurgicalError::io_error(&e, "Read CSV failed"))?;

    let delim = detect_or_use_delimiter(&content, delimiter.as_deref());

    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(delim as u8)
        .has_headers(true)
        .flexible(true)
        .from_reader(content.as_bytes());

    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| {
            SurgicalError::new(
                ErrorCode::CsvParseError,
                format!("CSV header error: {}", e),
                "Check CSV format.",
            )
        })?
        .iter()
        .map(|s| s.to_string())
        .collect();

    let row_count = rdr.records().count();
    let file_size = fs::metadata(&canonical).map(|m| m.len()).unwrap_or(0);

    Ok(json!({
        "columns": headers,
        "row_count": row_count,
        "delimiter_detected": delim.to_string(),
        "has_headers": true,
        "file_size_bytes": file_size,
    }))
}

/// Read specific rows and/or columns from a CSV file.
pub fn csv_read(
    path_guard: &PathGuard,
    path: &str,
    columns: Option<Vec<String>>,
    start_row: Option<u32>,
    end_row: Option<u32>,
    delimiter: Option<String>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let content = fs::read_to_string(&canonical)
        .map_err(|e| SurgicalError::io_error(&e, "Read CSV failed"))?;

    let delim = detect_or_use_delimiter(&content, delimiter.as_deref());
    let start_row = start_row.unwrap_or(1) as usize;
    let end_row = end_row.unwrap_or(50) as usize;

    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(delim as u8)
        .has_headers(true)
        .flexible(true)
        .from_reader(content.as_bytes());

    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| {
            SurgicalError::new(
                ErrorCode::CsvParseError,
                format!("CSV header error: {}", e),
                "Check CSV format.",
            )
        })?
        .iter()
        .map(|s| s.to_string())
        .collect();

    // Determine column indices
    let col_indices: Option<Vec<usize>> = columns.as_ref().map(|cols| {
        cols.iter()
            .filter_map(|c| {
                // Try as index first
                if let Ok(idx) = c.parse::<usize>() {
                    if idx < headers.len() {
                        Some(idx)
                    } else {
                        None
                    }
                } else {
                    headers.iter().position(|h| h == c)
                }
            })
            .collect()
    });

    let output_headers: Vec<String> = if let Some(ref indices) = col_indices {
        indices
            .iter()
            .filter_map(|&i| headers.get(i).cloned())
            .collect()
    } else {
        headers.clone()
    };

    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut total_rows = 0usize;

    for (idx, record) in rdr.records().enumerate() {
        total_rows = idx + 1;
        let row_num = idx + 1; // 1-indexed

        if row_num < start_row {
            continue;
        }
        if row_num > end_row {
            continue; // Keep counting total rows
        }

        if let Ok(record) = record {
            let row: Vec<String> = if let Some(ref indices) = col_indices {
                indices
                    .iter()
                    .map(|&i| record.get(i).unwrap_or("").to_string())
                    .collect()
            } else {
                record.iter().map(|s| s.to_string()).collect()
            };
            rows.push(row);
        }
    }

    Ok(json!({
        "headers": output_headers,
        "rows": rows,
        "rows_returned": rows.len(),
        "total_rows": total_rows,
    }))
}

/// Filter CSV rows by column value.
pub fn csv_query(
    path_guard: &PathGuard,
    path: &str,
    column: &str,
    operator: &str,
    value: &str,
    columns: Option<Vec<String>>,
    max_rows: Option<u32>,
    delimiter: Option<String>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let content = fs::read_to_string(&canonical)
        .map_err(|e| SurgicalError::io_error(&e, "Read CSV failed"))?;

    let delim = detect_or_use_delimiter(&content, delimiter.as_deref());
    let max_rows = max_rows.unwrap_or(100) as usize;

    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(delim as u8)
        .has_headers(true)
        .flexible(true)
        .from_reader(content.as_bytes());

    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| {
            SurgicalError::new(
                ErrorCode::CsvParseError,
                format!("CSV header error: {}", e),
                "Check CSV format.",
            )
        })?
        .iter()
        .map(|s| s.to_string())
        .collect();

    let col_idx = headers.iter().position(|h| h == column).ok_or_else(|| {
        SurgicalError::new(
            ErrorCode::ColumnNotFound,
            format!("Column '{}' not found. Available: {:?}", column, headers),
            "Use csv_info to see available column names.",
        )
    })?;

    // Determine output column indices
    let output_indices: Vec<usize> = if let Some(ref cols) = columns {
        cols.iter()
            .filter_map(|c| {
                if let Ok(idx) = c.parse::<usize>() {
                    if idx < headers.len() {
                        Some(idx)
                    } else {
                        None
                    }
                } else {
                    headers.iter().position(|h| h == c)
                }
            })
            .collect()
    } else {
        (0..headers.len()).collect()
    };

    let output_headers: Vec<String> = output_indices
        .iter()
        .filter_map(|&i| headers.get(i).cloned())
        .collect();

    let regex = if operator == "regex" {
        Some(Regex::new(value).map_err(|e| SurgicalError::pattern_invalid(value, &e.to_string()))?)
    } else {
        None
    };

    let mut matched_rows: Vec<Vec<String>> = Vec::new();
    let mut total_rows = 0usize;
    let mut matched_count = 0usize;

    for record in rdr.records() {
        total_rows += 1;
        if let Ok(record) = record {
            let cell = record.get(col_idx).unwrap_or("");

            let matches = match operator {
                "eq" => cell == value,
                "neq" => cell != value,
                "contains" => cell.contains(value),
                "gt" => compare_numeric(cell, value, |a, b| a > b),
                "lt" => compare_numeric(cell, value, |a, b| a < b),
                "gte" => compare_numeric(cell, value, |a, b| a >= b),
                "lte" => compare_numeric(cell, value, |a, b| a <= b),
                "regex" => regex.as_ref().map(|re| re.is_match(cell)).unwrap_or(false),
                _ => false,
            };

            if matches {
                matched_count += 1;
                if matched_rows.len() < max_rows {
                    let row: Vec<String> = output_indices
                        .iter()
                        .map(|&i| record.get(i).unwrap_or("").to_string())
                        .collect();
                    matched_rows.push(row);
                }
            }
        }
    }

    Ok(json!({
        "headers": output_headers,
        "rows": matched_rows,
        "matched_rows": matched_count,
        "total_rows": total_rows,
        "truncated": matched_count > max_rows,
    }))
}

/// Create a new CSV file or append rows.
pub fn csv_write(
    path_guard: &PathGuard,
    path: &str,
    headers: Option<Vec<String>>,
    rows: Vec<Vec<String>>,
    append: Option<bool>,
    delimiter: Option<String>,
) -> SurgicalResult<serde_json::Value> {
    let append = append.unwrap_or(false);
    let delim_char = delimiter
        .as_deref()
        .and_then(|d| d.chars().next())
        .unwrap_or(',');

    let canonical = if append {
        path_guard.validate(path)?
    } else {
        path_guard.validate_new(path)?
    };

    let file_existed = canonical.exists();

    if append && file_existed {
        // Append mode: open for append
        let file = fs::OpenOptions::new()
            .append(true)
            .open(&canonical)
            .map_err(|e| SurgicalError::io_error(&e, "Open for append failed"))?;

        let mut wtr = csv::WriterBuilder::new()
            .delimiter(delim_char as u8)
            .from_writer(file);

        for row in &rows {
            wtr.write_record(row).map_err(|e| {
                SurgicalError::new(
                    ErrorCode::CsvParseError,
                    format!("CSV write error: {}", e),
                    "Check row data.",
                )
            })?;
        }
        wtr.flush()
            .map_err(|e| SurgicalError::io_error(&e, "Flush failed"))?;
    } else {
        // Create new file
        let file = fs::File::create(&canonical)
            .map_err(|e| SurgicalError::io_error(&e, "Create file failed"))?;

        let mut wtr = csv::WriterBuilder::new()
            .delimiter(delim_char as u8)
            .from_writer(file);

        if let Some(ref hdrs) = headers {
            wtr.write_record(hdrs).map_err(|e| {
                SurgicalError::new(
                    ErrorCode::CsvParseError,
                    format!("CSV write error: {}", e),
                    "Check header data.",
                )
            })?;
        }

        for row in &rows {
            wtr.write_record(row).map_err(|e| {
                SurgicalError::new(
                    ErrorCode::CsvParseError,
                    format!("CSV write error: {}", e),
                    "Check row data.",
                )
            })?;
        }
        wtr.flush()
            .map_err(|e| SurgicalError::io_error(&e, "Flush failed"))?;
    }

    // Count total rows in file now
    let total = fs::read_to_string(&canonical)
        .map(|c| c.lines().count().saturating_sub(1)) // subtract header
        .unwrap_or(rows.len());

    Ok(json!({
        "rows_written": rows.len(),
        "total_rows": total,
        "created": !file_existed,
    }))
}

fn compare_numeric(cell: &str, value: &str, cmp: fn(f64, f64) -> bool) -> bool {
    match (cell.parse::<f64>(), value.parse::<f64>()) {
        (Ok(a), Ok(b)) => cmp(a, b),
        _ => cell > value, // String comparison fallback
    }
}

fn detect_or_use_delimiter(content: &str, delimiter: Option<&str>) -> char {
    if let Some(d) = delimiter {
        return d.chars().next().unwrap_or(',');
    }
    // Auto-detect by sampling first few lines
    let sample: Vec<&str> = content.lines().take(5).collect();
    if sample.is_empty() {
        return ',';
    }

    let candidates = [',', '\t', ';', '|'];
    let mut best = ',';
    let mut best_consistency = 0.0f64;

    for &delim in &candidates {
        let counts: Vec<usize> = sample
            .iter()
            .map(|line| line.matches(delim).count())
            .collect();
        if counts.iter().all(|&c| c == 0) {
            continue;
        }
        let avg = counts.iter().sum::<usize>() as f64 / counts.len() as f64;
        let variance: f64 = counts
            .iter()
            .map(|&c| (c as f64 - avg).powi(2))
            .sum::<f64>()
            / counts.len() as f64;
        // Higher count with lower variance = better delimiter
        let consistency = avg / (variance + 1.0);
        if consistency > best_consistency {
            best_consistency = consistency;
            best = delim;
        }
    }

    best
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
    fn test_csv_info() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_csv_info.csv");
        fs::write(&path, "name,age,city\nAlice,30,NYC\nBob,25,LA\n").unwrap();

        let result = csv_info(&guard, &path.to_string_lossy(), None).unwrap();
        assert_eq!(result["row_count"], 2);
        let cols = result["columns"].as_array().unwrap();
        assert_eq!(cols.len(), 3);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_csv_read() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_csv_read.csv");
        fs::write(&path, "name,age\nAlice,30\nBob,25\nCharlie,35\n").unwrap();

        let result = csv_read(
            &guard,
            &path.to_string_lossy(),
            None,
            Some(1),
            Some(2),
            None,
        )
        .unwrap();
        assert_eq!(result["rows_returned"], 2);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_csv_query() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_csv_query.csv");
        fs::write(&path, "name,age\nAlice,30\nBob,25\nCharlie,35\n").unwrap();

        let result = csv_query(
            &guard,
            &path.to_string_lossy(),
            "age",
            "gt",
            "28",
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(result["matched_rows"], 2); // Alice (30), Charlie (35)

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_csv_write() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_csv_write.csv");

        let result = csv_write(
            &guard,
            &path.to_string_lossy(),
            Some(vec!["name".into(), "age".into()]),
            vec![
                vec!["Alice".into(), "30".into()],
                vec!["Bob".into(), "25".into()],
            ],
            None,
            None,
        )
        .unwrap();

        assert_eq!(result["rows_written"], 2);
        assert_eq!(result["created"], true);

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("Alice"));

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_delimiter_detection() {
        assert_eq!(detect_or_use_delimiter("a,b,c\n1,2,3", None), ',');
        assert_eq!(detect_or_use_delimiter("a\tb\tc\n1\t2\t3", None), '\t');
        assert_eq!(detect_or_use_delimiter("a;b;c\n1;2;3", None), ';');
    }
}
