use crate::errors::{ErrorCode, SurgicalError, SurgicalResult};
use crate::pathguard::PathGuard;
use calamine::{open_workbook_auto, Data, Reader};
use regex::Regex;
use serde_json::json;
use std::fs;

/// Get spreadsheet structure: sheet names and dimensions.
pub fn xlsx_info(path_guard: &PathGuard, path: &str) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let mut workbook = open_workbook_auto(&canonical).map_err(|e| {
        SurgicalError::new(
            ErrorCode::XlsxParseError,
            format!("Cannot open spreadsheet '{}': {}", path, e),
            "Ensure the file is a valid .xlsx, .xls, or .ods file.",
        )
    })?;

    let sheet_names: Vec<String> = workbook.sheet_names().to_vec();
    let mut sheets = Vec::new();

    for name in &sheet_names {
        if let Ok(range) = workbook.worksheet_range(name) {
            let (rows, cols) = range.get_size();
            sheets.push(json!({
                "name": name,
                "rows": rows,
                "columns": cols,
            }));
        }
    }

    let file_size = fs::metadata(&canonical).map(|m| m.len()).unwrap_or(0);
    let active = sheet_names.first().cloned();

    Ok(json!({
        "sheets": sheets,
        "active_sheet": active,
        "file_size_bytes": file_size,
    }))
}

/// Read cells from a specific sheet and range.
pub fn xlsx_read(
    path_guard: &PathGuard,
    path: &str,
    sheet: Option<String>,
    range_str: Option<String>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let mut workbook = open_workbook_auto(&canonical).map_err(|e| {
        SurgicalError::new(
            ErrorCode::XlsxParseError,
            format!("Cannot open spreadsheet: {}", e),
            "Check file format.",
        )
    })?;

    let sheet_names = workbook.sheet_names().to_vec();
    let sheet_name = sheet.unwrap_or_else(|| sheet_names.first().cloned().unwrap_or_default());

    if !sheet_names.contains(&sheet_name) {
        return Err(SurgicalError::new(
            ErrorCode::SheetNotFound,
            format!(
                "Sheet '{}' not found. Available: {:?}",
                sheet_name, sheet_names
            ),
            "Use xlsx_info to see available sheet names.",
        ));
    }

    let range = workbook.worksheet_range(&sheet_name).map_err(|e| {
        SurgicalError::new(
            ErrorCode::XlsxParseError,
            format!("Cannot read sheet '{}': {}", sheet_name, e),
            "Check the sheet name.",
        )
    })?;

    // Parse Excel range notation (e.g., "B2:D10")
    let (start_row, start_col, end_row, end_col) = if let Some(ref r) = range_str {
        parse_excel_range(r)?
    } else {
        let (rows, cols) = range.get_size();
        (
            0,
            0,
            rows.saturating_sub(1).min(49),
            cols.saturating_sub(1).min(25),
        )
    };

    let mut headers: Vec<String> = Vec::new();
    let mut data_rows: Vec<Vec<serde_json::Value>> = Vec::new();
    let mut first_row = true;

    for row_idx in start_row..=end_row {
        let mut row_data: Vec<serde_json::Value> = Vec::new();
        for col_idx in start_col..=end_col {
            let cell = range.get((row_idx, col_idx));
            let value = cell_to_json(cell);
            row_data.push(value);
        }

        if first_row {
            headers = row_data
                .iter()
                .map(|v| match v {
                    serde_json::Value::String(s) => s.clone(),
                    _ => v.to_string(),
                })
                .collect();
            first_row = false;
        } else {
            data_rows.push(row_data);
        }
    }

    Ok(json!({
        "headers": headers,
        "rows": data_rows,
        "dimensions": {
            "rows": data_rows.len(),
            "columns": headers.len(),
        },
        "sheet_name": sheet_name,
    }))
}

/// Search for values across a spreadsheet.
pub fn xlsx_query(
    path_guard: &PathGuard,
    path: &str,
    sheet: Option<String>,
    pattern: &str,
    is_regex: Option<bool>,
    max_results: Option<u32>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let mut workbook = open_workbook_auto(&canonical).map_err(|e| {
        SurgicalError::new(
            ErrorCode::XlsxParseError,
            format!("Cannot open spreadsheet: {}", e),
            "Check file format.",
        )
    })?;

    let sheet_names = workbook.sheet_names().to_vec();
    let sheet_name = sheet.unwrap_or_else(|| sheet_names.first().cloned().unwrap_or_default());

    let range = workbook.worksheet_range(&sheet_name).map_err(|e| {
        SurgicalError::new(
            ErrorCode::XlsxParseError,
            format!("Cannot read sheet: {}", e),
            "Check sheet name.",
        )
    })?;

    let is_regex = is_regex.unwrap_or(false);
    let max_results = max_results.unwrap_or(50) as usize;

    let regex = if is_regex {
        Some(
            Regex::new(pattern)
                .map_err(|e| SurgicalError::pattern_invalid(pattern, &e.to_string()))?,
        )
    } else {
        None
    };

    let mut matches = Vec::new();
    let (rows, cols) = range.get_size();

    for row_idx in 0..rows {
        for col_idx in 0..cols {
            if matches.len() >= max_results {
                break;
            }

            let cell = range.get((row_idx, col_idx));
            let cell_str = cell_to_string(cell);

            let is_match = if let Some(ref re) = regex {
                re.is_match(&cell_str)
            } else {
                cell_str.contains(pattern)
            };

            if is_match {
                let cell_ref = format!("{}{}", col_to_letter(col_idx), row_idx + 1);

                // Get full row data
                let row_data: Vec<serde_json::Value> = (0..cols)
                    .map(|c| cell_to_json(range.get((row_idx, c))))
                    .collect();

                matches.push(json!({
                    "cell": cell_ref,
                    "row": row_idx + 1,
                    "column": col_idx + 1,
                    "value": cell_str,
                    "row_data": row_data,
                }));
            }
        }
    }

    let total = matches.len();

    Ok(json!({
        "matches": matches,
        "total_matches": total,
        "truncated": total >= max_results,
    }))
}

/// Parse Excel range notation like "B2:D10" into (start_row, start_col, end_row, end_col).
fn parse_excel_range(range: &str) -> SurgicalResult<(usize, usize, usize, usize)> {
    let parts: Vec<&str> = range.split(':').collect();
    if parts.len() != 2 {
        return Err(SurgicalError::new(
            ErrorCode::XlsxParseError,
            format!(
                "Invalid range notation '{}'. Expected format: 'B2:D10'",
                range
            ),
            "Use Excel-style range notation like 'A1:Z50'.",
        ));
    }

    let (start_col, start_row) = parse_cell_ref(parts[0])?;
    let (end_col, end_row) = parse_cell_ref(parts[1])?;

    Ok((start_row, start_col, end_row, end_col))
}

fn parse_cell_ref(cell: &str) -> SurgicalResult<(usize, usize)> {
    let cell = cell.trim();
    let mut col_str = String::new();
    let mut row_str = String::new();

    for ch in cell.chars() {
        if ch.is_ascii_alphabetic() {
            col_str.push(ch.to_ascii_uppercase());
        } else if ch.is_ascii_digit() {
            row_str.push(ch);
        }
    }

    let col = letter_to_col(&col_str).ok_or_else(|| {
        SurgicalError::new(
            ErrorCode::XlsxParseError,
            format!("Invalid column reference in '{}'", cell),
            "Use letters A-Z or AA-ZZ for columns.",
        )
    })?;

    let row: usize = row_str.parse().map_err(|_| {
        SurgicalError::new(
            ErrorCode::XlsxParseError,
            format!("Invalid row reference in '{}'", cell),
            "Use numbers for rows.",
        )
    })?;

    Ok((col, row.saturating_sub(1))) // Convert to 0-indexed
}

fn letter_to_col(s: &str) -> Option<usize> {
    if s.is_empty() {
        return None;
    }
    let mut col = 0usize;
    for ch in s.chars() {
        col = col * 26 + (ch as usize - 'A' as usize + 1);
    }
    Some(col.saturating_sub(1)) // 0-indexed
}

fn col_to_letter(col: usize) -> String {
    let mut result = String::new();
    let mut c = col;
    loop {
        result.insert(0, (b'A' + (c % 26) as u8) as char);
        if c < 26 {
            break;
        }
        c = c / 26 - 1;
    }
    result
}

fn cell_to_json(cell: Option<&Data>) -> serde_json::Value {
    match cell {
        Some(Data::Int(i)) => json!(i),
        Some(Data::Float(f)) => json!(f),
        Some(Data::String(s)) => json!(s),
        Some(Data::Bool(b)) => json!(b),
        Some(Data::DateTime(ref dt)) => json!(dt.as_f64()),
        Some(Data::DateTimeIso(ref s)) => json!(s),
        Some(Data::DurationIso(ref s)) => json!(s),
        Some(Data::Error(ref e)) => json!(format!("#ERR:{:?}", e)),
        Some(Data::Empty) | None => serde_json::Value::Null,
    }
}

fn cell_to_string(cell: Option<&Data>) -> String {
    match cell {
        Some(Data::Int(i)) => i.to_string(),
        Some(Data::Float(f)) => f.to_string(),
        Some(Data::String(s)) => s.clone(),
        Some(Data::Bool(b)) => b.to_string(),
        Some(Data::DateTime(ref dt)) => format!("{}", dt.as_f64()),
        Some(Data::DateTimeIso(ref s)) => s.clone(),
        Some(Data::DurationIso(ref s)) => s.clone(),
        Some(Data::Error(ref e)) => format!("{:?}", e),
        Some(Data::Empty) | None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_excel_range() {
        let (sr, sc, er, ec) = parse_excel_range("B2:D10").unwrap();
        assert_eq!(sc, 1); // B = column 1 (0-indexed)
        assert_eq!(sr, 1); // Row 2 = index 1 (0-indexed)
        assert_eq!(ec, 3); // D = column 3
        assert_eq!(er, 9); // Row 10 = index 9
    }

    #[test]
    fn test_col_to_letter() {
        assert_eq!(col_to_letter(0), "A");
        assert_eq!(col_to_letter(1), "B");
        assert_eq!(col_to_letter(25), "Z");
        assert_eq!(col_to_letter(26), "AA");
    }

    #[test]
    fn test_letter_to_col() {
        assert_eq!(letter_to_col("A"), Some(0));
        assert_eq!(letter_to_col("B"), Some(1));
        assert_eq!(letter_to_col("Z"), Some(25));
        assert_eq!(letter_to_col("AA"), Some(26));
    }
}
