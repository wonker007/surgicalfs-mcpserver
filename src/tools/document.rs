use crate::errors::{ErrorCode, SurgicalError, SurgicalResult};
use crate::pathguard::PathGuard;
use dotext::MsDoc;
use serde_json::json;
use std::fs;
use std::io::Read;

/// Extract text from a PDF per-page using pdf_extract's by-page API.
/// Returns a Vec<String> where each element is the text for one page.
fn extract_pdf_pages(path: &std::path::Path, display_path: &str) -> SurgicalResult<Vec<String>> {
    pdf_extract::extract_text_by_pages(path).map_err(|e| {
        SurgicalError::new(
            ErrorCode::PdfParseError,
            format!("Cannot read PDF '{}': {}", display_path, e),
            "Ensure the file is a valid, non-encrypted PDF.",
        )
    })
}

/// Get PDF metadata without extracting text.
pub fn pdf_info(path_guard: &PathGuard, path: &str) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let pages = extract_pdf_pages(&canonical, path)?;
    let total_pages = pages.len().max(1);
    let file_size = fs::metadata(&canonical).map(|m| m.len()).unwrap_or(0);

    Ok(json!({
        "total_pages": total_pages,
        "title": null,
        "author": null,
        "creator": null,
        "producer": null,
        "file_size_bytes": file_size,
    }))
}

/// Extract text from a PDF file by page range.
pub fn pdf_extract_text(
    path_guard: &PathGuard,
    path: &str,
    start_page: Option<u32>,
    end_page: Option<u32>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let pages = extract_pdf_pages(&canonical, path)?;
    let total_pages = pages.len().max(1);

    let start = start_page.unwrap_or(1) as usize;
    let end = end_page.unwrap_or(total_pages as u32) as usize;

    let mut page_results = Vec::new();
    for (idx, page_text) in pages.iter().enumerate() {
        let page_num = idx + 1;
        if page_num >= start && page_num <= end {
            page_results.push(json!({
                "page_number": page_num,
                "text": page_text.trim(),
            }));
        }
    }

    Ok(json!({
        "pages": page_results,
        "total_pages": total_pages,
        "extracted_pages": page_results.len(),
    }))
}

/// Extract text from a DOCX file.
pub fn docx_extract(
    path_guard: &PathGuard,
    path: &str,
    max_chars: Option<u32>,
    offset: Option<u32>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    path_guard.check_size(&canonical)?;

    let mut docx = dotext::Docx::open(&canonical).map_err(|e| {
        SurgicalError::new(
            ErrorCode::DocxParseError,
            format!("Cannot open DOCX '{}': {}", path, e),
            "Ensure the file is a valid .docx file.",
        )
    })?;

    let mut text = String::new();
    docx.read_to_string(&mut text).map_err(|e| {
        SurgicalError::new(
            ErrorCode::DocxParseError,
            format!("Cannot read DOCX content: {}", e),
            "The DOCX file may be corrupted.",
        )
    })?;

    let total_chars = text.chars().count() as u32;
    let offset = offset.unwrap_or(0) as usize;
    let max_chars = max_chars.unwrap_or(50_000) as usize;

    // Slice by character count, not byte offset, to avoid panics on multi-byte UTF-8
    let sliced: String = text.chars().skip(offset).take(max_chars).collect();

    let chars_returned = sliced.chars().count() as u32;
    let truncated = offset + max_chars < total_chars as usize;

    Ok(json!({
        "text": &sliced,
        "chars_returned": chars_returned,
        "total_chars": total_chars,
        "truncated": truncated,
    }))
}

#[cfg(test)]
mod tests {
    // PDF and DOCX tests require fixture files; tested manually or with integration tests.
}
