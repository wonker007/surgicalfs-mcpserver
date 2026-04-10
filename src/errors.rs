use serde::Serialize;
use thiserror::Error;

/// Structured error codes for machine-readable error handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ErrorCode {
    #[serde(rename = "PATH_DENIED")]
    PathDenied,
    #[serde(rename = "FILE_NOT_FOUND")]
    FileNotFound,
    #[serde(rename = "FILE_TOO_LARGE")]
    FileTooLarge,
    #[serde(rename = "BINARY_FILE")]
    BinaryFile,
    #[serde(rename = "PATTERN_INVALID")]
    PatternInvalid,
    #[serde(rename = "JSONPATH_INVALID")]
    JsonPathInvalid,
    #[serde(rename = "JSONPATH_NO_MATCH")]
    JsonPathNoMatch,
    #[serde(rename = "LINE_RANGE_INVALID")]
    LineRangeInvalid,
    #[serde(rename = "ENCODING_ERROR")]
    EncodingError,
    #[serde(rename = "CSV_PARSE_ERROR")]
    CsvParseError,
    #[serde(rename = "PDF_PARSE_ERROR")]
    PdfParseError,
    #[serde(rename = "DOCX_PARSE_ERROR")]
    DocxParseError,
    #[serde(rename = "XLSX_PARSE_ERROR")]
    XlsxParseError,
    #[serde(rename = "SHEET_NOT_FOUND")]
    SheetNotFound,
    #[serde(rename = "COLUMN_NOT_FOUND")]
    ColumnNotFound,
    #[serde(rename = "IO_ERROR")]
    IoError,
    #[serde(rename = "WRITE_SESSION_ERROR")]
    WriteSessionError,
    #[serde(rename = "FILE_EXISTS")]
    FileExists,
    #[serde(rename = "NOT_A_DIRECTORY")]
    NotADirectory,
    #[serde(rename = "INTERNAL_ERROR")]
    InternalError,
}

/// Structured error response returned to the MCP client.
#[derive(Debug, Serialize)]
pub struct ToolError {
    pub code: ErrorCode,
    pub message: String,
    pub suggestion: String,
}

impl ToolError {
    pub fn new(code: ErrorCode, message: impl Into<String>, suggestion: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            suggestion: suggestion.into(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            format!(
                r#"{{"code":"INTERNAL_ERROR","message":"{}","suggestion":""}}"#,
                self.message
            )
        })
    }
}

#[derive(Debug, Error)]
#[error("{}", .0.message)]
pub struct SurgicalError(pub ToolError);

impl SurgicalError {
    pub fn new(code: ErrorCode, message: impl Into<String>, suggestion: impl Into<String>) -> Self {
        Self(ToolError::new(code, message, suggestion))
    }

    pub fn path_denied(path: &str) -> Self {
        Self::new(
            ErrorCode::PathDenied,
            format!("Path '{}' is not within any allowed directory.", path),
            "Check allowed_directories in surgicalfs.toml.",
        )
    }

    pub fn file_not_found(path: &str) -> Self {
        Self::new(
            ErrorCode::FileNotFound,
            format!("File not found: '{}'", path),
            "Verify the path exists. Use directory_list to browse.",
        )
    }

    pub fn file_too_large(path: &str, size: u64, max: u64) -> Self {
        let size_mb = size as f64 / 1_048_576.0;
        let max_mb = max as f64 / 1_048_576.0;
        Self::new(
            ErrorCode::FileTooLarge,
            format!(
                "File '{}' is {:.1}MB, exceeding the {:.1}MB limit.",
                path, size_mb, max_mb
            ),
            "Use file_read_lines for partial access, or increase max_file_size in config.",
        )
    }

    pub fn binary_file(path: &str) -> Self {
        Self::new(
            ErrorCode::BinaryFile,
            format!("File '{}' appears to be binary.", path),
            "Use file_info for metadata, or pdf_extract/docx_extract/xlsx_read for document formats.",
        )
    }

    pub fn pattern_invalid(pattern: &str, err: &str) -> Self {
        Self::new(
            ErrorCode::PatternInvalid,
            format!("Invalid pattern '{}': {}", pattern, err),
            "Check regex syntax. Use is_regex=false for literal matching.",
        )
    }

    pub fn line_range_invalid(msg: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::LineRangeInvalid,
            msg,
            "Use 1-indexed inclusive ranges. Check total_lines with file_info first.",
        )
    }

    pub fn io_error(err: &std::io::Error, context: &str) -> Self {
        Self::new(
            ErrorCode::IoError,
            format!("{}: {}", context, err),
            "Check file permissions and path.",
        )
    }
}

impl From<SurgicalError> for String {
    fn from(e: SurgicalError) -> String {
        e.0.to_json()
    }
}

pub type SurgicalResult<T> = Result<T, SurgicalError>;
