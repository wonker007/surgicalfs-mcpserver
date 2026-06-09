use rmcp::{
    handler::server::router::tool::ToolRouter,
    handler::server::tool::ToolCallContext,
    handler::server::wrapper::Parameters,
    model::{
        CallToolRequestParams, CallToolResult, ListToolsResult, PaginatedRequestParams,
        ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    tool, tool_router, RoleServer, ServerHandler,
};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::config::Config;
use crate::errors::SurgicalError;
use crate::pathguard::PathGuard;
use crate::response_budget::apply_response_budget;
use crate::search_backend::SearchBackend;
use crate::tools::manage::WriteSessionManager;

// ─── Parameter structs ──────────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
struct PathParam {
    #[schemars(description = "Absolute or relative file path")]
    path: String,
}

#[derive(Deserialize, JsonSchema)]
struct FileHeadParams {
    #[schemars(description = "File path")]
    path: String,
    #[schemars(description = "Number of lines to read (default: 50)")]
    lines: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct FileTailParams {
    #[schemars(description = "File path")]
    path: String,
    #[schemars(description = "Number of lines to read (default: 50)")]
    lines: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct FileReadLinesParams {
    #[schemars(description = "File path")]
    path: String,
    #[schemars(description = "1-indexed start line (inclusive)")]
    start_line: u32,
    #[schemars(description = "1-indexed end line (inclusive)")]
    end_line: u32,
}

// Note on numeric params (offset, max_results, context_lines): These use Option<u32>
// which generates JSON schema `type: integer`. Standard MCP clients send proper JSON
// numbers, so serde deserializes them correctly. The v0.3.4 anchor bug was different —
// `serde_json::Value` has no schema type constraint, so some clients stringified the
// nested object. Numeric primitives with explicit schema types don't have this problem.
#[derive(Deserialize, JsonSchema)]
struct FileSearchParams {
    #[schemars(description = "Search pattern (regex by default)")]
    pattern: String,
    #[schemars(description = "File path or directory to search")]
    path: String,
    #[schemars(description = "Treat pattern as regex (default: true)")]
    is_regex: Option<bool>,
    #[schemars(description = "Case-sensitive matching (default: true)")]
    case_sensitive: Option<bool>,
    #[schemars(description = "Filter by file type globs, e.g. [\"*.md\", \"*.json\"]")]
    file_globs: Option<Vec<String>>,
    #[schemars(
        description = "Lines of context around each match (default: 2, ignored for lines/count modes)"
    )]
    context_lines: Option<u32>,
    #[schemars(description = "Maximum matches returned (default: 100)")]
    max_results: Option<u32>,
    #[schemars(
        description = "Output mode: \"full\" (matching lines + context, default), \"lines\" (line numbers + file paths only), \"count\" (match count per file only)"
    )]
    return_mode: Option<String>,
    #[schemars(
        description = "Skip the first N matches for pagination (default: 0). Combine with max_results for paged access."
    )]
    offset: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct FileGrepParams {
    #[schemars(description = "File path (single file only, not a directory)")]
    path: String,
    #[schemars(description = "Search pattern")]
    pattern: String,
    #[schemars(description = "Treat pattern as regex (default: false)")]
    is_regex: Option<bool>,
    #[schemars(description = "Case-sensitive matching (default: true)")]
    case_sensitive: Option<bool>,
    #[schemars(description = "Maximum matches returned (default: 100)")]
    max_results: Option<u32>,
    #[schemars(
        description = "Include matching line text in results (default: false — returns line numbers only)"
    )]
    include_content: Option<bool>,
    #[schemars(description = "Skip the first N matches for pagination (default: 0)")]
    offset: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct FileSearchReplacePreviewParams {
    #[schemars(description = "File path")]
    path: String,
    #[schemars(description = "Pattern to find")]
    find: String,
    #[schemars(description = "Replacement string")]
    replace: String,
    #[schemars(description = "Treat find as regex (default: false)")]
    is_regex: Option<bool>,
    #[schemars(description = "Max replacements to preview (default: 10)")]
    max_previews: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct FileReplaceParams {
    #[schemars(description = "File path")]
    path: String,
    #[schemars(description = "Text or regex to find")]
    find: String,
    #[schemars(description = "Replacement text (supports capture groups if regex)")]
    replace: String,
    #[schemars(description = "Treat find as regex (default: false)")]
    is_regex: Option<bool>,
    #[schemars(description = "\"all\", \"first\", or \"last\" (default: \"all\")")]
    occurrence: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct FileInsertParams {
    #[schemars(description = "File path")]
    path: String,
    #[schemars(description = "Text to insert")]
    content: String,
    #[schemars(
        description = "Anchor: {\"line\": n}, {\"before\": \"pattern\"}, {\"after\": \"pattern\"}, or {\"position\": \"start\"|\"end\"}"
    )]
    anchor: serde_json::Value,
    #[schemars(description = "\"first\" (default) or \"all\"")]
    occurrence: Option<String>,
    #[schemars(
        description = "Optional: for line-number anchors, pass the expected content at that line to verify it hasn't changed. Ignored for pattern anchors (the pattern match itself serves as verification)."
    )]
    expected_content: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct FileAppendParams {
    #[schemars(description = "File path")]
    path: String,
    #[schemars(description = "Text to append")]
    content: String,
    #[schemars(description = "Ensure newline before appending (default: true)")]
    newline: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
struct FilePatchLinesParams {
    #[schemars(description = "File path")]
    path: String,
    #[schemars(description = "1-indexed start line (inclusive)")]
    start_line: u32,
    #[schemars(description = "1-indexed end line (inclusive)")]
    end_line: u32,
    #[schemars(description = "Replacement content for the line range")]
    content: String,
    #[schemars(
        description = "Optional: pass the expected content of the target line range to verify it hasn't changed since you last read it. If verification fails, the edit is rejected with a diff."
    )]
    expected_content: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct FileBatchEditParams {
    #[schemars(description = "File path")]
    path: String,
    #[schemars(
        description = "Array of edit operations: replace, insert, patch_lines, delete_lines"
    )]
    edits: Vec<serde_json::Value>,
    #[schemars(description = "If true, preview without modifying (default: false)")]
    dry_run: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
struct JsonQueryParams {
    #[schemars(description = "Path to JSON file")]
    path: String,
    #[schemars(description = "JSONPath expression (e.g. $.config.key)")]
    query: String,
}

#[derive(Deserialize, JsonSchema)]
struct JsonMutateParams {
    #[schemars(description = "Path to JSON file")]
    path: String,
    #[schemars(description = "Array of mutation operations: set, delete, insert, append")]
    operations: Vec<serde_json::Value>,
}

#[derive(Deserialize, JsonSchema)]
struct FileWriteParams {
    #[schemars(description = "File path")]
    path: String,
    #[schemars(description = "File content")]
    content: String,
    #[schemars(description = "Overwrite if exists (default: false)")]
    overwrite: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
struct FileWriteChunkedParams {
    #[schemars(description = "File path")]
    path: String,
    #[schemars(description = "Mode: \"start\", \"append\", or \"finish\"")]
    mode: String,
    #[schemars(description = "Text content for this chunk (required for start/append)")]
    content: Option<String>,
    #[schemars(description = "Overwrite if exists (start mode only, default: false)")]
    overwrite: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
struct FileWriteStreamParams {
    #[schemars(description = "Path to staging/source file")]
    source: String,
    #[schemars(description = "Final destination path")]
    destination: String,
    #[schemars(description = "Overwrite if destination exists (default: false)")]
    overwrite: Option<bool>,
    #[schemars(description = "Delete staging file after copy (default: true)")]
    delete_source: Option<bool>,
    #[schemars(description = "Compute SHA-256 verification (default: true)")]
    verify: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
struct FileCopyParams {
    #[schemars(description = "Source file path")]
    source: String,
    #[schemars(description = "Destination file path")]
    destination: String,
    #[schemars(description = "Overwrite if destination exists (default: false)")]
    overwrite: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
struct FileMoveParams {
    #[schemars(description = "Source file path")]
    source: String,
    #[schemars(description = "Destination file path")]
    destination: String,
    #[schemars(description = "Overwrite if destination exists (default: false)")]
    overwrite: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
struct DirectoryListParams {
    #[schemars(description = "Directory path")]
    path: String,
    #[schemars(description = "Recursion depth (default: 1)")]
    depth: Option<u32>,
    #[schemars(description = "Glob pattern filters")]
    globs: Option<Vec<String>>,
    #[schemars(description = "Include hidden files/dirs (default: false)")]
    show_hidden: Option<bool>,
    #[schemars(description = "Sort by: \"name\", \"size\", \"modified\" (default: \"name\")")]
    sort_by: Option<String>,
    #[schemars(
        description = "Show .gitignore'd entries (default: follows config, typically false)"
    )]
    show_ignored: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
struct DirectoryTreeParams {
    #[schemars(description = "Directory path")]
    path: String,
    #[schemars(description = "Max depth (default: 3)")]
    depth: Option<u32>,
    #[schemars(description = "Glob pattern filters")]
    globs: Option<Vec<String>>,
    #[schemars(description = "Include hidden items (default: false)")]
    show_hidden: Option<bool>,
    #[schemars(description = "Show file sizes (default: false)")]
    show_size: Option<bool>,
    #[schemars(
        description = "Show .gitignore'd entries (default: follows config, typically false)"
    )]
    show_ignored: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
struct FileChecksumParams {
    #[schemars(description = "File path")]
    path: String,
    #[schemars(description = "Algorithm: \"sha256\", \"md5\", \"blake3\" (default: \"sha256\")")]
    algorithm: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct CsvInfoParams {
    #[schemars(description = "Path to CSV file")]
    path: String,
    #[schemars(description = "Column delimiter character (auto-detected if omitted)")]
    delimiter: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct CsvReadParams {
    #[schemars(description = "Path to CSV file")]
    path: String,
    #[schemars(description = "Column names or indices to return")]
    columns: Option<Vec<String>>,
    #[schemars(description = "Start row, 1-indexed after headers (default: 1)")]
    start_row: Option<u32>,
    #[schemars(description = "End row inclusive (default: 50)")]
    end_row: Option<u32>,
    #[schemars(description = "Column delimiter")]
    delimiter: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct CsvQueryParams {
    #[schemars(description = "Path to CSV file")]
    path: String,
    #[schemars(description = "Column name to filter on")]
    column: String,
    #[schemars(description = "Operator: eq, neq, contains, gt, lt, gte, lte, regex")]
    operator: String,
    #[schemars(description = "Value to compare against")]
    value: String,
    #[schemars(description = "Columns to include in output")]
    columns: Option<Vec<String>>,
    #[schemars(description = "Maximum rows to return (default: 100)")]
    max_rows: Option<u32>,
    #[schemars(description = "Column delimiter")]
    delimiter: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct CsvWriteParams {
    #[schemars(description = "Path to CSV file")]
    path: String,
    #[schemars(description = "Column headers (required for new files)")]
    headers: Option<Vec<String>>,
    #[schemars(description = "Array of row arrays")]
    rows: Vec<Vec<String>>,
    #[schemars(description = "Append to existing file (default: false)")]
    append: Option<bool>,
    #[schemars(description = "Column delimiter")]
    delimiter: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct PdfExtractParams {
    #[schemars(description = "Path to PDF file")]
    path: String,
    #[schemars(description = "Start page, 1-indexed (default: 1)")]
    start_page: Option<u32>,
    #[schemars(description = "End page inclusive (default: all)")]
    end_page: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct DocxExtractParams {
    #[schemars(description = "Path to .docx file")]
    path: String,
    #[schemars(description = "Maximum characters to return (default: 50000)")]
    max_chars: Option<u32>,
    #[schemars(description = "Character offset for pagination (default: 0)")]
    offset: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct XlsxInfoParams {
    #[schemars(description = "Path to .xlsx/.xls/.ods file")]
    path: String,
}

#[derive(Deserialize, JsonSchema)]
struct XlsxReadParams {
    #[schemars(description = "Path to spreadsheet file")]
    path: String,
    #[schemars(description = "Sheet name (default: first sheet)")]
    sheet: Option<String>,
    #[schemars(
        description = "Cell range in Excel notation, e.g. \"B2:D10\" (default: \"A1:Z50\")"
    )]
    range: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct XlsxQueryParams {
    #[schemars(description = "Path to spreadsheet file")]
    path: String,
    #[schemars(description = "Sheet name (default: first sheet)")]
    sheet: Option<String>,
    #[schemars(description = "Text or regex to search for")]
    pattern: String,
    #[schemars(description = "Treat pattern as regex (default: false)")]
    is_regex: Option<bool>,
    #[schemars(description = "Maximum matches (default: 50)")]
    max_results: Option<u32>,
}

// ─── Backwards-compatible parameter structs ──────────────────────────────────

#[derive(Deserialize, JsonSchema)]
struct ReadTextFileParams {
    #[schemars(description = "File path")]
    path: String,
    #[schemars(description = "Byte offset to start reading from")]
    offset: Option<u64>,
    #[schemars(description = "Number of bytes to read")]
    length: Option<u64>,
    #[schemars(description = "Return first N lines")]
    head: Option<u32>,
    #[schemars(description = "Return last N lines")]
    tail: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct ReadMultipleFilesParams {
    #[schemars(description = "Array of file paths to read")]
    paths: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
struct WriteFileParams {
    #[schemars(description = "File path")]
    path: String,
    #[schemars(description = "File content")]
    content: String,
}

#[derive(Deserialize, JsonSchema)]
struct EditFileParams {
    #[schemars(description = "File path")]
    path: String,
    #[schemars(description = "Array of {oldText, newText} edit pairs")]
    edits: Vec<serde_json::Value>,
    #[schemars(description = "If true, return diff without modifying file")]
    #[serde(rename = "dryRun")]
    dry_run: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
struct CompatDirectoryTreeParams {
    #[schemars(description = "Directory path")]
    path: String,
    #[schemars(description = "Max depth (default: 3)")]
    depth: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct MoveFileParams {
    #[schemars(description = "Source file path")]
    source: String,
    #[schemars(description = "Destination file path")]
    destination: String,
}

#[derive(Deserialize, JsonSchema)]
struct SearchFilesParams {
    #[schemars(description = "Directory path to search in")]
    path: String,
    #[schemars(description = "Glob pattern to match filenames (e.g. \"*.rs\")")]
    pattern: String,
    #[schemars(description = "Glob patterns to exclude")]
    #[serde(rename = "excludePatterns")]
    exclude_patterns: Option<Vec<String>>,
    #[schemars(description = "Maximum files to return (default: 200)")]
    max_results: Option<u32>,
    #[schemars(description = "Skip the first N results for pagination (default: 0)")]
    offset: Option<u32>,
}

// ─── Server struct ───────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SurgicalFsServer {
    config: Config,
    path_guard: PathGuard,
    search_backend: std::sync::Arc<SearchBackend>,
    write_sessions: std::sync::Arc<WriteSessionManager>,
    tool_router: ToolRouter<Self>,
    enabled_tools: std::collections::HashSet<String>,
    /// Tracks last-activity time and in-flight request count so the idle
    /// watchdog in main() can self-reap this process when an upstream
    /// supervisor orphans it. See `crate::lifecycle`.
    activity: std::sync::Arc<crate::lifecycle::ActivityTracker>,
}

impl SurgicalFsServer {
    pub fn new(config: Config, path_guard: PathGuard) -> Self {
        let search_backend =
            std::sync::Arc::new(SearchBackend::detect(&config.search.ripgrep_path));
        let write_sessions = std::sync::Arc::new(WriteSessionManager::new());

        let mut enabled_tools = crate::config::enabled_tool_names(&config.tools);

        // In read-only mode, remove all write/mutation tools
        if config.security.read_only {
            for name in crate::config::WRITE_TOOL_NAMES {
                enabled_tools.remove(*name);
            }
            tracing::info!("Read-only mode: write tools disabled");
        }

        tracing::info!(
            "Enabled tools: {} of {} total",
            enabled_tools.len(),
            crate::config::ALL_TOOL_CATEGORIES
                .iter()
                .flat_map(|c| crate::config::tools_in_category(c))
                .count()
        );

        Self {
            config,
            path_guard,
            search_backend,
            write_sessions,
            tool_router: Self::tool_router(),
            enabled_tools,
            activity: crate::lifecycle::ActivityTracker::new(),
        }
    }

    /// Clone of the activity tracker, handed to the idle watchdog in main().
    pub fn activity_handle(&self) -> std::sync::Arc<crate::lifecycle::ActivityTracker> {
        self.activity.clone()
    }

    /// Apply response budget to tool output.
    fn budget(&self, result: Result<serde_json::Value, SurgicalError>) -> String {
        match result {
            Ok(val) => {
                let text = serde_json::to_string_pretty(&val).unwrap_or_else(|_| val.to_string());
                apply_response_budget(text, &self.config.response_budget)
            }
            Err(e) => e.0.to_json(),
        }
    }
}

// ─── Tool implementations ────────────────────────────────────────────────────

#[tool_router]
impl SurgicalFsServer {
    // ── File Inspection ──

    #[tool(
        description = "Get file metadata (size, line count, encoding, timestamps) without reading content. Always call this before reading large or unknown files."
    )]
    fn file_info(&self, Parameters(p): Parameters<PathParam>) -> String {
        self.budget(crate::tools::inspect::file_info(
            &self.path_guard,
            &self.config,
            &p.path,
        ))
    }

    #[tool(
        description = "Read the first N lines of a file. Returns content with line count and truncation status. Use file_info first to check file size."
    )]
    fn file_head(&self, Parameters(p): Parameters<FileHeadParams>) -> String {
        self.budget(crate::tools::inspect::file_head(
            &self.path_guard,
            &self.config,
            &p.path,
            p.lines,
        ))
    }

    #[tool(
        description = "Read the last N lines of a file. Returns content with start line number."
    )]
    fn file_tail(&self, Parameters(p): Parameters<FileTailParams>) -> String {
        self.budget(crate::tools::inspect::file_tail(
            &self.path_guard,
            &self.config,
            &p.path,
            p.lines,
        ))
    }

    #[tool(
        description = "Read a specific line range from a file (1-indexed, inclusive). Returns only the requested lines. Do not request more lines than needed. Note line numbers for later reference rather than retaining content."
    )]
    fn file_read_lines(&self, Parameters(p): Parameters<FileReadLinesParams>) -> String {
        self.budget(crate::tools::inspect::file_read_lines(
            &self.path_guard,
            &self.config,
            &p.path,
            p.start_line,
            p.end_line,
        ))
    }

    // ── Search ──

    #[tool(
        description = "Search for text patterns across files using ripgrep. Returns matching lines with context. Use return_mode=\"lines\" for just line numbers (lowest token cost) or return_mode=\"count\" for match counts only. Default return_mode=\"full\" includes matching lines with context."
    )]
    fn file_search(&self, Parameters(p): Parameters<FileSearchParams>) -> String {
        self.budget(crate::tools::search::file_search(
            &self.path_guard,
            &self.config,
            &self.search_backend,
            &p.pattern,
            &p.path,
            p.is_regex,
            p.case_sensitive,
            p.file_globs,
            p.context_lines,
            p.max_results,
            p.return_mode,
            p.offset,
        ))
    }

    #[tool(
        description = "Lightweight single-file grep. Returns just line numbers by default — the most token-efficient way to locate patterns within a known file. Use include_content=true to also get matching line text. For searching across multiple files or directories, use file_search instead."
    )]
    fn file_grep(&self, Parameters(p): Parameters<FileGrepParams>) -> String {
        self.budget(crate::tools::search::file_grep(
            &self.path_guard,
            &self.config,
            &p.path,
            &p.pattern,
            p.is_regex,
            p.case_sensitive,
            p.max_results,
            p.include_content,
            p.offset,
        ))
    }

    #[tool(
        description = "Dry-run a find-and-replace showing before/after per line without modifying the file. Use this to verify changes before committing them with file_replace."
    )]
    fn file_search_replace_preview(
        &self,
        Parameters(p): Parameters<FileSearchReplacePreviewParams>,
    ) -> String {
        self.budget(crate::tools::search::file_search_replace_preview(
            &self.path_guard,
            &self.config,
            &p.path,
            &p.find,
            &p.replace,
            p.is_regex,
            p.max_previews,
        ))
    }

    // ── Mutation ──

    #[tool(
        description = "Find and replace text in a file in-place. Returns only a summary of changes (count and line numbers), not the modified file content. Do not re-read the file after replacement unless verifying specific lines — the replacement count confirms success."
    )]
    fn file_replace(&self, Parameters(p): Parameters<FileReplaceParams>) -> String {
        self.budget(crate::tools::mutate::file_replace(
            &self.path_guard,
            &self.config,
            &p.path,
            &p.find,
            &p.replace,
            p.is_regex,
            p.occurrence,
        ))
    }

    #[tool(
        description = "Insert text before or after a pattern match, or at a specific line number. Returns inserted line numbers, not file content. Optional: pass expected_content to verify the target line hasn't changed since you last read it."
    )]
    fn file_insert(&self, Parameters(p): Parameters<FileInsertParams>) -> String {
        self.budget(crate::tools::mutate::file_insert(
            &self.path_guard,
            &self.config,
            &p.path,
            &p.content,
            p.anchor,
            p.occurrence,
            p.expected_content,
        ))
    }

    #[tool(description = "Append text to the end of a file. Simple, fast, no context cost.")]
    fn file_append(&self, Parameters(p): Parameters<FileAppendParams>) -> String {
        self.budget(crate::tools::mutate::file_append(
            &self.path_guard,
            &p.path,
            &p.content,
            p.newline,
        ))
    }

    #[tool(
        description = "Replace a specific line range with new content. Returns summary of line changes. Optional: pass expected_content to verify the target lines haven't changed since you last read them."
    )]
    fn file_patch_lines(&self, Parameters(p): Parameters<FilePatchLinesParams>) -> String {
        self.budget(crate::tools::mutate::file_patch_lines(
            &self.path_guard,
            &self.config,
            &p.path,
            p.start_line,
            p.end_line,
            &p.content,
            p.expected_content,
        ))
    }

    #[tool(
        description = "Apply multiple targeted edits to a file in one atomic operation. When making 3 or more changes to a file, always use file_batch_edit instead of multiple individual tool calls. This reduces context window usage by ~90% for multi-edit operations."
    )]
    fn file_batch_edit(&self, Parameters(p): Parameters<FileBatchEditParams>) -> String {
        self.budget(crate::tools::mutate::file_batch_edit(
            &self.path_guard,
            &self.config,
            &p.path,
            p.edits,
            p.dry_run,
        ))
    }

    // ── JSON Operations ──

    #[tool(
        description = "Query a JSON file using JSONPath (RFC 9535). Returns only matched nodes. Do not read the full JSON file to find a value — use a JSONPath query instead."
    )]
    fn json_query(&self, Parameters(p): Parameters<JsonQueryParams>) -> String {
        self.budget(crate::tools::json_ops::json_query(
            &self.path_guard,
            &p.path,
            &p.query,
        ))
    }

    #[tool(
        description = "Modify a JSON file at specific JSONPath locations (set, delete, insert, append). Returns operation results, not the full modified JSON."
    )]
    fn json_mutate(&self, Parameters(p): Parameters<JsonMutateParams>) -> String {
        self.budget(crate::tools::json_ops::json_mutate(
            &self.path_guard,
            &p.path,
            p.operations,
        ))
    }

    // ── File Management ──

    #[tool(
        description = "Create or overwrite a file. Write strategy selection: For files <50 lines, use file_write (this tool). For files 50+ lines where you are generating content linearly, use file_write_chunked. For files 50+ lines assembled from multiple sources, use file_append to build a staging file then file_write_stream to promote it. For editing existing files with 1-2 changes, use file_replace or file_insert. For 3+ changes, use file_batch_edit."
    )]
    fn file_write(&self, Parameters(p): Parameters<FileWriteParams>) -> String {
        self.budget(crate::tools::manage::file_write(
            &self.path_guard,
            &p.path,
            &p.content,
            p.overwrite,
        ))
    }

    #[tool(
        description = "Write a large file in verified chunks. Modes: start (create + write first chunk), append (write next chunk), finish (verify complete file). For files >50 lines, always use this instead of file_write. After each chunk is verified, do not repeat or reference chunk content in subsequent messages — it is confirmed on disk."
    )]
    fn file_write_chunked(&self, Parameters(p): Parameters<FileWriteChunkedParams>) -> String {
        self.budget(crate::tools::manage::file_write_chunked(
            &self.path_guard,
            &self.write_sessions,
            &p.path,
            &p.mode,
            p.content.as_deref(),
            p.overwrite,
        ))
    }

    #[tool(
        description = "Atomically copy/move a staging file to its final destination with optional SHA-256 verification. After verified: true, content is confirmed on disk. Do not retain or re-output written content."
    )]
    fn file_write_stream(&self, Parameters(p): Parameters<FileWriteStreamParams>) -> String {
        self.budget(crate::tools::manage::file_write_stream(
            &self.path_guard,
            &p.source,
            &p.destination,
            p.overwrite,
            p.delete_source,
            p.verify,
        ))
    }

    #[tool(
        description = "Copy a file from source to destination on disk. The content never passes through the conversation — this is the most context-efficient way to duplicate or place a file whose content is already on disk. Use this instead of reading a file and writing it back."
    )]
    fn file_copy(&self, Parameters(p): Parameters<FileCopyParams>) -> String {
        self.budget(crate::tools::manage::file_copy(
            &self.path_guard,
            &p.source,
            &p.destination,
            p.overwrite,
        ))
    }

    #[tool(description = "Delete a file.")]
    fn file_delete(&self, Parameters(p): Parameters<PathParam>) -> String {
        self.budget(crate::tools::manage::file_delete(&self.path_guard, &p.path))
    }

    #[tool(description = "Move or rename a file.")]
    fn file_move(&self, Parameters(p): Parameters<FileMoveParams>) -> String {
        self.budget(crate::tools::manage::file_move(
            &self.path_guard,
            &p.source,
            &p.destination,
            p.overwrite,
        ))
    }

    // ── Directory Operations ──

    #[tool(
        description = "List directory contents with metadata. Supports glob filtering, depth control, sorting, and .gitignore filtering."
    )]
    fn directory_list(&self, Parameters(p): Parameters<DirectoryListParams>) -> String {
        self.budget(crate::tools::directory::directory_list(
            &self.path_guard,
            &p.path,
            p.depth,
            p.globs,
            p.show_hidden,
            p.sort_by,
            self.config.search.respect_gitignore,
            p.show_ignored,
        ))
    }

    #[tool(
        description = "Generate an ASCII tree representation of a directory structure. Respects .gitignore by default."
    )]
    fn directory_tree(&self, Parameters(p): Parameters<DirectoryTreeParams>) -> String {
        self.budget(crate::tools::directory::directory_tree(
            &self.path_guard,
            &p.path,
            p.depth,
            p.globs,
            p.show_hidden,
            p.show_size,
            self.config.search.respect_gitignore,
            p.show_ignored,
        ))
    }

    // ── Utility ──

    #[tool(
        description = "Compute a file checksum (SHA-256, MD5, or BLAKE3) without reading the file into context."
    )]
    fn file_checksum(&self, Parameters(p): Parameters<FileChecksumParams>) -> String {
        self.budget(crate::tools::utility::file_checksum(
            &self.path_guard,
            &p.path,
            p.algorithm,
        ))
    }

    // ── CSV Operations ──

    #[tool(
        description = "Get CSV file structure: column names, row count, delimiter detected. Does not load all data."
    )]
    fn csv_info(&self, Parameters(p): Parameters<CsvInfoParams>) -> String {
        self.budget(crate::tools::csv_ops::csv_info(
            &self.path_guard,
            &p.path,
            p.delimiter,
        ))
    }

    #[tool(
        description = "Read specific rows and/or columns from a CSV file. Never loads the entire file into context."
    )]
    fn csv_read(&self, Parameters(p): Parameters<CsvReadParams>) -> String {
        self.budget(crate::tools::csv_ops::csv_read(
            &self.path_guard,
            &p.path,
            p.columns,
            p.start_row,
            p.end_row,
            p.delimiter,
        ))
    }

    #[tool(
        description = "Filter CSV rows by column value. Operators: eq, neq, contains, gt, lt, gte, lte, regex. Avoids loading unneeded rows into context."
    )]
    fn csv_query(&self, Parameters(p): Parameters<CsvQueryParams>) -> String {
        self.budget(crate::tools::csv_ops::csv_query(
            &self.path_guard,
            &p.path,
            &p.column,
            &p.operator,
            &p.value,
            p.columns,
            p.max_rows,
            p.delimiter,
        ))
    }

    #[tool(description = "Create a new CSV file or append rows to an existing one.")]
    fn csv_write(&self, Parameters(p): Parameters<CsvWriteParams>) -> String {
        self.budget(crate::tools::csv_ops::csv_write(
            &self.path_guard,
            &p.path,
            p.headers,
            p.rows,
            p.append,
            p.delimiter,
        ))
    }

    // ── Document Extraction ──

    #[tool(description = "Get PDF metadata (page count, file size) without extracting text.")]
    fn pdf_info(&self, Parameters(p): Parameters<PathParam>) -> String {
        self.budget(crate::tools::document::pdf_info(&self.path_guard, &p.path))
    }

    #[tool(
        description = "Extract text from a PDF file by page range. Returns text per page with page numbers."
    )]
    fn pdf_extract(&self, Parameters(p): Parameters<PdfExtractParams>) -> String {
        self.budget(crate::tools::document::pdf_extract_text(
            &self.path_guard,
            &p.path,
            p.start_page,
            p.end_page,
        ))
    }

    #[tool(
        description = "Extract text from a Word document (.docx). Supports pagination via offset/max_chars for large documents."
    )]
    fn docx_extract(&self, Parameters(p): Parameters<DocxExtractParams>) -> String {
        self.budget(crate::tools::document::docx_extract(
            &self.path_guard,
            &p.path,
            p.max_chars,
            p.offset,
        ))
    }

    // ── Spreadsheet Operations ──

    #[tool(
        description = "Get spreadsheet structure: sheet names and dimensions. Supports .xlsx, .xls, .ods."
    )]
    fn xlsx_info(&self, Parameters(p): Parameters<XlsxInfoParams>) -> String {
        self.budget(crate::tools::spreadsheet::xlsx_info(
            &self.path_guard,
            &p.path,
        ))
    }

    #[tool(
        description = "Read cells from a spreadsheet sheet and range (Excel notation like \"B2:D10\"). Returns headers and data rows."
    )]
    fn xlsx_read(&self, Parameters(p): Parameters<XlsxReadParams>) -> String {
        self.budget(crate::tools::spreadsheet::xlsx_read(
            &self.path_guard,
            &p.path,
            p.sheet,
            p.range,
        ))
    }

    #[tool(
        description = "Search for values across a spreadsheet. Finds cells matching a pattern without loading the full sheet."
    )]
    fn xlsx_query(&self, Parameters(p): Parameters<XlsxQueryParams>) -> String {
        self.budget(crate::tools::spreadsheet::xlsx_query(
            &self.path_guard,
            &p.path,
            p.sheet,
            &p.pattern,
            p.is_regex,
            p.max_results,
        ))
    }

    // ── Backwards-Compatible Tools (default server names) ──

    #[tool(
        description = "Read the complete contents of a file. For large files or when you only need specific sections, prefer file_read_lines or file_head for better context efficiency."
    )]
    fn read_file(&self, Parameters(p): Parameters<PathParam>) -> String {
        self.budget(crate::tools::compat::read_file(
            &self.path_guard,
            &self.config,
            &p.path,
        ))
    }

    #[tool(
        description = "Read a text file with optional byte offset/length or head/tail line counts. For surgical reads, prefer file_read_lines."
    )]
    fn read_text_file(&self, Parameters(p): Parameters<ReadTextFileParams>) -> String {
        self.budget(crate::tools::compat::read_text_file(
            &self.path_guard,
            &self.config,
            &p.path,
            p.offset,
            p.length,
            p.head,
            p.tail,
        ))
    }

    #[tool(
        description = "Read a binary media file and return base64-encoded data with MIME type. Supports PNG, JPEG, GIF, WebP, BMP, SVG."
    )]
    fn read_media_file(&self, Parameters(p): Parameters<PathParam>) -> String {
        self.budget(crate::tools::compat::read_media_file(
            &self.path_guard,
            &p.path,
        ))
    }

    #[tool(
        description = "Read multiple files in a single call. Each path is validated independently; failures are reported per-file without blocking others."
    )]
    fn read_multiple_files(&self, Parameters(p): Parameters<ReadMultipleFilesParams>) -> String {
        self.budget(crate::tools::compat::read_multiple_files(
            &self.path_guard,
            &self.config,
            p.paths,
        ))
    }

    #[tool(
        description = "Create or overwrite a file. For context-efficient writes of large files, prefer file_write_chunked or file_write_stream."
    )]
    fn write_file(&self, Parameters(p): Parameters<WriteFileParams>) -> String {
        self.budget(crate::tools::compat::write_file(
            &self.path_guard,
            &p.path,
            &p.content,
        ))
    }

    #[tool(
        description = "Edit a file using oldText/newText pairs. Returns a unified diff. For surgical edits with more control, prefer file_batch_edit."
    )]
    fn edit_file(&self, Parameters(p): Parameters<EditFileParams>) -> String {
        self.budget(crate::tools::compat::edit_file(
            &self.path_guard,
            &self.config,
            &p.path,
            p.edits,
            p.dry_run,
        ))
    }

    #[tool(
        description = "Create a directory or nested directory structure. Idempotent — succeeds silently if already exists."
    )]
    fn create_directory(&self, Parameters(p): Parameters<PathParam>) -> String {
        self.budget(crate::tools::compat::create_directory(
            &self.path_guard,
            &p.path,
        ))
    }

    #[tool(
        description = "List directory entries as [FILE] or [DIR] prefixed names. For richer metadata, prefer directory_list."
    )]
    fn list_directory(&self, Parameters(p): Parameters<PathParam>) -> String {
        self.budget(crate::tools::compat::list_directory(
            &self.path_guard,
            &p.path,
        ))
    }

    #[tool(
        description = "List directory entries with file sizes. For richer metadata, prefer directory_list with sort_by."
    )]
    fn list_directory_with_sizes(&self, Parameters(p): Parameters<PathParam>) -> String {
        self.budget(crate::tools::compat::list_directory_with_sizes(
            &self.path_guard,
            &p.path,
        ))
    }

    #[tool(
        name = "directory_tree_compat",
        description = "Get a JSON tree structure of a directory. For ASCII tree output, use directory_tree."
    )]
    fn directory_tree_compat(
        &self,
        Parameters(p): Parameters<CompatDirectoryTreeParams>,
    ) -> String {
        self.budget(crate::tools::compat::directory_tree_json(
            &self.path_guard,
            &p.path,
            p.depth,
        ))
    }

    #[tool(description = "Move or rename a file. Overwrites destination by default.")]
    fn move_file(&self, Parameters(p): Parameters<MoveFileParams>) -> String {
        self.budget(crate::tools::compat::move_file(
            &self.path_guard,
            &p.source,
            &p.destination,
        ))
    }

    #[tool(
        description = "Search for files by glob pattern on filenames. This matches file names, not content. For content search, use file_search."
    )]
    fn search_files(&self, Parameters(p): Parameters<SearchFilesParams>) -> String {
        self.budget(crate::tools::compat::search_files(
            &self.path_guard,
            &p.path,
            &p.pattern,
            p.exclude_patterns,
            p.max_results,
            self.config.search.respect_gitignore,
            p.offset,
        ))
    }

    #[tool(
        description = "Get file metadata: size, timestamps, type, permissions. For richer metadata including encoding and line count, prefer file_info."
    )]
    fn get_file_info(&self, Parameters(p): Parameters<PathParam>) -> String {
        self.budget(crate::tools::compat::get_file_info(
            &self.path_guard,
            &p.path,
        ))
    }

    #[tool(description = "List the directories this server is allowed to access.")]
    fn list_allowed_directories(&self) -> String {
        let result = crate::tools::compat::list_allowed_directories(
            &self.config.security.allowed_directories,
        );
        let text = serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string());
        apply_response_budget(text, &self.config.response_budget)
    }
}

impl ServerHandler for SurgicalFsServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("SurgicalFS — high-performance filesystem MCP server. Provides surgical, token-efficient file operations, search, JSON/CSV/XLSX/PDF/DOCX processing, and context-aware write strategies.")
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        self.activity.touch();
        let all_tools = self.tool_router.list_all();
        let filtered: Vec<_> = all_tools
            .into_iter()
            .filter(|t| self.enabled_tools.contains(&*t.name))
            .collect();
        Ok(ListToolsResult {
            tools: filtered,
            meta: None,
            next_cursor: None,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Counts this call as in-flight until the guard drops, then stamps
        // activity — so the idle watchdog never reaps us mid-response.
        let _guard = self.activity.in_flight_guard();
        if !self.enabled_tools.contains(&*request.name) {
            // Find which category this tool belongs to
            let name_str: &str = &request.name;
            let category = crate::config::ALL_TOOL_CATEGORIES
                .iter()
                .find(|cat| crate::config::tools_in_category(cat).contains(&name_str))
                .unwrap_or(&"unknown");
            return Err(rmcp::ErrorData::new(
                rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                format!(
                    "Tool '{}' is not enabled. Enable the '{}' category in surgicalfs.toml [tools] section.",
                    request.name, category
                ),
                None,
            ));
        }
        let tcc = ToolCallContext::new(self, request, context);
        self.tool_router.call(tcc).await
    }
}
