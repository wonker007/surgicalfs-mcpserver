# CLAUDE.md — SurgicalFS MCP Server

## Project Overview
A high-performance Rust MCP server (Model Context Protocol) that replaces the
default filesystem MCP server for Claude Desktop. Built for Windows-first with
cross-platform compatibility.

**Current version: 0.4.1**

## Tech Stack
- Language: Rust (stable toolchain)
- MCP SDK: rmcp crate v1 (latest 1.x; Rust MCP SDK)
- Transport: stdio (JSON-RPC over stdin/stdout)
- Key dependencies: serde_json_path (JSONPath), calamine (XLSX), pdf-extract,
  dotext (DOCX), csv, regex, walkdir, glob, ignore (gitignore support)
- Search: ripgrep (preferred, auto-detected) with native Rust fallback

## Architecture
- src/main.rs — CLI parsing, config loading, server startup
- src/config.rs — TOML config types and loading
- src/server.rs — MCP ServerHandler impl with #[tool_router] and #[tool_handler] macros
- src/pathguard.rs — Security: path validation, allowlist, symlink checks
- src/tools/ — One module per tool category (inspect, search, mutate, json_ops,
  csv_ops, document, spreadsheet, manage, directory, utility, compat)
- src/encoding.rs — Encoding detection (BOM, UTF-8, Windows-1252 fallback)
- src/search_backend.rs — ripgrep (primary) / native Rust (fallback) search
- src/response_budget.rs — Response truncation enforcement (char-boundary safe)
- src/errors.rs — Structured error types (code, message, suggestion)

## Conventions
- All tool methods validate paths via self.path_guard.validate() before any I/O
- Mutation tools return compact summaries, NEVER full file content
- Response budget filter applies to ALL tool responses before sending via MCP
- Logging goes to stderr only (stdout is reserved for MCP JSON-RPC)
- Use anyhow for internal errors, thiserror for public error types
- Tests live in #[cfg(test)] modules at the bottom of each file
- The #[tool_handler] macro on ServerHandler impl wires tools/list and call_tool

## Commands
- cargo build — Debug build
- cargo build --release — Release build (optimized, stripped)
- cargo test — Run all tests (138 tests as of v0.4.1)
- cargo clippy — Lint
- cargo fmt — Format

## Deployment
- Binary path: /path/to/surgicalfs-mcp
- Config path: /path/to/surgicalfs.toml
- Build target: <your-target> (binary at target/<your-target>/release/)
- Must close Claude Desktop before copying the binary (it locks the exe)

## Design Spec
The full design document is at docs/surgicalfs-mcp-design.md.
The Claude Code build prompt is at docs/claude-code-prompt.md.

## Version History
- v0.1.0 — Initial build. All tools implemented and tested.
- v0.2.0 — Fixed tools/list returning empty array (#[tool_handler] macro).
  Replaced broken PowerShell search fallback with native Rust search.
  Fixed response budget truncation panic on multi-byte UTF-8 chars.
- v0.3.0 — Added file_copy tool for disk-to-disk copy without content
  round-tripping through the conversation context.
- v0.3.1 — Code audit cleanup: removed dead code (write_chunk_lines config field,
  unused detect_encoding fn). Fixed char-boundary panics in docx_extract and
  read_text_file byte slicing. Fixed file_insert offset bug with occurrence=all.
- v0.3.2 — Fixed PDF page extraction: replaced extract_text()+form-feed splitting
  with extract_text_by_pages() which returns one string per actual PDF page.
- v0.3.3 — Fixed chunked write session timeout: sessions now persisted to disk
  (%TEMP%/surgicalfs-sessions/) so they survive across stateless MCP process
  invocations (supergateway streamableHttp mode spawns a fresh process per call).
- v0.3.4 — Fixed file_replace silently failing on multi-line find patterns
  (line-by-line matching couldn't span lines; now uses whole-text matching with
  \r\n normalization). Fixed file_insert anchor always returning "Invalid anchor"
  from Claude Web UI (anchor arrived as JSON string instead of object; now
  auto-parses string anchors).
- v0.4.0 — Five features: (1) Config-driven tool categories via `[tools]
  enable` in surgicalfs.toml — disable unused categories to reduce tool
  definition overhead. (2) `.gitignore` support via `ignore` crate — search,
  directory_list, directory_tree, and search_files now respect .gitignore by
  default (`respect_gitignore = true`). (3) `--read-only` mode CLI flag and
  config option — disables all write/mutation tools. (4) Search pagination —
  `offset` param on file_search, file_grep, search_files for paged access.
  (5) Content verification — `expected_content` param on file_patch_lines and
  file_insert to detect stale edits.
- v0.4.1 — Security audit fixes: fixed integer overflow in file_grep
  pagination (offset+max_results used saturating_add). Added config
  validation for empty/invalid tool category names. Updated tool
  descriptions to mention expected_content and offset params. Added
  edge case tests for \r\n content verification and overflow saturation.
