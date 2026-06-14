# SurgicalFS MCP Server

High-performance, context-efficient filesystem MCP server built in Rust. Designed as a drop-in replacement for the default `@modelcontextprotocol/server-filesystem` — with surgical read/write operations, structured file format support, and aggressive context window optimization.

**Version: 0.5.0** · **47 tools** · **Rust + rmcp SDK** · **Windows-first, cross-platform compatible**

Works with any MCP-compatible client: Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Zed, ChatGPT (via remote MCP), Gemini, and more.

---

## Why SurgicalFS?

The default MCP filesystem server has several limitations that become painful in real-world usage:

- **Context pollution** — `read_file` dumps entire file contents into the conversation, burning tokens on irrelevant lines
- **No partial editing** — every edit requires reading the full file, modifying it, and writing it back
- **Slow cold-start** — Node.js process spins up on every invocation
- **Security gaps** — known path traversal CVEs (CVE-2025-53109, CVE-2025-53110) in the reference implementation
- **No structured formats** — no native support for JSON queries, CSV filtering, XLSX/PDF/DOCX extraction

SurgicalFS addresses all of these with a single compiled binary that starts instantly, enforces a path allowlist, and provides tools designed to minimize context window usage at every level.

### Design Philosophy: Context Economy

Every tool in SurgicalFS is designed around a single principle: **never put bytes into the context window that don't need to be there.**

- Read tools support head/tail/line-range access — never load a full file when you need 10 lines
- Mutation tools return compact summaries (line numbers, counts), never the modified file content
- Search tools offer tiered verbosity: `full` → `lines` → `count`, from richest to cheapest
- A server-side **response budget** hard-caps every response before it enters the conversation
- Write strategies guide the model toward chunked writes, staging files, and batch edits to avoid repeating content
- Tool descriptions embed context hygiene directives that steer LLM behavior at the protocol level

### How It Compares

| Server | Tools | Est. definition tokens | Partial reads | Structured formats | Response budget |
|--------|-------|------------------------|---------------|-------------------|-----------------|
| **Official filesystem** | 14 | ~1,500 | No | No | No |
| **Desktop Commander** | ~25 | ~8,000 | No (full reads) | XLSX/PDF/DOCX | No |
| **safurrier/mcp-filesystem** | ~20 | ~4,000 | Yes | No | No |
| **SurgicalFS (all tools)** | 47 | ~14,000 | Yes | JSON/CSV/XLSX/PDF/DOCX | Yes |
| **SurgicalFS (core only)** | ~17 | ~5,000 | Yes | No | Yes |

SurgicalFS costs more upfront in tool definitions, but recoups it on the first operation. A single `read_file` call on a 200-line file through the official server dumps ~800 tokens; SurgicalFS's `file_head` with 20 lines returns ~100 tokens. Over a typical coding session, the response-side savings far exceed the definition overhead.

> **Tip:** If tool definition overhead is a concern, disable unnecessary categories via config. See [Tool Categories & Config-Driven Profiles](#tool-categories--config-driven-profiles).

---

## Installation

### Build from source

```bash
cargo build --release
```

Binary location depends on your toolchain. With the GNU target (recommended on Windows):

```
target/x86_64-pc-windows-gnu/release/surgicalfs-mcp.exe
```

On Linux/macOS with the default target:

```
target/release/surgicalfs-mcp
```

### Configure for your MCP client

SurgicalFS uses **stdio transport** (JSON-RPC over stdin/stdout), which is the standard for local MCP servers. The configuration pattern is the same across clients: point the client at the binary and optionally specify a config file.

#### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "surgicalfs": {
      "command": "/path/to/surgicalfs-mcp",
      "args": []
    }
  }
}
```

Config file locations:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

#### Claude Code

```bash
claude mcp add surgicalfs -- /path/to/surgicalfs-mcp
```

#### Cursor

Add to Cursor Settings → MCP, or in `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "surgicalfs": {
      "command": "/path/to/surgicalfs-mcp",
      "args": []
    }
  }
}
```

#### VS Code (Copilot)

Add to `.vscode/mcp.json` (per-workspace) or user `mcp.json`:

```json
{
  "servers": {
    "surgicalfs": {
      "command": "/path/to/surgicalfs-mcp",
      "args": []
    }
  }
}
```

#### Windsurf

Add to `~/.windsurf/mcp.json` or the project-level equivalent:

```json
{
  "mcpServers": {
    "surgicalfs": {
      "command": "/path/to/surgicalfs-mcp",
      "args": []
    }
  }
}
```

#### Zed

Add to Zed's settings under `context_servers`:

```json
{
  "context_servers": {
    "surgicalfs": {
      "command": {
        "path": "/path/to/surgicalfs-mcp",
        "args": []
      }
    }
  }
}
```

#### Remote access (ChatGPT, Gemini, claude.ai web/mobile, and other HTTP clients)

SurgicalFS uses stdio transport natively. To expose it over HTTP for web-based clients, use [supergateway](https://github.com/nichochar/supergateway) to bridge stdio to streamable HTTP, then put it behind a reverse tunnel (Cloudflare Tunnel, ngrok, etc.):

```bash
npx supergateway --stdio "/path/to/surgicalfs-mcp" --port 8080 --outputTransport streamableHttp
```

Then point your tunnel at `localhost:8080` and register the public URL in your client's MCP integration settings.

> **Windows + stateless gateways — prevent orphaned processes:** In supergateway's default *stateless* `streamableHttp` mode, a fresh server process is spawned per request and is **not** reliably reaped on Windows (the gateway's `child.kill()` targets the `cmd.exe` shell wrapper, and it never closes the child's stdin — so stdin-EOF never arrives while the gateway is alive). These children accumulate until the gateway exhausts its handles and the endpoint goes dark. Pass `--idle-timeout-secs` so each child self-reaps once idle:
>
> ```bash
> npx supergateway --stdio "/path/to/surgicalfs-mcp --idle-timeout-secs 30" --port 8080 --outputTransport streamableHttp
> ```
>
> Use a small value (e.g. `30`) for stateless mode, where each child is single-shot. For `--stateful` supergateway (one reused process per session), use a value **larger** than the longest expected mid-conversation pause (e.g. `600`) so a session isn't reaped during think-time.

> **Note:** AI providers make outbound connections to your MCP endpoint — `localhost` URLs won't work from hosted clients. A tunnel or public-facing server is required.

> **Security:** MCP over HTTP has no built-in authentication. Anyone who discovers your tunnel URL can call any tool and read/write files within your allowed directories. Secure your tunnel with IP allowlisting (e.g., Cloudflare WAF rules restricting to your AI provider's IP ranges), VPN, or equivalent access controls before exposing to the internet. The `--read-only` flag provides an additional safety layer for remote deployments.

---

## Configuration

Open `configure.html` in your browser for an interactive config generator — toggle tool categories, see live token cost estimates, and copy the generated TOML and client registration snippets.

SurgicalFS looks for `surgicalfs.toml` in this order:
1. Next to the executable
2. Platform config directory:
   - **Windows:** `%APPDATA%\surgicalfs-mcp\config.toml`
   - **macOS/Linux:** `~/.config/surgicalfs-mcp/config.toml`
3. Explicit path: `surgicalfs-mcp --config /path/to/surgicalfs.toml`

### Full configuration reference

```toml
[security]
# REQUIRED: directories the server is allowed to access.
# All path operations are validated against this allowlist.
# Symlinks that resolve outside these directories are blocked.
allowed_directories = ["/home/yourname/projects"]
follow_symlinks = false        # default: false
max_file_size = 5242880        # bytes, default: 5MB

[search]
ripgrep_path = "auto"          # "auto" (PATH → beside exe → native fallback), or explicit path
max_results = 100              # default cap for search results
default_context_lines = 2      # lines of context around matches

[defaults]
head_lines = 50                # default for file_head
tail_lines = 50                # default for file_tail
max_read_lines = 500           # cap for file_read_lines range
encoding = "auto"              # "auto", "utf-8", "windows-1252"

[response_budget]
max_response_lines = 200       # hard cap on response line count
max_response_bytes = 32768     # hard cap on response byte size (32KB)
truncation_mode = "smart"      # "smart" (break at newline) or "hard" (exact byte cut)

[runtime]
idle_timeout_secs = 0          # self-exit after N idle seconds (0 = never).
                               # Leave 0 for local stdio clients. Set >0 only for
                               # remote supergateway deployments to reap orphaned
                               # children (see Remote access above). CLI override:
                               # surgicalfs-mcp --idle-timeout-secs 30
```

---

## Remote Access (HTTP Transport)

SurgicalFS can run as a long-lived HTTP server for remote MCP access — through a reverse proxy, Cloudflare Tunnel, or any HTTP-forwarding infrastructure.

### Transport selector

```bash
# stdio (default) — for local MCP clients
surgicalfs-mcp

# HTTP — for remote access
surgicalfs-mcp --transport http --bind 127.0.0.1:8787
```

Or set in the config file:

```toml
[server]
transport = "http"
bind = "127.0.0.1:8787"
```

In HTTP mode, the server exposes `/mcp` as a stateless JSON-RPC endpoint (POST only) and `/health` as an unauthenticated liveness probe.

### Authentication

The `[server] auth_token` field enables bearer token authentication on `/mcp`:

```toml
[server]
auth_token = "your-secret-token"
```

When set, requests must include `Authorization: Bearer <token>`. When empty (default), `/mcp` is unauthenticated — suitable for localhost or network-level auth.

**Client compatibility:** Bearer auth works with Claude Desktop (via `headers` in JSON config), Claude Code (`authorization_token`), and API consumers. Claude.ai's web connector does not support custom headers; use network-level auth (IP allowlists, Cloudflare Access) for that client.

See `surgicalfs.toml.example` for the full `[server]` configuration reference, including `request_timeout_secs` and `max_concurrent_requests`.

### Control plane

HTTP mode starts a second listener for operator monitoring and control (default `127.0.0.1:9787`, never exposed publicly):

| Endpoint | Description |
|----------|-------------|
| `GET /dashboard` | Browser-based monitoring UI |
| `GET /health` | Liveness: status, version, uptime, RSS, handle count |
| `GET /ready` | Readiness: config source, directory reachability |
| `GET /metrics` | Request counters, latency buckets, process metrics |
| `GET /events` | SSE stream of tool calls and system events |
| `GET /admin/tools` | Tool inventory by category with enabled/disabled status |
| `POST /admin/tools` | Enable/disable tools at runtime (see below) |

The control plane authenticates with a per-boot token (auto-generated, written to `surgicalfs-ctl.token`). The dashboard handles this automatically.

### Runtime tool toggle

Tools can be enabled or disabled at runtime without restarting:

```bash
curl -X POST http://127.0.0.1:9787/admin/tools \
  -H "Authorization: Bearer $(cat surgicalfs-ctl.token)" \
  -H "X-SurgicalFS-Ctl: 1" \
  -H "Content-Type: application/json" \
  -d '{"action":"disable","targets":["mutate"]}'
```

Actions: `enable`, `disable`, `set` (replace the entire enabled set). Targets can be category names or individual tool names. Changes take effect immediately for all MCP clients and persist across restarts via a sidecar state file (`surgicalfs-state.json`). Delete the sidecar to reset to TOML defaults.

In read-only mode (`--read-only`), write tools cannot be re-enabled via toggle.

### Running as a Windows Service

Use [Shawl](https://github.com/mtkennerly/shawl) to run SurgicalFS as a Windows Service with auto-start and restart-on-failure:

```powershell
shawl add --name SurgicalFS-MCP --restart-if-not 0 --stop-timeout 10000 -- `
    "C:\path\to\surgicalfs-mcp.exe" --config surgicalfs.toml --transport http --bind 127.0.0.1:8787

Set-Service -Name SurgicalFS-MCP -StartupType Automatic
Start-Service SurgicalFS-MCP
```

The server responds to Ctrl+C (or service stop) with graceful shutdown: stops accepting, drains in-flight requests, then exits.

---

## Tools Reference

SurgicalFS provides 47 tools across 11 categories: surgical operations purpose-built for context efficiency, plus a backwards-compatible layer that mirrors the default MCP filesystem server.

### Inspect (4 tools)

| Tool | Description |
|------|-------------|
| `file_info` | File metadata (size, line count, encoding, timestamps) without reading content |
| `file_head` | First N lines (default: 50) with truncation indicator |
| `file_tail` | Last N lines (default: 50) with start line number |
| `file_read_lines` | Specific line range (1-indexed, inclusive) |

### Search (3 tools)

| Tool | Description |
|------|-------------|
| `file_search` | Multi-file/directory pattern search via ripgrep. Supports `return_mode`: `full` (lines + context), `lines` (file:line pairs only, ~80% fewer tokens), `count` (matches per file, ~95% fewer tokens) |
| `file_grep` | Single-file grep returning line numbers only by default. `include_content=true` adds matching text. Most token-efficient way to locate patterns in a known file |
| `file_search_replace_preview` | Dry-run find-and-replace showing before/after diffs without modifying the file |

### Mutate (5 tools)

| Tool | Description |
|------|-------------|
| `file_replace` | In-place find-and-replace (literal or regex). Returns change count + line numbers, never file content. Supports multi-line patterns with `\r\n` normalization |
| `file_insert` | Insert text at a line number, or before/after a pattern match. Accepts anchor as object or JSON string |
| `file_append` | Append text to end of file |
| `file_patch_lines` | Replace a line range with new content |
| `file_batch_edit` | Multiple edits in one atomic operation. ~90% less context than individual calls for 3+ edits |

### JSON (2 tools)

| Tool | Description |
|------|-------------|
| `json_query` | JSONPath queries (RFC 9535) returning matched nodes only |
| `json_mutate` | Modify JSON at JSONPath locations (set, delete, insert, append) |

### CSV (4 tools)

| Tool | Description |
|------|-------------|
| `csv_info` | Column names, row count, detected delimiter |
| `csv_read` | Read specific rows and/or columns |
| `csv_query` | Filter rows by column value (eq, neq, contains, gt, lt, gte, lte, regex) |
| `csv_write` | Create new CSV or append rows to existing |

### Documents (3 tools)

| Tool | Description |
|------|-------------|
| `pdf_info` | Page count and file size without extracting text |
| `pdf_extract` | Extract text by page range, one string per page |
| `docx_extract` | Extract text from `.docx` with offset/max_chars pagination |

### Spreadsheets (3 tools)

| Tool | Description |
|------|-------------|
| `xlsx_info` | Sheet names and dimensions for `.xlsx`, `.xls`, `.ods` |
| `xlsx_read` | Read cells by sheet and range (Excel notation, e.g., `B2:D10`) |
| `xlsx_query` | Search for values across sheets without loading full data |

### File Management (6 tools)

| Tool | Description |
|------|-------------|
| `file_write` | Create/overwrite a file (recommended for <50 lines) |
| `file_write_chunked` | Verified chunked writes for large files. Sessions persist to disk for stateless transports |
| `file_write_stream` | Atomic copy/move of a staging file to final destination with optional SHA-256 verification |
| `file_copy` | Disk-to-disk copy — content never enters the conversation |
| `file_delete` | Delete a file |
| `file_move` | Move or rename a file |

### Directory (2 tools)

| Tool | Description |
|------|-------------|
| `directory_list` | List contents with metadata, glob filtering, depth control, sorting |
| `directory_tree` | ASCII tree visualization with optional file sizes |

### Utility (1 tool)

| Tool | Description |
|------|-------------|
| `file_checksum` | SHA-256, MD5, or BLAKE3 checksum without reading file into context |

### Backwards-Compatible Layer (14 tools)

Drop-in replacements for every tool in the default `@modelcontextprotocol/server-filesystem`, so existing workflows and prompts continue to work unchanged:

`read_file`, `read_text_file`, `read_media_file`, `read_multiple_files`, `write_file`, `edit_file`, `create_directory`, `list_directory`, `list_directory_with_sizes`, `directory_tree_compat`, `move_file`, `search_files`, `get_file_info`, `list_allowed_directories`

Tool descriptions in the compat layer steer the model toward the surgical alternatives (e.g., `read_file`'s description suggests `file_read_lines` or `file_head` for large files).

---

## Tool Categories & Config-Driven Profiles

MCP tool definitions consume context window tokens on every interaction — typically 250–500 tokens per tool. With 47 tools, SurgicalFS costs roughly 14,000 tokens of definition overhead. While this is modest compared to servers like GitHub MCP (~55,000 tokens for 93 tools), it can matter in token-constrained environments.

Some clients implement deferred tool loading (e.g., claude.ai's tool search), which avoids upfront injection. But most clients — including Cursor, VS Code, and ChatGPT — load all definitions eagerly.

> **Note:** Cursor enforces a hard limit of 40 tools. SurgicalFS's full catalog of 47 exceeds this. Use a profile to stay within client limits.

### Profiles

Configure which tool categories are registered via `surgicalfs.toml`:

```toml
[tools]
# Only register these categories in tools/list
enable = ["inspect", "search", "mutate", "manage", "directory", "utility"]
# Omitted categories won't appear in the tool catalog at all.
# Categories: inspect, search, mutate, json, csv, document, spreadsheet,
#             manage, directory, utility, compat
```

| Profile | Categories | Tools | Est. tokens |
|---------|-----------|-------|-------------|
| **Full** (default) | All 11 | 47 | ~14,000 |
| **Core** | inspect, search, mutate, manage, directory, utility | ~17 | ~5,000 |
| **Core + formats** | Core + json, csv, document, spreadsheet | ~29 | ~9,000 |
| **Compat only** | compat | 14 | ~4,000 |

This gives you granular control over the cost/capability tradeoff. Users who don't need XLSX parsing, the compat layer, or CSV operations simply don't pay for them.

---

## Token Efficiency Guide

SurgicalFS provides multiple verbosity tiers for search operations, letting you trade detail for token savings:

### `file_search` return modes

| `return_mode` | Response shape | Token cost |
|----------------|----------------|------------|
| `full` (default) | Matching lines with surrounding context | High |
| `lines` | `{file, line}` pairs only | ~80% less |
| `count` | Match count per file | ~95% less |

### `file_grep` modes

| Mode | Response shape | Token cost |
|------|----------------|------------|
| Default | Line numbers only: `[5, 12, 89]` | Minimal |
| `include_content=true` | `{line, content}` pairs | Low |

### `search_files` limiting

Set `max_results` to cap glob results (default can return up to 200 paths).

### Write strategy selection

| Scenario | Recommended tool | Why |
|----------|-----------------|-----|
| New file, <50 lines | `file_write` | Single call, simple |
| New file, 50+ lines | `file_write_chunked` | Verified chunks, no re-output |
| Assembled from sources | `file_append` → `file_write_stream` | Build staging file, then promote |
| Edit 1–2 locations | `file_replace` or `file_insert` | Returns summary, not content |
| Edit 3+ locations | `file_batch_edit` | ~90% less context than individual calls |
| Duplicate existing file | `file_copy` | Zero context cost |

---

## Architecture

```
src/
├── main.rs              # CLI parsing, config loading, server startup
├── config.rs            # TOML config types and defaults
├── server.rs            # MCP ServerHandler with #[tool_router] + #[tool_handler]
├── pathguard.rs         # Security: path allowlist, symlink blocking, size guards
├── encoding.rs          # BOM detection, UTF-8/Windows-1252 fallback
├── search_backend.rs    # ripgrep (preferred) / native Rust (fallback) search
├── response_budget.rs   # Hard response truncation (char-boundary safe)
├── errors.rs            # Structured errors with suggestions
├── lifecycle.rs         # Exit triggers, idle self-reap, temp-file sweep
├── handler.rs           # Stateless HTTP handler (JSON-RPC dispatch)
├── shared.rs            # SharedState: tool set, metrics, activity, events
├── metrics.rs           # Lock-free counters, latency buckets, process sampler
├── control.rs           # Control-plane routes, auth, SSE, dashboard
├── redact.rs            # Positive-allowlist arg redaction for /events
├── state.rs             # Per-boot control token, sidecar state persistence
└── tools/
    ├── inspect.rs       # file_info, file_head, file_tail, file_read_lines
    ├── search.rs        # file_search, file_grep, file_search_replace_preview
    ├── mutate.rs        # file_replace, file_insert, file_append, file_patch_lines, file_batch_edit
    ├── json_ops.rs      # json_query, json_mutate
    ├── csv_ops.rs       # csv_info, csv_read, csv_query, csv_write
    ├── document.rs      # pdf_info, pdf_extract, docx_extract
    ├── spreadsheet.rs   # xlsx_info, xlsx_read, xlsx_query
    ├── manage.rs        # file_write, file_write_chunked, file_write_stream, file_copy, file_delete, file_move
    ├── directory.rs     # directory_list, directory_tree
    ├── utility.rs       # file_checksum
    └── compat.rs        # 14 backwards-compatible tools matching default MCP filesystem server
```

### Security Model

- **Path allowlist** — every operation validates paths against `allowed_directories` before any I/O
- **Symlink blocking** — symlinks resolving outside allowed directories are rejected (configurable)
- **File size guard** — configurable `max_file_size` prevents accidental reads of huge files
- **Case-insensitive paths** — Windows drive letters and paths handled correctly via `dunce`
- **No `unsafe` blocks** — zero unsafe Rust in the entire codebase
- **Zero `cargo audit` advisories** — no known dependency vulnerabilities
- **Atomic writes** — all file mutations use temp-write + rename, preventing torn files from crashes
- **Bearer auth** — optional token-based auth for the MCP endpoint (HTTP mode)
- **Control-plane isolation** — monitoring/admin on a separate localhost-only listener with per-boot CSRF-protected auth

### Search Backend

SurgicalFS auto-detects [ripgrep](https://github.com/BurntSushi/ripgrep) for maximum search performance:

1. Checks `PATH` for `rg`
2. Checks next to the SurgicalFS binary
3. Falls back to a native Rust search backend (regex + walkdir)

The fallback is fully functional but slower on large directory trees. Bundling `rg` (or `rg.exe`) next to the SurgicalFS binary is recommended for best performance.

### Response Budget

Every tool response passes through a server-side budget filter before being sent via MCP:

- `max_response_lines` — hard line count cap
- `max_response_bytes` — hard byte size cap
- `truncation_mode` — `smart` (break at nearest newline) or `hard` (exact byte cut, char-boundary safe)

This ensures that even if a tool produces a large result, the context window impact is bounded. No other filesystem MCP server provides this.

---

## Development

```bash
cargo build              # Debug build
cargo build --release    # Optimized, stripped, LTO-enabled release build
cargo test               # Run all tests (~331 tests)
cargo clippy             # Lint (zero warnings policy)
cargo fmt                # Format
cargo audit              # Dependency vulnerability scan (zero advisories)
```

### Build profile

The release profile is tuned for minimal binary size and maximum performance:

```toml
[profile.release]
opt-level = 3
lto = true
strip = true
codegen-units = 1
```

---

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| `rmcp` | Rust MCP SDK (server mode, stdio transport) |
| `serde_json_path` | JSONPath RFC 9535 queries |
| `calamine` | XLSX/XLS/ODS spreadsheet reading |
| `pdf-extract` | PDF text extraction |
| `dotext` | DOCX text extraction |
| `csv` | CSV parsing and writing |
| `regex` | Pattern matching |
| `walkdir` | Directory traversal |
| `dunce` | Windows-safe path canonicalization |
| `sha2`, `md-5`, `blake3` | Checksums |
| `encoding_rs` | Encoding detection and conversion |
| `clap` | CLI argument parsing |

---

## Version History

| Version | Changes |
|---------|---------|
| **v0.5.0** | **Major reliability overhaul.** Native HTTP transport replaces Node/supergateway bridge — single Rust process, zero per-request spawning. Control plane: localhost dashboard with live metrics, SSE activity stream, and runtime tool toggle. SharedState architecture: lock-free metrics (request counters, latency histogram, process self-watch), concurrency semaphore, broadcast event bus. Sidecar tool-toggle persistence (survives restart). Structured rolling-JSON logging. Atomic writes for all file mutations. Self-maintenance: orphaned temp-file sweep. Windows Service support via Shawl. 331 tests, 47 tools (unchanged). |
| **v0.4.2** | Idle self-reap to prevent orphaned processes behind stateless `supergateway` on Windows. New `[runtime] idle_timeout_secs` config + `--idle-timeout-secs` CLI flag (default 0 = off; local clients unaffected). Lifecycle logic consolidated into `src/lifecycle.rs` with an in-flight guard so a process is never reaped mid-response. |
| **v0.4.1** | Security audit fixes: integer overflow in `file_grep` pagination (switched to `saturating_add`). Config validation for empty/invalid tool category names. Updated tool descriptions for `expected_content`. Edge case tests for CRLF content verification and overflow saturation. |
| **v0.4.0** | Config-driven tool categories (`[tools] enable`). `.gitignore` support via `ignore` crate. `--read-only` CLI flag. Search pagination (`offset` param). Content verification (`expected_content` on `file_patch_lines` and `file_insert`). |
| **v0.3.4** | Fixed `file_replace` silently failing on multi-line find patterns (now uses whole-text matching with `\r\n` normalization). Fixed `file_insert` anchor parsing from web-based MCP clients (auto-parses JSON string anchors). Added `file_grep` single-file search tool. Added `return_mode` (`full`/`lines`/`count`) to `file_search`. Added `max_results` to `search_files`. |
| **v0.3.3** | Fixed chunked write session timeout: sessions now persist to temp directory for stateless transports (e.g., supergateway streamableHttp). |
| **v0.3.2** | Fixed PDF page extraction: replaced `extract_text()` + form-feed splitting with per-page extraction. |
| **v0.3.1** | Code audit: removed dead code, fixed char-boundary panics in `docx_extract` and `read_text_file`, fixed `file_insert` offset bug with `occurrence=all`. |
| **v0.3.0** | Added `file_copy` for disk-to-disk copy without content round-tripping. |
| **v0.2.0** | Fixed `tools/list` returning empty array (added `#[tool_handler]` macro). Replaced broken PowerShell search fallback with native Rust backend. Fixed response budget truncation panic on multi-byte UTF-8. |
| **v0.1.0** | Initial release. All tools implemented and tested. |

---

## Roadmap

- [x] **HTTP transport + control plane** — remote access, monitoring dashboard, runtime tool toggle (v0.5.0)
- [ ] **MCP Roots protocol support** — dynamic directory updates from clients without server restart
- [ ] **File diff tool** — unified diff between two files for code review workflows
- [ ] **ZIP/archive support** — create and extract archives

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgements

Built with the [Rust MCP SDK (rmcp)](https://github.com/modelcontextprotocol/rust-sdk). SurgicalFS implements the [Model Context Protocol](https://modelcontextprotocol.io), an open standard under the Linux Foundation for connecting AI assistants to external tools and data sources.

The content verification feature (`expected_content` on `file_patch_lines` and `file_insert`) is inspired by [safurrier/mcp-filesystem](https://github.com/safurrier/mcp-filesystem) by Alex Furrier (MIT licensed).
