mod config;
mod encoding;
mod errors;
mod pathguard;
mod response_budget;
mod search_backend;
mod server;
mod tools;

use anyhow::Result;
use clap::Parser;
use rmcp::ServiceExt;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "surgicalfs-mcp",
    about = "High-performance filesystem MCP server"
)]
struct Cli {
    /// Path to surgicalfs.toml config file
    #[arg(long)]
    config: Option<PathBuf>,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Disable all write/mutation tools (read-only mode)
    #[arg(long)]
    read_only: bool,

    /// Allowed directories (fallback if no config file)
    #[arg(trailing_var_arg = true)]
    directories: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging to stderr (stdout reserved for MCP JSON-RPC)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("SurgicalFS MCP server starting...");

    // Load config
    let mut cfg = if let Some(config_path) = &cli.config {
        tracing::info!("Loading config from: {}", config_path.display());
        config::Config::load(config_path)?
    } else if !cli.directories.is_empty() {
        tracing::info!("Using directory arguments: {:?}", cli.directories);
        config::Config::from_directories(cli.directories)?
    } else if let Some(default_path) = config::Config::find_default() {
        tracing::info!("Found default config at: {}", default_path.display());
        config::Config::load(&default_path)?
    } else {
        anyhow::bail!(
            "No config file or directories specified.\n\
             Usage:\n  \
             surgicalfs-mcp --config surgicalfs.toml\n  \
             surgicalfs-mcp C:\\path\\to\\allowed\\dir"
        );
    };

    // CLI --read-only overrides config
    if cli.read_only {
        cfg.security.read_only = true;
    }

    tracing::info!(
        "Allowed directories: {:?}",
        cfg.security.allowed_directories
    );

    // Create path guard
    let path_guard = pathguard::PathGuard::new(
        &cfg.security.allowed_directories,
        cfg.security.follow_symlinks,
        cfg.security.max_file_size,
    )
    .map_err(|e| anyhow::anyhow!("{}", e.0.message))?;

    // Create server
    let server = server::SurgicalFsServer::new(cfg, path_guard);

    // Serve over stdio
    tracing::info!("Server ready, listening on stdio...");
    let service = server.serve(rmcp::transport::stdio()).await?;

    // Wait for MCP protocol shutdown, Ctrl+C, or stdin pipe break.
    //
    // In supergateway stateless mode, a new surgicalfs-mcp process is spawned
    // per HTTP request. After the response is sent, supergateway never closes
    // stdin or kills the child — so service.waiting() blocks forever and
    // processes accumulate as zombies. The stdin_pipe_broken() check detects
    // this by polling the stdin pipe handle without reading (PeekNamedPipe on
    // Windows) so it doesn't compete with rmcp's stdin reader.
    tokio::select! {
        result = service.waiting() => {
            result?;
            tracing::info!("MCP session ended, shutting down.");
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl+C received, shutting down.");
        }
        _ = stdin_pipe_broken() => {
            tracing::info!("Stdin pipe broken (parent exited), shutting down.");
        }
    }

    Ok(())
}

/// Detect when the stdin pipe is broken (writer closed their end).
///
/// Uses PeekNamedPipe on Windows to check the pipe handle state WITHOUT
/// reading any data (zero-byte peek). This avoids competing with rmcp's
/// stdin reader. When the pipe writer (supergateway/Node.js) exits or
/// closes the pipe, PeekNamedPipe returns FALSE with ERROR_BROKEN_PIPE.
///
/// Polls every 2 seconds — low overhead, fast enough to catch orphans.
async fn stdin_pipe_broken() {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        tokio::task::spawn_blocking(|| {
            let stdin = std::io::stdin();
            let handle = stdin.as_raw_handle();
            loop {
                // PeekNamedPipe with 0-byte buffer: checks pipe state without reading.
                // Returns FALSE (0) when pipe is broken (ERROR_BROKEN_PIPE).
                let ok = unsafe {
                    PeekNamedPipe(
                        handle,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };
                if ok == 0 {
                    // Pipe broken — writer exited
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        })
        .await
        .ok();
    }

    #[cfg(not(windows))]
    {
        // On Unix, rmcp's stdio transport reliably detects EOF via poll/epoll,
        // so service.waiting() will return. This is a no-op fallback.
        std::future::pending::<()>().await;
    }
}

#[cfg(windows)]
extern "system" {
    /// Win32 PeekNamedPipe — checks pipe state without consuming data.
    /// https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-peeknamedpipe
    fn PeekNamedPipe(
        h_named_pipe: *mut std::ffi::c_void,
        lp_buffer: *mut std::ffi::c_void,
        n_buffer_size: u32,
        lp_bytes_read: *mut u32,
        lp_total_bytes_avail: *mut u32,
        lp_bytes_left_this_message: *mut u32,
    ) -> i32;
}
