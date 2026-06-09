mod config;
mod encoding;
mod errors;
mod lifecycle;
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

    /// Exit after N seconds with no tool activity (0 = never). Overrides the
    /// `[runtime] idle_timeout_secs` config value. Needed for the remote
    /// supergateway deployment to reap orphaned children — see `src/lifecycle.rs`.
    #[arg(long)]
    idle_timeout_secs: Option<u64>,

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
    // CLI --idle-timeout-secs overrides config
    if let Some(secs) = cli.idle_timeout_secs {
        cfg.runtime.idle_timeout_secs = secs;
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

    // Capture lifecycle settings before cfg is moved into the server.
    let idle_timeout_secs = cfg.runtime.idle_timeout_secs;

    // Create server
    let server = server::SurgicalFsServer::new(cfg, path_guard);

    // Start the idle self-reap watchdog as an INDEPENDENT task before serving.
    //
    // It must NOT live inside the post-serve select below: serve() does not
    // return until the client's MCP initialize handshake completes, so a
    // watchdog placed after it would never run for a child stuck before or
    // during init (e.g. a connection the gateway dropped mid-handshake) — the
    // very orphan we must reap under supergateway. As a standalone task it
    // covers every phase (pre-init, idle-between-calls, post-call); the
    // in-flight guard in ActivityTracker still prevents reaping mid-response.
    if idle_timeout_secs > 0 {
        let activity = server.activity_handle();
        tokio::spawn(async move {
            lifecycle::idle_watchdog(activity, idle_timeout_secs).await;
            tracing::info!(
                "Idle for {idle_timeout_secs}s with no tool activity; self-reaping orphaned child."
            );
            std::process::exit(0);
        });
    }

    // Serve over stdio
    tracing::info!("Server ready, listening on stdio...");
    let service = server.serve(rmcp::transport::stdio()).await?;

    // Shut down on the first of these lifecycle triggers. See `src/lifecycle.rs`
    // for the full rationale; in short, the idle self-reap is the only trigger
    // that fires when an alive-but-negligent supervisor (supergateway stateless
    // mode) leaves this child orphaned with its stdin pipe held open.
    tokio::select! {
        result = service.waiting() => {
            result?;
            tracing::info!("MCP session ended, shutting down.");
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl+C received, shutting down.");
        }
        _ = lifecycle::stdin_pipe_broken() => {
            tracing::info!("Stdin pipe broken (parent exited), shutting down.");
        }
    }

    Ok(())
}
