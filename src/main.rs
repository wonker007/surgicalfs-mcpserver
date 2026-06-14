// `auth::bearer_auth` (the Stage 1 middleware) is retained for potential future
// use but is no longer in the `/mcp` request path — Stage 1.5 checks the bearer
// inline in `handler::mcp_handler` to avoid an axum `State`-type conflict. The
// module-level allow keeps it compiled (per the prompt's "keep auth.rs") without
// tripping `clippy -D warnings` on the now-unused fn.
#[allow(dead_code)]
mod auth;
mod config;
mod control;
mod encoding;
mod errors;
mod handler;
mod lifecycle;
mod metrics;
mod pathguard;
mod redact;
mod response_budget;
mod search_backend;
mod server;
mod shared;
mod state;
mod tools;

use anyhow::Result;
use clap::Parser;
use rmcp::ServiceExt;
use std::path::PathBuf;

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

    /// Transport to serve on: "stdio" (default) or "http". Overrides the
    /// `[server] transport` config value.
    #[arg(long)]
    transport: Option<String>,

    /// HTTP bind address, e.g. 127.0.0.1:8787 (HTTP transport only). Overrides
    /// the `[server] bind` config value.
    #[arg(long)]
    bind: Option<String>,

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

    // Load config BEFORE initializing logging: structured file logging needs
    // `cfg.logging.log_dir`. The config source is captured here and logged once
    // below, after the subscriber is up, so the breadcrumb isn't lost.
    let config_source: String;
    let mut loaded_path: Option<PathBuf> = None;
    let mut cfg = if let Some(config_path) = &cli.config {
        config_source = format!("config file {}", config_path.display());
        loaded_path = Some(config_path.clone());
        config::Config::load(config_path)?
    } else if !cli.directories.is_empty() {
        config_source = format!("directory arguments {:?}", cli.directories);
        config::Config::from_directories(cli.directories.clone())?
    } else if let Some(default_path) = config::Config::find_default() {
        config_source = format!("default config {}", default_path.display());
        loaded_path = Some(default_path.clone());
        config::Config::load(&default_path)?
    } else {
        anyhow::bail!(
            "No config file or directories specified.\n\
             Usage:\n  \
             surgicalfs-mcp --config surgicalfs.toml\n  \
             surgicalfs-mcp C:\\path\\to\\allowed\\dir"
        );
    };
    // `loaded_path` records where the config came from (passed into `run_http`
    // so the control plane's `/ready` can report it as `config_source`; `None`
    // for directory-argument mode).

    // CLI --read-only overrides config
    if cli.read_only {
        cfg.security.read_only = true;
    }
    // CLI --idle-timeout-secs overrides config
    if let Some(secs) = cli.idle_timeout_secs {
        cfg.runtime.idle_timeout_secs = secs;
    }

    // Initialize logging: stderr always (stdout reserved for MCP JSON-RPC), plus
    // a rolling daily JSON file when `[logging] log_dir` is set. The guard MUST
    // live for the whole process (dropping it stops the background writer and
    // loses buffered entries), so it stays in `main`'s scope.
    let _log_guard = setup_logging(&cli.log_level, &cfg.logging.log_dir);

    tracing::info!("SurgicalFS MCP server starting...");
    tracing::info!("Loaded {config_source}");
    tracing::info!(
        "Allowed directories: {:?}",
        cfg.security.allowed_directories
    );

    // Determine the transport (CLI `--transport` overrides `[server] transport`)
    // and the HTTP bind address (CLI `--bind` overrides `[server] bind`).
    let transport = cli
        .transport
        .clone()
        .unwrap_or_else(|| cfg.server.transport.clone());
    let bind = cli.bind.clone().unwrap_or_else(|| cfg.server.bind.clone());

    // Create path guard
    let path_guard = pathguard::PathGuard::new(
        &cfg.security.allowed_directories,
        cfg.security.follow_symlinks,
        cfg.security.max_file_size,
    )
    .map_err(|e| anyhow::anyhow!("{}", e.0.message))?;

    match transport.as_str() {
        "stdio" => run_stdio(cfg, path_guard).await,
        "http" => {
            // The idle self-reap is a stdio-only mechanism. In HTTP mode a
            // periodic self-exit would trigger a supervisor restart storm and
            // tear down long-lived SSE streams (v0.5.0 review, High-reliability
            // finding), so force it off and warn if a value was supplied.
            if cfg.runtime.idle_timeout_secs > 0 {
                tracing::warn!(
                    "idle_timeout_secs = {} is ignored in HTTP transport (it would cause a \
                     restart storm); forcing 0.",
                    cfg.runtime.idle_timeout_secs
                );
                cfg.runtime.idle_timeout_secs = 0;
            }
            run_http(cfg, path_guard, bind, loaded_path).await
        }
        other => anyhow::bail!(
            "Unknown transport '{}'. Valid values: \"stdio\" or \"http\".",
            other
        ),
    }
}

/// Initialize tracing. Always logs to stderr (stdout is reserved for MCP
/// JSON-RPC). When `log_dir` is non-empty, additionally writes a rolling daily
/// JSON log file (`surgicalfs.log`) through a non-blocking background writer;
/// the returned `WorkerGuard` must be held for the process lifetime (see the
/// call site in `main`). `RUST_LOG` overrides `log_level` when set.
fn setup_logging(
    log_level: &str,
    log_dir: &str,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    if log_dir.is_empty() {
        // Stderr only — backward-compatible with every prior release.
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().with_writer(std::io::stderr))
            .init();
        None
    } else {
        let file_appender = tracing_appender::rolling::daily(log_dir, "surgicalfs.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().with_writer(std::io::stderr))
            .with(fmt::layer().json().with_writer(non_blocking))
            .init();
        Some(guard)
    }
}

/// Serve over stdio (the default, backward-compatible transport). This is the
/// original `main()` body extracted verbatim — no behavior changes.
async fn run_stdio(cfg: config::Config, path_guard: pathguard::PathGuard) -> Result<()> {
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

/// Serve over a stateless MCP-over-HTTP handler (Stage 1.5, ACT-DRAFT-B amended;
/// DOC-002 §2.2, §5). Mounts a bearer-authed `/mcp` (DEC-DRAFT-F, checked inline
/// in `handler::mcp_handler`) and an unauthenticated `/health` probe (DOC-002 §7.3).
///
/// This replaces rmcp's `StreamableHttpService` (DEC-DRAFT-K): the DEC-DRAFT-R
/// production gate showed its SSE/session transport's server→client stream is torn
/// down by cloudflared (~13ms), so the tool-call request channel never formed.
/// The stateless handler answers each POST with buffered `application/json` — no
/// SSE, no sessions — while reusing the full tool-dispatch chain via the server's
/// existing `ServerHandler` methods. See `docs/reports/custom-http-handler-feasibility.md`.
async fn run_http(
    cfg: config::Config,
    path_guard: pathguard::PathGuard,
    bind: String,
    config_path: Option<PathBuf>,
) -> Result<()> {
    use axum::extract::DefaultBodyLimit;
    use axum::routing::{get, post};
    use axum::Router;

    // Capture the control-plane bind before `cfg` is consumed below.
    let control_bind = cfg.server.control_bind.clone();

    // Control-plane token (DEC-DRAFT-M): minted per boot, written to disk with a
    // restricted ACL on Windows, injected into `/dashboard`, and NEVER logged.
    let ctl_token_path = state::ctl_token_path(config_path.as_deref());
    let ctl_token = state::generate_ctl_token();
    state::write_ctl_token(&ctl_token_path, &ctl_token).map_err(|e| {
        anyhow::anyhow!(
            "Failed to write control token to {}: {e}",
            ctl_token_path.display()
        )
    })?;
    tracing::info!(
        "Control-plane token written to {} (value not logged)",
        ctl_token_path.display()
    );

    // SharedState is created BEFORE the server so the server, the process
    // metrics sampler, and the control plane observe one instance (DEC-DRAFT-L).
    // The config source path feeds the control plane's `/ready` `config_source`.
    let shared = std::sync::Arc::new(shared::SharedState::new(&cfg, config_path));

    // Process metrics sampler (HTTP mode only): refreshes RSS + handle count
    // every 10s into `shared.metrics`, and bridges each sample onto the SSE bus
    // as a `Health` event when the dashboard is watching.
    {
        let shared_for_sampler = shared.clone();
        tokio::spawn(async move {
            metrics::process_metrics_sampler(shared_for_sampler).await;
        });
    }

    // Self-maintenance (Stage 5, DOC-002 §7.4): sweep orphaned `.surgicalfs-tmp`
    // files left behind by a hard kill mid-atomic-write — once at startup (to clear
    // prior-crash orphans promptly) and then every 5 minutes. The sweep is
    // blocking tree-walk I/O, so it runs on the blocking pool via `spawn_blocking`
    // to keep it off the async workers (same discipline as `call_tool`'s
    // `block_in_place` and `stdin_pipe_broken`'s `spawn_blocking`). It only reaps
    // files older than its age threshold, so it never races an in-flight write.
    {
        let dirs = cfg.security.allowed_directories.clone();
        tokio::spawn(async move {
            loop {
                let d = dirs.clone();
                let _ = tokio::task::spawn_blocking(move || lifecycle::sweep_tmp_files(&d)).await;
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            }
        });
    }

    let auth_token = cfg.server.auth_token.clone();
    if auth_token.is_empty() {
        tracing::warn!(
            "[server] auth_token is empty: /mcp is UNAUTHENTICATED. Set a bearer token before any \
             non-loopback exposure."
        );
    } else {
        tracing::info!("/mcp bearer authentication enabled.");
    }

    // Mint an inert `Peer<RoleServer>` once. No tool method reads it, but rmcp's
    // `call_tool`/`list_tools` require a `RequestContext` that carries one
    // (REP-DRAFT-A §3). `serve_directly` is a public, synchronous free function
    // that skips the MCP init handshake; we run it over a throwaway in-process
    // duplex transport purely to obtain the Peer, then clone it per request.
    let (dr, dw) = tokio::io::duplex(4096);
    let throwaway = server::SurgicalFsServer::new(cfg.clone(), path_guard.clone());
    let throwaway_rs = rmcp::service::serve_directly(throwaway, (dr, dw), None);
    let peer = throwaway_rs.peer().clone();
    // Keep the throwaway service alive in the background. Dropping it would cancel
    // its task (harmless — the Peer is never exercised), but keeping it alive is
    // more robust against future rmcp versions adding Peer liveness checks.
    tokio::spawn(async move {
        let _ = throwaway_rs.waiting().await;
    });

    // Stage 2: build the real server from the pre-created SharedState.
    let server = std::sync::Arc::new(server::SurgicalFsServer::new_with_shared(
        cfg,
        path_guard,
        shared.clone(),
    ));
    let app_state = handler::AppState {
        server,
        peer,
        auth_token,
    };

    // MCP data-plane router (unchanged): `/mcp` POST → stateless handler (auth
    // checked inline), 1 MiB body cap, and an unauthenticated `/health` probe
    // (DOC-002 §7.3).
    let mcp_app = Router::new()
        .route("/mcp", post(handler::mcp_handler))
        .layer(DefaultBodyLimit::max(1_048_576))
        .route("/health", get(health_handler))
        .with_state(app_state);

    // Control-plane router (Stage 3): localhost-only operator surface on a
    // separate listener (DEC-DRAFT-A). Never routed through the Cloudflare Tunnel.
    let ctl_app = control::control_router(shared, ctl_token, &control_bind);

    // Bind both listeners up front so a bind failure aborts startup cleanly.
    let mcp_listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind MCP listener on {bind}: {e}"))?;
    tracing::info!(
        "MCP data plane ready (stateless JSON-RPC) on http://{bind} (routes: /mcp, /health)"
    );
    let ctl_listener = tokio::net::TcpListener::bind(&control_bind)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind control plane on {control_bind}: {e}"))?;
    tracing::info!("Control plane ready on http://{control_bind}/dashboard");

    // Dual graceful shutdown: a single Ctrl+C fans out to both servers via a
    // watch channel, so both drain together (STOP condition §13.6).
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    {
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("Ctrl+C received, shutting down both listeners...");
            let _ = tx.send(true);
        });
    }

    // Each listener gets a BOUNDED graceful drain. A single Ctrl+C starts the
    // graceful shutdown, but an open `/events` SSE stream is an infinite response
    // that axum's `with_graceful_shutdown` would wait on forever (it drains every
    // in-flight connection), so the process would hang with a dashboard tab open.
    // We therefore race the graceful serve against a hard deadline measured from
    // the shutdown signal: quick connections (MCP tool calls) drain cleanly; a
    // wedged SSE connection is abandoned after the grace period and the process
    // exits (STOP condition §13.6 — both listeners stop on Ctrl+C).
    const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

    let mut mcp_rx = shutdown_tx.subscribe();
    let mut mcp_deadline_rx = shutdown_tx.subscribe();
    let mcp_handle = tokio::spawn(async move {
        tokio::select! {
            r = axum::serve(mcp_listener, mcp_app)
                .with_graceful_shutdown(async move { let _ = mcp_rx.changed().await; }) => r,
            _ = async move {
                let _ = mcp_deadline_rx.changed().await;
                tokio::time::sleep(SHUTDOWN_GRACE).await;
            } => Ok(()),
        }
    });

    let mut ctl_rx = shutdown_tx.subscribe();
    let mut ctl_deadline_rx = shutdown_tx.subscribe();
    let ctl_handle = tokio::spawn(async move {
        tokio::select! {
            r = axum::serve(ctl_listener, ctl_app)
                .with_graceful_shutdown(async move { let _ = ctl_rx.changed().await; }) => r,
            _ = async move {
                let _ = ctl_deadline_rx.changed().await;
                tokio::time::sleep(SHUTDOWN_GRACE).await;
            } => Ok(()),
        }
    });

    let (mcp_result, ctl_result) = tokio::join!(mcp_handle, ctl_handle);
    match mcp_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!("MCP server error: {e}"),
        Err(e) => tracing::error!("MCP server task panicked: {e}"),
    }
    match ctl_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!("Control server error: {e}"),
        Err(e) => tracing::error!("Control server task panicked: {e}"),
    }

    Ok(())
}

/// Unauthenticated health probe. Returns only non-sensitive process status
/// (DOC-002 §7.3): no allowed paths, no tool names, no config values.
async fn health_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "transport": "http",
        "pid": std::process::id(),
    }))
}
