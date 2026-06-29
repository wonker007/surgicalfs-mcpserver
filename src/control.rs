//! Control-plane routes, auth, and CORS (DOC-002 §4; DEC-DRAFT-A/H/M/N).
//!
//! A second axum listener (separate from `/mcp`) bound localhost-only
//! (DEC-DRAFT-A) and NEVER routed through the Cloudflare Tunnel. It serves a
//! read-only operator surface:
//!
//! | Route          | Auth                         | Purpose |
//! |----------------|------------------------------|---------|
//! | `GET /health`  | bearer + `X-SurgicalFS-Ctl`  | status, version, uptime, RSS, handles |
//! | `GET /ready`   | bearer + `X-SurgicalFS-Ctl`  | config snapshot + directory reachability |
//! | `GET /metrics` | bearer + `X-SurgicalFS-Ctl`  | request counters, latency buckets, process |
//! | `GET /events`  | bearer **or** `?token=`      | SSE activity feed (redacted) |
//! | `GET /admin/tools` | bearer + `X-SurgicalFS-Ctl` | tool inventory by category |
//! | `GET /dashboard`   | none (embeds the token)     | self-contained HTML UI |
//!
//! Auth is a per-boot CSPRNG token (`state::generate_ctl_token`). Every authed
//! route requires `Authorization: Bearer <token>` plus a custom
//! `X-SurgicalFS-Ctl: 1` header (CSRF defense — a cross-origin page can't set it
//! without a CORS preflight, which the strict policy blocks). `/events` is the
//! exception: `EventSource` cannot set headers, so it accepts the secret token as
//! a `?token=` query param (DEC-DRAFT-H / prompt §9.4 Option A) and relies on the
//! token's secrecy + strict CORS instead of the custom header.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderName, Method, StatusCode},
    middleware::Next,
    response::{sse::Event, sse::KeepAlive, sse::Sse, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde_json::json;
use std::time::Duration;
use tokio_stream::{wrappers::BroadcastStream, Stream, StreamExt};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::shared::SharedState;

// ─── Auth middleware ─────────────────────────────────────────────────────────

/// Validate control-plane auth. Every authed route requires a bearer token and
/// the `X-SurgicalFS-Ctl: 1` header; `/events` instead accepts a `?token=` query
/// param and skips the custom-header requirement (EventSource can't send either).
async fn ctl_auth(
    State(ctl_token): State<String>,
    headers: HeaderMap,
    req: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let is_events = req.uri().path() == "/events";

    // Token from `Authorization: Bearer …`, or — for `/events` only — the
    // `?token=` query param (raw match; the token is URL-safe base64, so no
    // percent-decoding is needed).
    let header_token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let query_token: Option<String> = if is_events {
        req.uri().query().and_then(query_param_token)
    } else {
        None
    };
    let provided = header_token.or(query_token.as_deref());

    let auth_ok = provided
        .map(|t| constant_time_eq(t.as_bytes(), ctl_token.as_bytes()))
        .unwrap_or(false);
    if !auth_ok {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // CSRF defense: require the custom header on everything except `/events`.
    if !is_events {
        let has_ctl_header = headers
            .get("x-surgicalfs-ctl")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "1")
            .unwrap_or(false);
        if !has_ctl_header {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    Ok(next.run(req).await)
}

/// Extract the first `token=` value from a raw query string (no percent-decode).
fn query_param_token(query: &str) -> Option<String> {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("token=").map(|v| v.to_string()))
}

/// Constant-time byte comparison (XOR fold, no early exit). Third copy in the
/// tree (`handler.rs`, `auth.rs`); not extracted because those files are out of
/// scope for this change. Length is compared first and is not secret.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (*x ^ *y))
            == 0
}

// ─── CORS ────────────────────────────────────────────────────────────────────

/// Strict CORS allowing only the control plane's own localhost origins. Built
/// from the actual `control_bind` port so a non-default port still matches.
/// Same-origin requests (the dashboard's own fetches) bypass CORS entirely; this
/// only constrains cross-origin callers, which we deny.
fn ctl_cors(control_bind: &str) -> CorsLayer {
    use axum::http::HeaderValue;
    let port = control_bind.rsplit(':').next().unwrap_or("9787");
    let origins: Vec<HeaderValue> = ["127.0.0.1", "localhost"]
        .iter()
        .filter_map(|host| format!("http://{host}:{port}").parse::<HeaderValue>().ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            HeaderName::from_static("authorization"),
            HeaderName::from_static("content-type"),
            HeaderName::from_static("x-surgicalfs-ctl"),
        ])
        .allow_credentials(false)
}

// ─── Route handlers ──────────────────────────────────────────────────────────

/// `GET /health` — status + process snapshot (more detailed than the MCP one).
async fn health_handler(State(shared): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    let snap = shared.metrics.process_snapshot.read().unwrap();
    let cs = &shared.config_snapshot;
    Json(json!({
        "status": "ok",
        "version": cs.version,
        "transport": "http",
        "uptime_secs": cs.start_time.elapsed().as_secs(),
        "pid": std::process::id(),
        "rss_bytes": snap.rss_bytes,
        "handle_count": snap.handle_count,
    }))
}

/// Resolve the EFFECTIVE MCP-auth state (Phase 3): the `surgicalfs-auth.token`
/// sidecar overrides the TOML default. Returns `(enabled, source, sidecar_exists)`
/// where `source` is `"sidecar"`, `"config"`, or `"none"`. Reads the sidecar fresh
/// so the dashboard reflects staged changes (a restart applies them).
fn auth_status(shared: &SharedState) -> (bool, &'static str, bool) {
    let path = crate::state::auth_sidecar_path(shared.config_snapshot.config_source.as_deref());
    match crate::state::read_auth_sidecar(&path) {
        Some(token) => (!token.is_empty(), "sidecar", true),
        None => {
            let toml_enabled = shared.config_snapshot.auth_enabled;
            (
                toml_enabled,
                if toml_enabled { "config" } else { "none" },
                false,
            )
        }
    }
}

/// `GET /ready` — frozen config snapshot + per-directory reachability.
async fn ready_handler(State(shared): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    let cs = &shared.config_snapshot;
    let dirs: Vec<serde_json::Value> = cs
        .allowed_directories
        .iter()
        .map(|d| {
            let reachable = std::path::Path::new(d).exists();
            json!({ "path": d, "reachable": reachable })
        })
        .collect();
    let (auth_enabled, _src, _exists) = auth_status(&shared);

    Json(json!({
        "ready": true,
        "config_source": cs.config_source,
        "allowed_directories": dirs,
        "mcp_bind": cs.mcp_bind,
        "control_bind": cs.control_bind,
        "read_only": cs.read_only,
        "auth_enabled": auth_enabled,
        "log_dir": cs.log_dir,
        "retention_days": cs.retention_days,
        "tunnel_url": cs.tunnel_url,
    }))
}

/// `GET /metrics` — request counters, latency histogram, process + tool counts.
async fn metrics_handler(State(shared): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    use std::sync::atomic::Ordering;
    let m = &shared.metrics;
    let snap = m.process_snapshot.read().unwrap();
    let enabled_count = shared.enabled_tools.read().unwrap().len();
    let total_count = crate::config::ALL_TOOL_CATEGORIES
        .iter()
        .flat_map(|c| crate::config::tools_in_category(c))
        .count();
    let max = shared.config_snapshot.max_concurrent_requests;
    let in_flight = max.saturating_sub(shared.concurrency.available_permits());

    Json(json!({
        "requests": {
            "total": m.requests_total.load(Ordering::Relaxed),
            "errors": m.requests_errors.load(Ordering::Relaxed),
            "in_flight": in_flight,
            "max_concurrent": max,
        },
        "latency": {
            "sum_us": m.latency_sum_us.load(Ordering::Relaxed),
            "buckets": {
                "lt_1ms": m.latency_buckets[0].load(Ordering::Relaxed),
                "lt_10ms": m.latency_buckets[1].load(Ordering::Relaxed),
                "lt_50ms": m.latency_buckets[2].load(Ordering::Relaxed),
                "lt_100ms": m.latency_buckets[3].load(Ordering::Relaxed),
                "lt_500ms": m.latency_buckets[4].load(Ordering::Relaxed),
                "lt_1s": m.latency_buckets[5].load(Ordering::Relaxed),
                "lt_5s": m.latency_buckets[6].load(Ordering::Relaxed),
                "gte_5s": m.latency_buckets[7].load(Ordering::Relaxed),
            },
        },
        "process": {
            "rss_bytes": snap.rss_bytes,
            "handle_count": snap.handle_count,
            "sampled_at_secs_ago": snap.sampled_at.elapsed().as_secs(),
        },
        "tools": {
            "enabled": enabled_count,
            "total": total_count,
        },
    }))
}

/// `GET /events` — SSE activity feed. Emits redacted `tool_call` events and
/// periodic `health` events; keep-alive pings hold the connection open.
async fn events_handler(
    State(shared): State<Arc<SharedState>>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = shared.event_bus.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let event_type = match &event {
                crate::shared::ActivityEvent::ToolCall { .. } => "tool_call",
                crate::shared::ActivityEvent::Health { .. } => "health",
                crate::shared::ActivityEvent::ToolToggle { .. } => "tool_toggle",
            };
            let data = serde_json::to_string(&event).unwrap_or_default();
            Some(Ok(Event::default().event(event_type).data(data)))
        }
        // Lagged (slow consumer dropped messages) — skip, keep streaming.
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}

/// `POST /admin/tools` request: an action plus targets (category names and/or
/// individual tool names). `set` replaces the whole enabled set with `targets`.
#[derive(serde::Deserialize)]
struct ToolToggleRequest {
    action: String,
    targets: Vec<String>,
}

/// `POST /admin/tools` response: the resulting enabled set + counts + whether the
/// change was persisted to the sidecar.
#[derive(serde::Serialize)]
struct ToolToggleResponse {
    enabled_tools: Vec<String>,
    enabled_count: usize,
    total_count: usize,
    persisted: bool,
}

/// `POST /admin/tools` — enable/disable/set tools at runtime (Stage 4,
/// DEC-DRAFT-B/C). Resolves category names to their constituent tools, applies
/// the action to the live `enabled_tools` set, re-enforces read-only, persists the
/// result to the sidecar (lock released BEFORE I/O), and fans a `ToolToggle` event
/// to the dashboard. `tools/list`/`tools/call` on the MCP plane see the change
/// immediately (they read the same RwLock); MCP clients pick up the new list on
/// their next `tools/list` (no push channel exists — see prompt §1).
async fn toggle_tools_handler(
    State(shared): State<Arc<SharedState>>,
    Json(req): Json<ToolToggleRequest>,
) -> Result<Json<ToolToggleResponse>, (StatusCode, String)> {
    // 1. Resolve targets: expand category names, validate individual tool names.
    let mut resolved: std::collections::HashSet<String> = std::collections::HashSet::new();
    for target in &req.targets {
        let tools = crate::config::tools_in_category(target);
        if tools.is_empty() {
            // Not a category — must be a known individual tool name.
            let exists = crate::config::ALL_TOOL_CATEGORIES
                .iter()
                .flat_map(|c| crate::config::tools_in_category(c))
                .any(|t| *t == target.as_str());
            if !exists {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Unknown tool or category: {target}"),
                ));
            }
            resolved.insert(target.clone());
        } else {
            resolved.extend(tools.iter().map(|s| s.to_string()));
        }
    }

    // Serialize the whole mutate+persist critical section so two concurrent POSTs
    // (e.g. two dashboard tabs) can't race the sidecar — neither colliding on the
    // temp file nor inverting persisted-vs-live order (Stage 4 review fix). The
    // tokio Mutex is held across the sync commit and the (sync) file write; the
    // only `.await` is this acquire, so no lock is ever held across an await.
    let _persist_guard = shared.sidecar_lock.lock().await;

    // 2. Compute the CANDIDATE set, validate it, then commit — so a rejected
    //    request (unknown action / would-be-empty) never mutates the live set.
    let snapshot = {
        let mut enabled = shared.enabled_tools.write().unwrap();
        let mut candidate: std::collections::HashSet<String> = match req.action.as_str() {
            "enable" => {
                let mut s = enabled.clone();
                s.extend(resolved.iter().cloned());
                s
            }
            "disable" => {
                let mut s = enabled.clone();
                for tool in &resolved {
                    s.remove(tool);
                }
                s
            }
            "set" => resolved.clone(),
            other => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Unknown action: {other}. Use 'enable', 'disable', or 'set'."),
                ));
            }
        };

        // 3. Read-only invariant: write tools can never be enabled (read-only wins).
        if shared.read_only {
            for name in crate::config::WRITE_TOOL_NAMES {
                candidate.remove(*name);
            }
        }

        // Guard against leaving the server with zero tools — mirrors the config
        // layer's empty-`tools.enable` rejection (config.rs). Returning here keeps
        // the live set unchanged (we have not committed `candidate` yet). To
        // disable everything deliberately, delete the sidecar to reset.
        if candidate.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "Refusing to leave zero tools enabled. Delete the sidecar to reset \
                 to the config defaults."
                    .to_string(),
            ));
        }

        // Commit the validated candidate to the live set.
        *enabled = candidate.clone();
        candidate
        // write lock released here (before any file I/O)
    };

    let enabled_count = snapshot.len();
    let enabled_list: Vec<String> = {
        let mut v: Vec<String> = snapshot.iter().cloned().collect();
        v.sort();
        v
    };
    let total_count = crate::config::ALL_TOOL_CATEGORIES
        .iter()
        .flat_map(|c| crate::config::tools_in_category(c))
        .count();

    // 4. Persist to the sidecar (write lock already released; still serialized by
    //    `_persist_guard`).

    let persisted = if let Some(ref path) = shared.state_file_path {
        match crate::state::write_sidecar(path, &snapshot) {
            Ok(()) => {
                tracing::info!("Tool state persisted to {}", path.display());
                true
            }
            Err(e) => {
                tracing::error!("Failed to persist tool state: {e}");
                false
            }
        }
    } else {
        tracing::warn!("No state file path configured — tool toggle is ephemeral");
        false
    };

    // 5. Fan a redacted toggle event to the dashboard (best-effort).
    if shared.event_bus.receiver_count() > 0 {
        let _ = shared
            .event_bus
            .send(crate::shared::ActivityEvent::ToolToggle {
                action: req.action.clone(),
                targets: req.targets.clone(),
                enabled_count,
                total_count,
            });
    }

    Ok(Json(ToolToggleResponse {
        enabled_tools: enabled_list,
        enabled_count,
        total_count,
        persisted,
    }))
}

/// `GET /admin/tools` — read-only tool inventory by category. Each tool carries
/// its `description` (from `SharedState::tool_descriptions`, populated at startup
/// from the compiled `#[tool(description = …)]` metadata); an unknown tool maps to
/// an empty string.
async fn tools_handler(State(shared): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    let enabled = shared.enabled_tools.read().unwrap();
    let descriptions = shared.tool_descriptions.read().unwrap();
    let categories: Vec<serde_json::Value> = crate::config::ALL_TOOL_CATEGORIES
        .iter()
        .map(|cat| {
            let names = crate::config::tools_in_category(cat);
            let tools: Vec<serde_json::Value> = names
                .iter()
                .map(|t| {
                    json!({
                        "name": t,
                        "enabled": enabled.contains(*t),
                        "description": descriptions.get(*t).map(String::as_str).unwrap_or(""),
                    })
                })
                .collect();
            let enabled_in_cat = names.iter().filter(|t| enabled.contains(**t)).count();
            json!({
                "category": cat,
                "tools": tools,
                "enabled_count": enabled_in_cat,
                "total_count": names.len(),
            })
        })
        .collect();

    let enabled_count = enabled.len();
    drop(enabled); // release the read lock before building the response

    Json(json!({
        "categories": categories,
        "enabled_count": enabled_count,
        "total_count": crate::config::ALL_TOOL_CATEGORIES
            .iter()
            .flat_map(|c| crate::config::tools_in_category(c))
            .count(),
    }))
}

/// `POST /admin/server` request: an action (`restart` or `stop`).
#[derive(serde::Deserialize)]
struct ServerControlRequest {
    action: String,
}

/// `POST /admin/server` — trigger a graceful server shutdown. `restart` exits the
/// process with code 1 so Shawl restarts the service; `stop` exits with code 0 so
/// it does not (manual restart required). Both signal the same `run_http` watch
/// channel (`SharedState::shutdown_tx`); the actual exit code is applied after both
/// listeners drain. Auth-protected by `ctl_auth` like every other admin route.
///
/// Action is validated BEFORE the channel is touched, so an unknown action is a
/// clean 400 even on a build with no shutdown channel (stdio/tests). A missing
/// channel (should never happen on the control plane, which only runs in HTTP mode)
/// is a defensive 500.
async fn server_control_handler(
    State(shared): State<Arc<SharedState>>,
    Json(req): Json<ServerControlRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (reason, status, message) = match req.action.as_str() {
        "restart" => (
            crate::shared::ShutdownReason::Restart,
            "restarting",
            "Server is shutting down. Shawl will restart it automatically.",
        ),
        "stop" => (
            crate::shared::ShutdownReason::Stop,
            "stopping",
            "Server is shutting down. Manual restart required (sc.exe start SurgicalFS-MCP).",
        ),
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Unknown action: {other}. Use 'restart' or 'stop'."),
            ));
        }
    };

    let tx = shared.shutdown_tx.as_ref().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Shutdown channel not configured (server not running in HTTP mode)".to_string(),
    ))?;
    // Best-effort: a send failure means every receiver was already dropped, i.e. a
    // shutdown is already in progress — nothing more to do.
    let _ = tx.send(Some(reason));
    tracing::info!("Control plane requested shutdown: {reason:?}");

    Ok(Json(json!({ "status": status, "message": message })))
}

/// `GET /analytics` — aggregated analytics (Phase 2): session totals, on-demand
/// day/week/month rollups (read from the daily JSONL files), per-tool and per-repo
/// breakdowns, and the presentation-vs-content split. The file reads run on the
/// blocking pool (`spawn_blocking`) so the rollup never stalls an async worker.
/// FULL paths flow through here — operator-only by design (localhost + ctl auth).
async fn analytics_handler(State(shared): State<Arc<SharedState>>) -> Response {
    let s = shared.clone();
    match tokio::task::spawn_blocking(move || s.analytics.aggregate()).await {
        Ok(r) => Json(serde_json::to_value(r).unwrap_or(serde_json::Value::Null)).into_response(),
        Err(e) => {
            // Return a non-2xx so the dashboard's `if (!r.ok)` path surfaces the
            // failure instead of silently rendering an empty panel.
            tracing::error!("analytics aggregation task failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "aggregation failed" })),
            )
                .into_response()
        }
    }
}

/// `GET /analytics/export?range=today|week|month|all` query.
#[derive(serde::Deserialize)]
struct ExportQuery {
    range: Option<String>,
}

/// `GET /analytics/export` — raw JSONL download for offline analysis. Returns the
/// concatenated daily files for the requested range as `application/x-ndjson` with
/// an attachment disposition. Empty body when logging is disabled.
async fn analytics_export_handler(
    State(shared): State<Arc<SharedState>>,
    Query(q): Query<ExportQuery>,
) -> Response {
    let range = q.range.unwrap_or_else(|| "today".to_string());
    let s = shared.clone();
    let body = tokio::task::spawn_blocking(move || s.analytics.export_range(&range))
        .await
        .unwrap_or_default();
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-ndjson"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"surgicalfs-analytics.jsonl\"",
            ),
        ],
        body,
    )
        .into_response()
}

// ─── Activity log viewer (Phase 3) ─────────────────────────────────────────────

/// `GET /logs?lines=N` query (default 100, capped at 500).
#[derive(serde::Deserialize)]
struct LogsQuery {
    lines: Option<usize>,
}

/// `GET /logs` — list `surgicalfs.log.*` files (newest first) + the tail of the
/// current day's file. Returns `{enabled:false,...}` when file logging is off. The
/// directory scan + file read run on the blocking pool.
async fn logs_handler(
    State(shared): State<Arc<SharedState>>,
    Query(q): Query<LogsQuery>,
) -> Json<serde_json::Value> {
    let log_dir = shared.config_snapshot.log_dir.clone();
    let lines = q.lines.unwrap_or(100).min(500);
    let v = tokio::task::spawn_blocking(move || read_logs(&log_dir, lines))
        .await
        .unwrap_or_else(|_| json!({ "enabled": false, "files": [], "tail": [] }));
    Json(v)
}

/// Blocking: enumerate `surgicalfs.log.YYYY-MM-DD` files and tail the newest.
fn read_logs(log_dir: &str, lines: usize) -> serde_json::Value {
    if log_dir.is_empty() {
        return json!({ "enabled": false, "log_dir": "", "files": [], "tail": [] });
    }
    let dir = std::path::Path::new(log_dir);
    // (name, size, date) for each valid log file.
    let mut files: Vec<(String, u64, String)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(date) = name.strip_prefix("surgicalfs.log.") {
                if chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_ok() {
                    let date_owned = date.to_string();
                    let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                    files.push((name, size, date_owned));
                }
            }
        }
    }
    files.sort_by(|a, b| b.2.cmp(&a.2)); // date descending → newest first

    // Tail the newest file. Daily rotation bounds each file's TIME span (one day),
    // not its size; reading it whole is fine for this low-volume operator log on a
    // localhost-only endpoint (a busy day could be optimized to a bounded tail read).
    let tail: Vec<String> = match files.first() {
        Some((name, _, _)) => match std::fs::read_to_string(dir.join(name)) {
            Ok(content) => {
                let all: Vec<&str> = content.lines().collect();
                let start = all.len().saturating_sub(lines);
                all[start..].iter().map(|s| s.to_string()).collect()
            }
            Err(_) => Vec::new(),
        },
        None => Vec::new(),
    };

    let files_json: Vec<serde_json::Value> = files
        .iter()
        .map(|(n, s, d)| json!({ "name": n, "size_bytes": s, "date": d }))
        .collect();
    json!({ "enabled": true, "log_dir": log_dir, "files": files_json, "tail": tail })
}

/// `GET /logs/download?file=...` query.
#[derive(serde::Deserialize)]
struct LogDownloadQuery {
    file: String,
}

/// `GET /logs/download` — download one log file as `text/plain` attachment. The
/// filename is strictly validated (`surgicalfs.log.YYYY-MM-DD`, no separators or
/// `..`) to block path traversal; unknown files 404.
async fn logs_download_handler(
    State(shared): State<Arc<SharedState>>,
    Query(q): Query<LogDownloadQuery>,
) -> Response {
    let file = q.file;
    // Validate: exact prefix + a parseable date, and no path components.
    let valid = !file.contains('/')
        && !file.contains('\\')
        && !file.contains("..")
        && file
            .strip_prefix("surgicalfs.log.")
            .map(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").is_ok())
            .unwrap_or(false);
    if !valid {
        return (StatusCode::BAD_REQUEST, "invalid log filename").into_response();
    }
    let log_dir = shared.config_snapshot.log_dir.clone();
    if log_dir.is_empty() {
        return (StatusCode::NOT_FOUND, "logging disabled").into_response();
    }
    let path = std::path::Path::new(&log_dir).join(&file);
    match tokio::task::spawn_blocking(move || std::fs::read(path)).await {
        Ok(Ok(bytes)) => (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    "text/plain; charset=utf-8".to_string(),
                ),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{file}\""),
                ),
            ],
            bytes,
        )
            .into_response(),
        _ => (StatusCode::NOT_FOUND, "log file not found").into_response(),
    }
}

// ─── MCP auth-token management (Phase 3) ───────────────────────────────────────

const AUTH_NOTE: &str = "Claude.ai web connector does not support custom Authorization headers \
     (DEC-DRAFT-W). This token works for Claude Desktop, Claude Code, and API clients.";

/// `GET /admin/auth` — current MCP-auth status (enabled / source / sidecar_exists).
async fn admin_auth_get_handler(State(shared): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    let (enabled, source, sidecar_exists) = auth_status(&shared);
    Json(json!({
        "enabled": enabled,
        "source": source,
        "sidecar_exists": sidecar_exists,
        "note": AUTH_NOTE,
    }))
}

/// `POST /admin/auth` request: an action plus an optional token (for `set`).
#[derive(serde::Deserialize)]
struct AuthActionRequest {
    action: String,
    token: Option<String>,
}

/// `POST /admin/auth` — manage the MCP-auth sidecar. `generate` mints a random
/// token, `set` writes a provided one, `clear` removes the sidecar (reset to the
/// TOML default). All require a server restart to take effect (the token is read
/// at startup into `AppState`), so every success carries `restart_required: true`.
async fn admin_auth_post_handler(
    State(shared): State<Arc<SharedState>>,
    Json(req): Json<AuthActionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let path = crate::state::auth_sidecar_path(shared.config_snapshot.config_source.as_deref());
    match req.action.as_str() {
        "generate" => {
            let token = crate::state::generate_ctl_token();
            crate::state::write_auth_sidecar(&path, &token).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("write failed: {e}"),
                )
            })?;
            Ok(Json(
                json!({ "action": "generate", "token": token, "restart_required": true }),
            ))
        }
        "set" => {
            let token = req.token.unwrap_or_default();
            if token.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "set requires a non-empty 'token' (use 'clear' to disable auth)".to_string(),
                ));
            }
            crate::state::write_auth_sidecar(&path, &token).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("write failed: {e}"),
                )
            })?;
            Ok(Json(
                json!({ "action": "set", "token": token, "restart_required": true }),
            ))
        }
        "clear" => {
            crate::state::clear_auth_sidecar(&path).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("clear failed: {e}"),
                )
            })?;
            Ok(Json(json!({ "action": "clear", "restart_required": true })))
        }
        other => Err((
            StatusCode::BAD_REQUEST,
            format!("Unknown action: {other}. Use 'generate', 'set', or 'clear'."),
        )),
    }
}

// ─── Logging management (Phase 4) ──────────────────────────────────────────────

/// The PENDING logging state recorded in the `surgicalfs-logging.json` sidecar,
/// read fresh on every call. `None` when no sidecar exists (the server boots
/// from the TOML `[logging]` default). `enabled` is true when `log_dir` is
/// non-empty; an empty-dir sidecar is the explicit "off" written by the disable
/// action (Phase 4.6). `apply_analytics_fallback` mirrors boot so the reported
/// analytics dir matches what the server will actually do on the next restart.
struct PendingLogging {
    enabled: bool,
    log_dir: String,
    analytics_log_dir: String,
    retention_days: u32,
}

fn pending_logging(shared: &SharedState) -> Option<PendingLogging> {
    let cs = &shared.config_snapshot;
    let path = crate::state::logging_sidecar_path(cs.config_source.as_deref());
    let mut sc = crate::state::read_logging_sidecar(&path)?;
    sc.apply_analytics_fallback();
    Some(PendingLogging {
        enabled: !sc.log_dir.is_empty(),
        log_dir: sc.log_dir,
        analytics_log_dir: sc.analytics_log_dir,
        retention_days: sc.retention_days,
    })
}

/// `GET /admin/logging` — the RUNNING (boot-effective) logging state PLUS the
/// PENDING on-disk sidecar state, so the dashboard can show "currently X,
/// pending Y (restart to apply)" and resolve any number of enable/disable
/// clicks with a single restart (Phase 4.6). `restart_required` is true when a
/// sidecar is staged whose effective state differs from the running state.
async fn admin_logging_get_handler(
    State(shared): State<Arc<SharedState>>,
) -> Json<serde_json::Value> {
    let cs = &shared.config_snapshot;
    let run_enabled = !cs.log_dir.is_empty();
    let pending = pending_logging(&shared);
    let (pending_json, restart_required) = match &pending {
        Some(p) => (
            json!({
                "enabled": p.enabled,
                "log_dir": p.log_dir.clone(),
                "analytics_log_dir": p.analytics_log_dir.clone(),
                "retention_days": p.retention_days,
            }),
            p.enabled != run_enabled || p.log_dir != cs.log_dir,
        ),
        None => (serde_json::Value::Null, false),
    };
    Json(json!({
        "enabled": run_enabled,
        "log_dir": cs.log_dir.clone(),
        "retention_days": cs.retention_days,
        "source": if pending.is_some() { "sidecar" } else { "config" },
        "sidecar_exists": pending.is_some(),
        "pending": pending_json,
        "restart_required": restart_required,
    }))
}

/// `POST /admin/logging` request: `enable` (optionally with a dir/retention) or
/// `disable`.
#[derive(serde::Deserialize)]
struct LoggingActionRequest {
    action: String,
    log_dir: Option<String>,
    retention_days: Option<u32>,
}

/// `POST /admin/logging` — enable/disable file logging via the sidecar. `enable`
/// defaults to `<config parent>/logs` with 30-day retention, creating the dir;
/// `disable` deletes the sidecar (reset to the TOML default). Both need a restart
/// (logging is initialized at startup), so they carry `restart_required: true`.
async fn admin_logging_post_handler(
    State(shared): State<Arc<SharedState>>,
    Json(req): Json<LoggingActionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let cs = &shared.config_snapshot;
    let path = crate::state::logging_sidecar_path(cs.config_source.as_deref());
    match req.action.as_str() {
        "enable" => {
            let default_dir = cs
                .config_source
                .as_deref()
                .and_then(|p| p.parent())
                .map(|p| p.join("logs"))
                .unwrap_or_else(|| std::env::temp_dir().join("surgicalfs-logs"));
            let log_dir = req
                .log_dir
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| default_dir.to_string_lossy().to_string());
            let retention = req.retention_days.unwrap_or(30);
            // Phase 4.5: enable BOTH tracing logs and analytics JSONL from one
            // toggle. They share the directory (distinct file naming:
            // surgicalfs.log.* vs surgicalfs-analytics-*.jsonl). Analytics keeps its
            // own 90-day default retention.
            let analytics_dir = log_dir.clone();
            let analytics_retention = 90;
            // Create the directory now so logging works on the next boot.
            std::fs::create_dir_all(&log_dir).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("could not create log dir: {e}"),
                )
            })?;
            crate::state::write_logging_sidecar(
                &path,
                &log_dir,
                retention,
                &analytics_dir,
                analytics_retention,
            )
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("write failed: {e}"),
                )
            })?;
            Ok(Json(json!({
                "action": "enable",
                "log_dir": log_dir,
                "analytics_log_dir": analytics_dir,
                "retention_days": retention,
                "restart_required": true,
            })))
        }
        "disable" => {
            // Phase 4.6: record the "off" intent as an explicit empty-log_dir
            // sidecar instead of DELETING it. A deleted sidecar fell back to the
            // running state, so GET looked like a no-op and the operator
            // restarted twice. With the empty sidecar on disk, GET reports
            // `pending: {enabled:false}` and the dashboard shows one
            // "pending: disabled (restart to apply)" banner. The next boot reads
            // the empty sidecar and starts with logging (and analytics) off.
            crate::state::write_logging_sidecar(&path, "", 30, "", 90).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("write failed: {e}"),
                )
            })?;
            Ok(Json(
                json!({ "action": "disable", "restart_required": true }),
            ))
        }
        other => Err((
            StatusCode::BAD_REQUEST,
            format!("Unknown action: {other}. Use 'enable' or 'disable'."),
        )),
    }
}

// ─── Dashboard assets (Phase 4: CSS/JS externalized from the HTML) ─────────────

/// `Cache-Control: no-cache` for all three dashboard responses — the browser may
/// cache but MUST revalidate each load, so a binary rebuild always wins on refresh.
const DASH_CACHE: &str = "no-cache";

/// `GET /dashboard` — serve the slim HTML skeleton with the per-boot token injected.
/// Unauthenticated by design: the page *is* how the operator obtains the token.
/// Template injection is not an auth bypass — the control routes still validate
/// every request's bearer/query token.
async fn dashboard_handler(State(ctl_token): State<String>) -> Response {
    let html = include_str!("../dashboard.html").replace("__SURGICALFS_CTL_TOKEN__", &ctl_token);
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, DASH_CACHE),
        ],
        html,
    )
        .into_response()
}

/// `GET /dashboard.css` — static stylesheet (unauthenticated, like `/dashboard`).
async fn dashboard_css_handler() -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, DASH_CACHE),
        ],
        include_str!("../dashboard.css"),
    )
        .into_response()
}

/// `GET /dashboard.js` — static script (unauthenticated, like `/dashboard`).
async fn dashboard_js_handler() -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, DASH_CACHE),
        ],
        include_str!("../dashboard.js"),
    )
        .into_response()
}

// ─── Router assembly ─────────────────────────────────────────────────────────

/// Build the control-plane router. Authed routes carry `State<Arc<SharedState>>`
/// and the `ctl_auth` + CORS layers; `/dashboard` is a separate sub-router with
/// `State<String>` (the token). Both sub-routers fully apply their state before
/// the merge, so axum sees one `Router<()>`.
pub fn control_router(shared: Arc<SharedState>, ctl_token: String, control_bind: &str) -> Router {
    let authed = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/metrics", get(metrics_handler))
        .route("/events", get(events_handler))
        .route(
            "/admin/tools",
            get(tools_handler).post(toggle_tools_handler),
        )
        .route("/admin/server", post(server_control_handler))
        .route(
            "/admin/auth",
            get(admin_auth_get_handler).post(admin_auth_post_handler),
        )
        .route(
            "/admin/logging",
            get(admin_logging_get_handler).post(admin_logging_post_handler),
        )
        .route("/analytics", get(analytics_handler))
        .route("/analytics/export", get(analytics_export_handler))
        .route("/logs", get(logs_handler))
        .route("/logs/download", get(logs_download_handler))
        .layer(axum::middleware::from_fn_with_state(
            ctl_token.clone(),
            ctl_auth,
        ))
        .layer(ctl_cors(control_bind))
        .with_state(shared);

    // Unauthenticated dashboard assets (the page is how the operator gets the
    // token). CSS/JS handlers ignore the `State<String>` token.
    let public = Router::new()
        .route("/dashboard", get(dashboard_handler))
        .route("/dashboard.css", get(dashboard_css_handler))
        .route("/dashboard.js", get(dashboard_js_handler))
        .with_state(ctl_token);

    authed.merge(public)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`

    const TOK: &str = "test-ctl-token-AZ09-_";

    fn test_shared() -> Arc<SharedState> {
        let tmp = std::env::temp_dir().to_string_lossy().to_string();
        let cfg = crate::config::Config::from_directories(vec![tmp]).unwrap();
        Arc::new(SharedState::new(&cfg, None, None))
    }

    fn app() -> Router {
        control_router(test_shared(), TOK.to_string(), "127.0.0.1:9787")
    }

    /// Build a GET request with optional bearer + X-SurgicalFS-Ctl headers.
    fn req(uri: &str, bearer: Option<&str>, ctl_header: bool) -> Request<Body> {
        let mut b = Request::builder().uri(uri).method("GET");
        if let Some(t) = bearer {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        if ctl_header {
            b = b.header("x-surgicalfs-ctl", "1");
        }
        b.body(Body::empty()).unwrap()
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    // ── constant_time_eq ──

    #[test]
    fn constant_time_eq_matches_only_identical() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab")); // length differs
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn query_param_token_extracts_value() {
        assert_eq!(query_param_token("token=abc").as_deref(), Some("abc"));
        assert_eq!(query_param_token("x=1&token=abc").as_deref(), Some("abc"));
        assert_eq!(query_param_token("token=abc&y=2").as_deref(), Some("abc"));
        assert_eq!(query_param_token("foo=bar").as_deref(), None);
        assert_eq!(query_param_token("").as_deref(), None);
    }

    // ── auth matrix ──

    #[tokio::test]
    async fn health_ok_with_bearer_and_ctl_header() {
        let resp = app()
            .oneshot(req("/health", Some(TOK), true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["status"], "ok");
        assert_eq!(v["transport"], "http");
        assert!(v["version"].is_string());
        assert!(v["uptime_secs"].is_number());
    }

    #[tokio::test]
    async fn unauthorized_without_token() {
        let resp = app().oneshot(req("/health", None, true)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unauthorized_with_wrong_token() {
        let resp = app()
            .oneshot(req("/health", Some("wrong"), true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn forbidden_without_ctl_header() {
        let resp = app()
            .oneshot(req("/health", Some(TOK), false))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // ── /ready ──

    #[tokio::test]
    async fn ready_reports_config_snapshot_and_reachability() {
        let resp = app().oneshot(req("/ready", Some(TOK), true)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["ready"], true);
        assert_eq!(v["control_bind"], "127.0.0.1:9787");
        let dirs = v["allowed_directories"].as_array().unwrap();
        assert!(!dirs.is_empty());
        // The temp dir exists, so it must be reported reachable.
        assert_eq!(dirs[0]["reachable"], true);
    }

    // ── /metrics ──

    #[tokio::test]
    async fn metrics_reports_counters_buckets_process() {
        let resp = app()
            .oneshot(req("/metrics", Some(TOK), true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["requests"]["total"], 0);
        assert_eq!(v["requests"]["in_flight"], 0);
        assert!(v["requests"]["max_concurrent"].is_number());
        assert!(v["latency"]["buckets"]["lt_1ms"].is_number());
        assert!(v["latency"]["buckets"]["gte_5s"].is_number());
        assert!(v["process"]["rss_bytes"].is_number());
        assert!(v["tools"]["total"].as_u64().unwrap() >= 1);
    }

    // ── /admin/tools ──

    #[tokio::test]
    async fn admin_tools_lists_categories() {
        let resp = app()
            .oneshot(req("/admin/tools", Some(TOK), true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        let cats = v["categories"].as_array().unwrap();
        assert_eq!(cats.len(), crate::config::ALL_TOOL_CATEGORIES.len());
        // All categories enabled by default (no [tools] enable).
        assert_eq!(v["enabled_count"], v["total_count"]);
        // Each category reports a name and a tools array.
        assert!(cats[0]["category"].is_string());
        assert!(cats[0]["tools"].is_array());
    }

    // ── /dashboard ──

    #[tokio::test]
    async fn dashboard_injects_token_and_needs_no_auth() {
        let resp = app().oneshot(req("/dashboard", None, false)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let html = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(html.contains(TOK), "token not injected into dashboard");
        assert!(
            !html.contains("__SURGICALFS_CTL_TOKEN__"),
            "placeholder left unreplaced"
        );
    }

    // ── /events ──

    #[tokio::test]
    async fn events_accepts_query_token_without_headers() {
        let resp = app()
            .oneshot(req(&format!("/events?token={TOK}"), None, false))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.starts_with("text/event-stream"), "content-type: {ct}");
    }

    #[tokio::test]
    async fn events_rejects_missing_token() {
        let resp = app().oneshot(req("/events", None, false)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn events_rejects_wrong_query_token() {
        let resp = app()
            .oneshot(req("/events?token=nope", None, false))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn events_also_accepts_bearer_header() {
        let resp = app()
            .oneshot(req("/events", Some(TOK), false))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── CORS ──

    #[tokio::test]
    async fn cors_preflight_allows_localhost_origin() {
        let preflight = Request::builder()
            .uri("/health")
            .method("OPTIONS")
            .header("origin", "http://127.0.0.1:9787")
            .header("access-control-request-method", "GET")
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(preflight).await.unwrap();
        // Preflight is short-circuited by the CORS layer (outermost), before auth.
        let acao = resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok());
        assert_eq!(acao, Some("http://127.0.0.1:9787"));
    }

    #[tokio::test]
    async fn cors_rejects_foreign_origin() {
        let preflight = Request::builder()
            .uri("/health")
            .method("OPTIONS")
            .header("origin", "http://evil.example.com")
            .header("access-control-request-method", "GET")
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(preflight).await.unwrap();
        // A disallowed origin gets no allow-origin header echoed back.
        assert!(resp.headers().get("access-control-allow-origin").is_none());
    }

    // ── POST /admin/tools (Stage 4) ──

    /// Build a POST request to `/admin/tools` with auth + JSON body.
    fn post_req(uri: &str, bearer: Option<&str>, ctl_header: bool, body: &str) -> Request<Body> {
        let mut b = Request::builder()
            .uri(uri)
            .method("POST")
            .header("content-type", "application/json");
        if let Some(t) = bearer {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        if ctl_header {
            b = b.header("x-surgicalfs-ctl", "1");
        }
        b.body(Body::from(body.to_string())).unwrap()
    }

    /// Read-only SharedState (no source path → toggles ephemeral).
    fn shared_ro() -> Arc<SharedState> {
        let tmp = std::env::temp_dir().to_string_lossy().to_string();
        let mut cfg = crate::config::Config::from_directories(vec![tmp]).unwrap();
        cfg.security.read_only = true;
        Arc::new(SharedState::new(&cfg, None, None))
    }

    async fn post_toggle(shared: Arc<SharedState>, body: &str) -> (StatusCode, serde_json::Value) {
        let router = control_router(shared, TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(post_req("/admin/tools", Some(TOK), true, body))
            .await
            .unwrap();
        let status = resp.status();
        (status, body_json(resp).await)
    }

    #[tokio::test]
    async fn post_disable_category_removes_its_tools() {
        // 'utility' has exactly one tool: file_checksum.
        let (st, v) = post_toggle(
            test_shared(),
            r#"{"action":"disable","targets":["utility"]}"#,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["enabled_count"], 46); // 47 - 1
        assert_eq!(v["total_count"], 47);
        let list = v["enabled_tools"].as_array().unwrap();
        assert!(!list.iter().any(|t| t == "file_checksum"));
        assert_eq!(v["persisted"], false); // no state_file_path on test_shared
    }

    #[tokio::test]
    async fn post_set_replaces_entire_set() {
        // 'json' category → json_query + json_mutate only.
        let (st, v) = post_toggle(test_shared(), r#"{"action":"set","targets":["json"]}"#).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["enabled_count"], 2);
        let mut list: Vec<String> = v["enabled_tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_string())
            .collect();
        list.sort();
        assert_eq!(list, vec!["json_mutate", "json_query"]);
    }

    #[tokio::test]
    async fn post_enable_adds_to_existing_set() {
        // Reduce to a known small set, then enable one more individual tool.
        let shared = test_shared();
        let (_st, _v) = post_toggle(shared.clone(), r#"{"action":"set","targets":["json"]}"#).await;
        let (st, v) = post_toggle(shared, r#"{"action":"enable","targets":["file_info"]}"#).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["enabled_count"], 3); // json_query, json_mutate, file_info
        let list = v["enabled_tools"].as_array().unwrap();
        assert!(list.iter().any(|t| t == "file_info"));
    }

    #[tokio::test]
    async fn post_set_empty_is_rejected() {
        // Leaving zero tools enabled is refused (mirrors the config empty-set guard).
        let (st, _v) = post_toggle(test_shared(), r#"{"action":"set","targets":[]}"#).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_readonly_enabling_only_write_tools_is_rejected() {
        // In read-only mode, 'set' to only write tools strips to empty → 400.
        let (st, _v) = post_toggle(shared_ro(), r#"{"action":"set","targets":["manage"]}"#).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_disabling_everything_is_rejected_and_live_set_unchanged() {
        // Disabling every category would leave zero tools → 400, and the live set
        // must be untouched (compute-then-validate-then-commit).
        let shared = test_shared();
        let all: Vec<&str> = crate::config::ALL_TOOL_CATEGORIES.to_vec();
        let body = format!(
            r#"{{"action":"disable","targets":{}}}"#,
            serde_json::to_string(&all).unwrap()
        );
        let (st, _v) = post_toggle(shared.clone(), &body).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        // Live set unchanged: GET still reports all 47 enabled.
        let router = control_router(shared, TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(req("/admin/tools", Some(TOK), true))
            .await
            .unwrap();
        let v = body_json(resp).await;
        assert_eq!(v["enabled_count"], 47);
    }

    #[tokio::test]
    async fn post_get_reflects_toggle() {
        let shared = test_shared();
        let (_st, _v) = post_toggle(
            shared.clone(),
            r#"{"action":"disable","targets":["compat"]}"#,
        )
        .await;
        // GET on the same shared must now show compat fully disabled.
        let router = control_router(shared, TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(req("/admin/tools", Some(TOK), true))
            .await
            .unwrap();
        let v = body_json(resp).await;
        let compat = v["categories"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["category"] == "compat")
            .unwrap();
        assert_eq!(compat["enabled_count"], 0);
    }

    #[tokio::test]
    async fn post_unknown_target_is_400() {
        let (st, _v) = post_toggle(
            test_shared(),
            r#"{"action":"enable","targets":["not_a_real_tool"]}"#,
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_unknown_action_is_400() {
        let (st, _v) = post_toggle(
            test_shared(),
            r#"{"action":"frobnicate","targets":["json"]}"#,
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_readonly_strips_write_tools() {
        // Try to enable the 'manage' category (all write tools) in read-only mode.
        let (st, v) = post_toggle(shared_ro(), r#"{"action":"enable","targets":["manage"]}"#).await;
        assert_eq!(st, StatusCode::OK);
        let list = v["enabled_tools"].as_array().unwrap();
        for write_tool in crate::config::WRITE_TOOL_NAMES {
            assert!(
                !list.iter().any(|t| t == *write_tool),
                "read-only must strip write tool {write_tool}"
            );
        }
    }

    #[tokio::test]
    async fn post_requires_bearer_token() {
        let router = control_router(test_shared(), TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(post_req(
                "/admin/tools",
                None,
                true,
                r#"{"action":"disable","targets":["json"]}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn post_requires_ctl_header() {
        let router = control_router(test_shared(), TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(post_req(
                "/admin/tools",
                Some(TOK),
                false,
                r#"{"action":"disable","targets":["json"]}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_persists_to_sidecar_when_configured() {
        let dir = std::env::temp_dir().join(format!(
            "sfs-toggle-persist-{}-{}",
            std::process::id(),
            crate::state::generate_ctl_token().get(..8).unwrap_or("x")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = crate::config::Config::from_directories(vec![dir.to_string_lossy().to_string()])
            .unwrap();
        let shared = Arc::new(SharedState::new(
            &cfg,
            Some(dir.join("surgicalfs.toml")),
            None,
        ));

        let (st, v) = post_toggle(shared, r#"{"action":"set","targets":["json"]}"#).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["persisted"], true);

        // The sidecar must exist and reload to the same set.
        let sidecar = dir.join("surgicalfs-state.json");
        assert!(sidecar.exists(), "sidecar not written");
        let reloaded = crate::state::read_sidecar(&sidecar).unwrap().unwrap();
        let expected: std::collections::HashSet<String> = ["json_query", "json_mutate"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(reloaded, expected);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── GET /admin/tools descriptions (Phase 1) ──

    #[tokio::test]
    async fn admin_tools_includes_descriptions() {
        let shared = test_shared();
        // Populate one known description (run_http does this from compiled metadata).
        shared.tool_descriptions.write().unwrap().insert(
            "file_info".to_string(),
            "Get file metadata (test)".to_string(),
        );

        let router = control_router(shared, TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(req("/admin/tools", Some(TOK), true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;

        let inspect = v["categories"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["category"] == "inspect")
            .unwrap();
        let file_info = inspect["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "file_info")
            .unwrap();
        assert_eq!(file_info["description"], "Get file metadata (test)");
        // Tools without a populated description fall back to an empty string.
        let file_head = inspect["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "file_head")
            .unwrap();
        assert_eq!(file_head["description"], "");
    }

    // ── POST /admin/server (Phase 1) ──

    /// SharedState wired with a shutdown channel; returns the live receiver so the
    /// test can observe the signal the handler sends.
    fn shared_with_shutdown() -> (
        Arc<SharedState>,
        tokio::sync::watch::Receiver<Option<crate::shared::ShutdownReason>>,
    ) {
        let (tx, rx) = tokio::sync::watch::channel(None::<crate::shared::ShutdownReason>);
        let tmp = std::env::temp_dir().to_string_lossy().to_string();
        let cfg = crate::config::Config::from_directories(vec![tmp]).unwrap();
        (Arc::new(SharedState::new(&cfg, None, Some(tx))), rx)
    }

    #[tokio::test]
    async fn admin_server_restart_sends_shutdown() {
        let (shared, mut rx) = shared_with_shutdown();
        let router = control_router(shared, TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(post_req(
                "/admin/server",
                Some(TOK),
                true,
                r#"{"action":"restart"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["status"], "restarting");
        rx.changed().await.unwrap();
        assert_eq!(*rx.borrow(), Some(crate::shared::ShutdownReason::Restart));
    }

    #[tokio::test]
    async fn admin_server_stop_sends_shutdown() {
        let (shared, mut rx) = shared_with_shutdown();
        let router = control_router(shared, TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(post_req(
                "/admin/server",
                Some(TOK),
                true,
                r#"{"action":"stop"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["status"], "stopping");
        rx.changed().await.unwrap();
        assert_eq!(*rx.borrow(), Some(crate::shared::ShutdownReason::Stop));
    }

    #[tokio::test]
    async fn admin_server_unknown_action_returns_400() {
        // Action is validated before the channel is touched, so even test_shared
        // (no shutdown channel) yields a clean 400, not a 500.
        let router = control_router(test_shared(), TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(post_req(
                "/admin/server",
                Some(TOK),
                true,
                r#"{"action":"explode"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn admin_server_requires_auth() {
        let router = control_router(test_shared(), TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(post_req(
                "/admin/server",
                None,
                true,
                r#"{"action":"restart"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_server_requires_ctl_header() {
        // CSRF defense: a valid bearer without `X-SurgicalFS-Ctl: 1` is forbidden —
        // pins the requirement for the state-changing restart/stop route.
        let router = control_router(test_shared(), TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(post_req(
                "/admin/server",
                Some(TOK),
                false,
                r#"{"action":"restart"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // ── GET /analytics + /analytics/export (Phase 2) ──

    #[tokio::test]
    async fn analytics_endpoint_returns_session_data() {
        let resp = app()
            .oneshot(req("/analytics", Some(TOK), true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        // Session is always present; per-tool/per-repo are arrays; presentation
        // and logging status are present. Logging is disabled on test_shared.
        assert!(v["session"]["total_calls"].is_number());
        assert!(v["per_tool"].is_array());
        assert!(v["per_repo"].is_array());
        assert!(v["presentation"]["calls"].is_number());
        assert_eq!(v["logging_enabled"], false);
        // Day/week/month are null when logging is disabled.
        assert!(v["today"].is_null());
        assert!(v["chars_per_token"].as_f64().unwrap() > 0.0);
    }

    #[tokio::test]
    async fn analytics_export_returns_ndjson() {
        let resp = app()
            .oneshot(req("/analytics/export?range=today", Some(TOK), true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.starts_with("application/x-ndjson"), "content-type: {ct}");
    }

    #[tokio::test]
    async fn analytics_requires_auth() {
        let resp = app().oneshot(req("/analytics", None, true)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── /logs + /admin/auth (Phase 3) ──

    /// Unique temp dir per test (avoids cross-test races on the sidecar/log files).
    fn unique_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sfs-ctl-p3-{tag}-{}-{}",
            std::process::id(),
            crate::state::generate_ctl_token().get(..8).unwrap_or("x")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// SharedState whose config has `[logging] log_dir` = `dir` and config source =
    /// `dir/surgicalfs.toml` (so the auth sidecar resolves next to it).
    fn shared_with_logdir(dir: &std::path::Path) -> Arc<SharedState> {
        let tmp = std::env::temp_dir().to_string_lossy().to_string();
        let mut cfg = crate::config::Config::from_directories(vec![tmp]).unwrap();
        cfg.logging.log_dir = dir.to_string_lossy().to_string();
        cfg.logging.retention_days = 30;
        Arc::new(SharedState::new(
            &cfg,
            Some(dir.join("surgicalfs.toml")),
            None,
        ))
    }

    #[tokio::test]
    async fn logs_endpoint_returns_file_list() {
        let dir = unique_dir("logs");
        // Two daily log files; the newer one is tailed.
        std::fs::write(
            dir.join("surgicalfs.log.2026-06-13"),
            "old line 1\nold line 2\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("surgicalfs.log.2026-06-14"),
            "{\"level\":\"INFO\",\"message\":\"hello\"}\n{\"level\":\"WARN\",\"message\":\"bye\"}\n",
        )
        .unwrap();
        let router = control_router(shared_with_logdir(&dir), TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(req("/logs?lines=50", Some(TOK), true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["enabled"], true);
        let files = v["files"].as_array().unwrap();
        assert_eq!(files.len(), 2);
        // Newest first.
        assert_eq!(files[0]["name"], "surgicalfs.log.2026-06-14");
        assert!(files[0]["size_bytes"].as_u64().unwrap() > 0);
        let tail = v["tail"].as_array().unwrap();
        assert_eq!(tail.len(), 2); // the newest file has 2 lines
        assert!(tail[1].as_str().unwrap().contains("bye"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn logs_endpoint_disabled_when_no_log_dir() {
        let resp = app().oneshot(req("/logs", Some(TOK), true)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["enabled"], false);
        assert_eq!(v["files"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn logs_download_validates_filename() {
        // Path traversal attempt → 400, never touches the filesystem.
        let resp = app()
            .oneshot(req("/logs/download?file=../../etc/passwd", Some(TOK), true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // A bogus-but-shaped name → also rejected (not a valid date).
        let resp2 = app()
            .oneshot(req(
                "/logs/download?file=surgicalfs.log.not-a-date",
                Some(TOK),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn admin_auth_get_reports_status() {
        // Fresh dir (no sidecar) + no TOML auth_token → disabled / none.
        let dir = unique_dir("authget");
        let router = control_router(shared_with_logdir(&dir), TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(req("/admin/auth", Some(TOK), true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["enabled"], false);
        assert_eq!(v["source"], "none");
        assert_eq!(v["sidecar_exists"], false);
        assert!(v["note"].as_str().unwrap().contains("Claude.ai"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_auth_generate_writes_sidecar() {
        let dir = unique_dir("authgen");
        let shared = shared_with_logdir(&dir);
        let router = control_router(shared, TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(post_req(
                "/admin/auth",
                Some(TOK),
                true,
                r#"{"action":"generate"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["action"], "generate");
        assert_eq!(v["restart_required"], true);
        assert!(v["token"].as_str().unwrap().len() >= 40);
        // The sidecar file was written next to the config.
        let sidecar = dir.join("surgicalfs-auth.token");
        assert!(sidecar.exists(), "auth sidecar not written");
        assert_eq!(
            std::fs::read_to_string(&sidecar).unwrap(),
            v["token"].as_str().unwrap()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_auth_clear_removes_sidecar() {
        let dir = unique_dir("authclear");
        // Pre-write a sidecar.
        crate::state::write_auth_sidecar(&dir.join("surgicalfs-auth.token"), "preset").unwrap();
        let shared = shared_with_logdir(&dir);
        let router = control_router(shared, TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(post_req(
                "/admin/auth",
                Some(TOK),
                true,
                r#"{"action":"clear"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["action"], "clear");
        assert!(
            !dir.join("surgicalfs-auth.token").exists(),
            "auth sidecar should be removed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_auth_requires_auth() {
        // The state-changing route must be behind ctl auth.
        let resp = app()
            .oneshot(post_req(
                "/admin/auth",
                None,
                true,
                r#"{"action":"generate"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Dashboard assets + /admin/logging (Phase 4) ──

    fn content_type(resp: &Response) -> String {
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }

    #[tokio::test]
    async fn dashboard_css_serves_content_type() {
        // Unauthenticated (None bearer, no ctl header), like /dashboard.
        let resp = app()
            .oneshot(req("/dashboard.css", None, false))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(content_type(&resp).starts_with("text/css"));
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        assert!(!bytes.is_empty(), "css body should be non-empty");
    }

    #[tokio::test]
    async fn dashboard_js_serves_content_type() {
        let resp = app()
            .oneshot(req("/dashboard.js", None, false))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(content_type(&resp).starts_with("application/javascript"));
    }

    #[tokio::test]
    async fn dashboard_assets_need_no_auth() {
        // Both assets are reachable with NO auth headers at all (200, not 401/403).
        for path in ["/dashboard.css", "/dashboard.js"] {
            let resp = app().oneshot(req(path, None, false)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{path} should need no auth");
            // And carry the revalidation cache header.
            let cc = resp
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            assert_eq!(cc, "no-cache", "{path} cache-control");
        }
    }

    #[tokio::test]
    async fn admin_logging_get_reports_status() {
        // shared_with_logdir sets [logging] log_dir → enabled, source "config".
        let dir = unique_dir("logget");
        let router = control_router(shared_with_logdir(&dir), TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(req("/admin/logging", Some(TOK), true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["enabled"], true);
        assert_eq!(v["source"], "config");
        assert_eq!(v["sidecar_exists"], false);
        assert!(v["log_dir"].is_string());
        assert!(v["retention_days"].is_number());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_logging_enable_writes_sidecar() {
        let dir = unique_dir("logenable");
        let router = control_router(shared_with_logdir(&dir), TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(post_req(
                "/admin/logging",
                Some(TOK),
                true,
                r#"{"action":"enable"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["action"], "enable");
        assert_eq!(v["restart_required"], true);
        assert!(v["log_dir"].as_str().unwrap().ends_with("logs"));
        // Phase 4.5: enable also sets analytics (same dir) and reports it back.
        assert_eq!(v["analytics_log_dir"], v["log_dir"]);
        // The sidecar was written next to the config, with both subsystems set.
        let sidecar = dir.join("surgicalfs-logging.json");
        assert!(sidecar.exists(), "logging sidecar not written");
        let sc = crate::state::read_logging_sidecar(&sidecar).unwrap();
        assert!(
            !sc.analytics_log_dir.is_empty(),
            "analytics dir not persisted"
        );
        assert_eq!(sc.analytics_log_dir, sc.log_dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_logging_disable_writes_empty_sidecar() {
        let dir = unique_dir("logdisable");
        // Pre-write an "enabled" sidecar.
        crate::state::write_logging_sidecar(&dir.join("surgicalfs-logging.json"), "X", 10, "X", 90)
            .unwrap();
        let router = control_router(shared_with_logdir(&dir), TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(post_req(
                "/admin/logging",
                Some(TOK),
                true,
                r#"{"action":"disable"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["action"], "disable");
        // Phase 4.6: disable RECORDS the off-intent as an empty-log_dir sidecar
        // (not a delete), so GET can report pending:disabled and the next boot
        // starts with logging off.
        let sidecar = dir.join("surgicalfs-logging.json");
        assert!(
            sidecar.exists(),
            "disable should leave an explicit off sidecar"
        );
        let sc = crate::state::read_logging_sidecar(&sidecar).unwrap();
        assert!(
            sc.log_dir.is_empty(),
            "disable sidecar must have empty log_dir"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_logging_get_includes_pending() {
        let dir = unique_dir("logpending");
        // Running state = enabled via [logging] log_dir (shared_with_logdir).
        // Pre-write a DISABLE sidecar (empty log_dir) → pending is disabled,
        // differs from the running (enabled) state → restart_required true.
        crate::state::write_logging_sidecar(&dir.join("surgicalfs-logging.json"), "", 0, "", 90)
            .unwrap();
        let router = control_router(shared_with_logdir(&dir), TOK.to_string(), "127.0.0.1:9787");
        let resp = router
            .oneshot(req("/admin/logging", Some(TOK), true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        // Running stays enabled (boot config); pending reflects the sidecar.
        assert_eq!(v["enabled"], true, "running state stays enabled");
        assert!(v["pending"].is_object(), "pending must reflect the sidecar");
        assert_eq!(
            v["pending"]["enabled"], false,
            "empty-dir sidecar = pending disabled"
        );
        assert_eq!(
            v["restart_required"], true,
            "pending differs from running → restart required"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
