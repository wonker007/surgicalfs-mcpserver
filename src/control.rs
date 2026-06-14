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
    extract::State,
    http::{HeaderMap, HeaderName, Method, StatusCode},
    middleware::Next,
    response::{sse::Event, sse::KeepAlive, sse::Sse, Html, Json, Response},
    routing::get,
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

    Json(json!({
        "ready": true,
        "config_source": cs.config_source,
        "allowed_directories": dirs,
        "mcp_bind": cs.mcp_bind,
        "control_bind": cs.control_bind,
        "read_only": cs.read_only,
        "auth_enabled": cs.auth_enabled,
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

/// `GET /admin/tools` — read-only tool inventory by category.
async fn tools_handler(State(shared): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    let enabled = shared.enabled_tools.read().unwrap();
    let categories: Vec<serde_json::Value> = crate::config::ALL_TOOL_CATEGORIES
        .iter()
        .map(|cat| {
            let names = crate::config::tools_in_category(cat);
            let tools: Vec<serde_json::Value> = names
                .iter()
                .map(|t| json!({ "name": t, "enabled": enabled.contains(*t) }))
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

/// `GET /dashboard` — serve the self-contained HTML with the token injected.
/// Unauthenticated by design: the page *is* how the operator obtains the token.
/// Template injection is not an auth bypass — the control routes still validate
/// every request's bearer/query token.
async fn dashboard_handler(State(ctl_token): State<String>) -> Html<String> {
    let html = include_str!("../dashboard.html");
    Html(html.replace("__SURGICALFS_CTL_TOKEN__", &ctl_token))
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
        .layer(axum::middleware::from_fn_with_state(
            ctl_token.clone(),
            ctl_auth,
        ))
        .layer(ctl_cors(control_bind))
        .with_state(shared);

    let public = Router::new()
        .route("/dashboard", get(dashboard_handler))
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
        Arc::new(SharedState::new(&cfg, None))
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
        Arc::new(SharedState::new(&cfg, None))
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
        let shared = Arc::new(SharedState::new(&cfg, Some(dir.join("surgicalfs.toml"))));

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
}
