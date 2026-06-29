//! Stateless MCP-over-HTTP handler (Stage 1.5, ACT-DRAFT-B amended).
//!
//! Replaces rmcp's `StreamableHttpService` on the `/mcp` route. Each POST is an
//! independent JSON-RPC request answered with a buffered `application/json`
//! response — no SSE, no sessions, no `Mcp-Session-Id`, no persistent channel.
//! That is what makes it survive cloudflared: DEC-DRAFT-R found the SSE/session
//! transport's server→client stream was torn down ~13ms in by the tunnel, so the
//! tool-call request channel never formed. A stateless request/response has
//! nothing to tear down.
//!
//! The full tool-dispatch chain is reused verbatim through `SurgicalFsServer`'s
//! existing `ServerHandler` methods (`get_info` / `list_tools` / `call_tool`) —
//! so `enabled_tools`, the in-flight guard, `block_in_place`, the tool_router,
//! every `#[tool]` method, the response budget, PathGuard, read-only mode and
//! atomic writes all apply unchanged. See `docs/reports/custom-http-handler-feasibility.md`.

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use rmcp::{
    model::{CallToolRequestParams, NumberOrString},
    service::{Peer, RequestContext},
    RoleServer, ServerHandler,
};
use serde_json::Value;

use crate::server;

/// Shared state for the stateless `/mcp` handler.
#[derive(Clone)]
pub struct AppState {
    pub server: std::sync::Arc<server::SurgicalFsServer>,
    /// Inert `Peer` minted once at startup. No tool method reads it, but rmcp's
    /// `call_tool`/`list_tools` require a `RequestContext` that carries one
    /// (REP-DRAFT-A). `Peer` is `Clone`, so we clone it per request.
    pub peer: Peer<RoleServer>,
    pub auth_token: String,
}

/// Bearer check. Empty configured token = auth disabled (pass-through),
/// matching DEC-DRAFT-F and the Stage 1 middleware semantics.
fn bearer_ok(configured_token: &str, auth_header: Option<&str>) -> bool {
    if configured_token.is_empty() {
        return true;
    }
    match auth_header.and_then(|v| v.strip_prefix("Bearer ")) {
        Some(token) => constant_time_eq(token.as_bytes(), configured_token.as_bytes()),
        None => false,
    }
}

/// Best-effort constant-time byte comparison for the bearer token: no early exit
/// on a content mismatch, so request timing doesn't leak the token byte-by-byte.
/// The token is the sole network-auth boundary on the public endpoint (defense in
/// depth with the Cloudflare WAF). Length is compared first and is not secret.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (*x ^ *y))
            == 0
}

/// Stateless JSON-RPC-over-HTTP entry point for `/mcp`.
pub async fn mcp_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    // Auth is checked inline (not via middleware) to avoid the axum state-type
    // conflict between a `State<String>` middleware and a `State<AppState>` route.
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    if !bearer_ok(&state.auth_token, auth_header) {
        return (StatusCode::UNAUTHORIZED, "Missing or invalid bearer token").into_response();
    }

    let request: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return json_rpc_error(None, -32700, &format!("Parse error: {e}")),
    };

    let id = request.get("id").cloned();
    let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = request.get("params").cloned().unwrap_or(Value::Null);

    match method {
        "initialize" => handle_initialize(&state, id, &params),
        "notifications/initialized" => (StatusCode::ACCEPTED, "").into_response(),
        "tools/list" => handle_list_tools(&state, id).await,
        "tools/call" => handle_call_tool(&state, id, params).await,
        other => json_rpc_error(id, -32601, &format!("Method not found: {other}")),
    }
}

/// `initialize` — `get_info()` (= `InitializeResult`) needs no context.
///
/// We echo the client's requested `protocolVersion` when present. The MCP spec
/// says the server responds with the same version it will use, and the rmcp
/// `serve()` path (used by the old transport) negotiated this — a client pinned
/// to an older version may reject the server's newer default from `get_info()`.
fn handle_initialize(state: &AppState, id: Option<Value>, params: &Value) -> Response {
    let mut info = match serde_json::to_value(state.server.get_info()) {
        Ok(v) => v,
        Err(e) => return json_rpc_error(id, -32603, &format!("internal error: {e}")),
    };
    if let (Some(pv), Some(obj)) = (
        params.get("protocolVersion").and_then(|v| v.as_str()),
        info.as_object_mut(),
    ) {
        obj.insert("protocolVersion".to_string(), Value::String(pv.to_string()));
    }
    json_rpc_response(id, info)
}

/// `tools/list` — reuse the server's `list_tools` (applies the `enabled_tools` filter).
async fn handle_list_tools(state: &AppState, id: Option<Value>) -> Response {
    let ctx = RequestContext::new(NumberOrString::Number(0), state.peer.clone());
    match state.server.list_tools(None, ctx).await {
        Ok(result) => match serde_json::to_value(result) {
            Ok(v) => {
                // Analytics (Phase 2): measure the result payload — what the LLM
                // pays to register the tools — not the JSON-RPC envelope.
                let result_bytes = v.to_string().len();
                state
                    .server
                    .shared()
                    .analytics
                    .record_presentation(result_bytes);
                json_rpc_response(id, v)
            }
            Err(e) => json_rpc_error(id, -32603, &format!("internal error: {e}")),
        },
        Err(e) => json_rpc_error(id, e.code.0 as i64, e.message.as_ref()),
    }
}

/// `tools/call` — reuse the server's `call_tool` (full dispatch chain).
async fn handle_call_tool(state: &AppState, id: Option<Value>, params: Value) -> Response {
    let call_params: CallToolRequestParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return json_rpc_error(id, -32602, &format!("Invalid params: {e}")),
    };

    // Capture analytics metadata BEFORE `call_params` is consumed by `call_tool`
    // (Phase 2). The full path is used for repo aggregation — this is the
    // operator-only analytics pipeline, distinct from the redacted `/events`.
    let tool_name = call_params.name.to_string();
    // Repo attribution looks at the first present path-like arg: `path`, then
    // `source`/`destination` (copy/move/stream), then the first of `paths`
    // (read_multiple_files) — otherwise these land in the "(no repo / system)"
    // bucket.
    let tool_path = call_params.arguments.as_ref().and_then(|a| {
        ["path", "source", "destination"]
            .iter()
            .find_map(|k| a.get(*k).and_then(|v| v.as_str()))
            .or_else(|| {
                a.get("paths")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.as_str())
            })
            .map(|s| s.to_string())
    });
    let start = std::time::Instant::now();

    let ctx = RequestContext::new(NumberOrString::Number(0), state.peer.clone());
    let outcome = state.server.call_tool(call_params, ctx).await;
    let duration_ms = start.elapsed().as_millis() as u64;

    match outcome {
        Ok(result) => match serde_json::to_value(result) {
            Ok(v) => {
                // Measure the serialized response, then record analytics. The JSONL
                // append is blocking I/O, so it runs in `block_in_place` (HTTP mode
                // is multi-threaded). Counter updates are cheap; no stdio concern —
                // the stdio path never reaches this handler.
                let response_bytes = v.to_string().len();
                let shared = state.server.shared().clone();
                let repo = tool_path
                    .as_deref()
                    .and_then(|p| shared.analytics.repo_for(p));
                let entry = crate::analytics::ToolCallEntry::new(
                    &tool_name,
                    duration_ms,
                    response_bytes,
                    "ok",
                    tool_path,
                    repo,
                );
                tokio::task::block_in_place(move || shared.analytics.record_tool_call(entry));
                json_rpc_response(id, v)
            }
            Err(e) => json_rpc_error(id, -32603, &format!("internal error: {e}")),
        },
        Err(e) => {
            // Record protocol-level failures too (e.g. not-enabled / at-capacity),
            // with the JSON-RPC error message length as the response size.
            let response_bytes = e.message.len();
            let shared = state.server.shared().clone();
            let repo = tool_path
                .as_deref()
                .and_then(|p| shared.analytics.repo_for(p));
            let entry = crate::analytics::ToolCallEntry::new(
                &tool_name,
                duration_ms,
                response_bytes,
                "error",
                tool_path,
                repo,
            );
            tokio::task::block_in_place(move || shared.analytics.record_tool_call(entry));
            json_rpc_error(id, e.code.0 as i64, e.message.as_ref())
        }
    }
}

// ─── JSON-RPC envelope helpers ───────────────────────────────────────────────

fn rpc_ok_body(id: &Option<Value>, result: Value) -> Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_err_body(id: &Option<Value>, code: i64, message: &str) -> Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn json_body(value: Value) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        value.to_string(),
    )
        .into_response()
}

fn json_rpc_response(id: Option<Value>, result: Value) -> Response {
    json_body(rpc_ok_body(&id, result))
}

/// JSON-RPC errors are delivered as HTTP 200 — the error lives in the body.
fn json_rpc_error(id: Option<Value>, code: i64, message: &str) -> Response {
    json_body(rpc_err_body(&id, code, message))
}

/// §2.5 fallback: single-event SSE framing of one JSON-RPC response. Still
/// stateless (one event, then the response ends — no persistent channel). Unused
/// by default; if the connector rejects plain `application/json`, swap a call of
/// `json_rpc_response` for this. Retained per the prompt's §2.5.
#[allow(dead_code)]
fn sse_json_rpc_response(id: Option<Value>, result: Value) -> Response {
    let frame = format!("event: message\ndata: {}\n\n", rpc_ok_body(&id, result));
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/event-stream")],
        frame,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    fn header_map(auth: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(a) = auth {
            h.insert("authorization", a.parse().unwrap());
        }
        h
    }

    /// Mint an `AppState` with a real (inert) Peer, plus a real `SurgicalFsServer`
    /// allowlisting the temp dir. Returns the throwaway `RunningService` so the
    /// caller keeps it alive for the test's duration.
    async fn build_state(
        auth_token: &str,
    ) -> (
        AppState,
        rmcp::service::RunningService<RoleServer, server::SurgicalFsServer>,
    ) {
        let tmp = std::env::temp_dir().to_string_lossy().to_string();
        let cfg = crate::config::Config::from_directories(vec![tmp.clone()]).unwrap();
        let pg = crate::pathguard::PathGuard::new(&[tmp], false, 5_242_880).unwrap();
        let (dr, dw) = tokio::io::duplex(64);
        let rs = rmcp::service::serve_directly(
            server::SurgicalFsServer::new(cfg.clone(), pg.clone()),
            (dr, dw),
            None,
        );
        let peer = rs.peer().clone();
        let state = AppState {
            server: std::sync::Arc::new(server::SurgicalFsServer::new(cfg, pg)),
            peer,
            auth_token: auth_token.to_string(),
        };
        (state, rs)
    }

    async fn call(state: &AppState, auth: Option<&str>, body: &str) -> (StatusCode, Value) {
        let resp = mcp_handler(State(state.clone()), header_map(auth), body.to_string()).await;
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    #[test]
    fn bearer_ok_cases() {
        assert!(bearer_ok("", None)); // empty config disables auth
        assert!(bearer_ok("", Some("Bearer anything")));
        assert!(bearer_ok("secret", Some("Bearer secret")));
        assert!(!bearer_ok("secret", None));
        assert!(!bearer_ok("secret", Some("Bearer wrong")));
        assert!(!bearer_ok("secret", Some("secret"))); // missing "Bearer " scheme
    }

    #[test]
    fn rpc_bodies_format() {
        let ok = rpc_ok_body(&Some(serde_json::json!(7)), serde_json::json!({"x": 1}));
        assert_eq!(ok["jsonrpc"], "2.0");
        assert_eq!(ok["id"], 7);
        assert_eq!(ok["result"]["x"], 1);

        let err = rpc_err_body(&None, -32601, "nope");
        assert_eq!(err["jsonrpc"], "2.0");
        assert!(err["id"].is_null());
        assert_eq!(err["error"]["code"], -32601);
        assert_eq!(err["error"]["message"], "nope");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dispatch_paths() {
        let (state, _rs) = build_state("").await;

        // Parse error.
        let (st, v) = call(&state, None, "not json at all").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["error"]["code"], -32700);

        // Unknown method.
        let (_st, v) = call(&state, None, r#"{"jsonrpc":"2.0","id":1,"method":"bogus"}"#).await;
        assert_eq!(v["error"]["code"], -32601);

        // Invalid tools/call params (missing required `name`).
        let (_st, v) = call(
            &state,
            None,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"nope":true}}"#,
        )
        .await;
        assert_eq!(v["error"]["code"], -32602);

        // initialize → InitializeResult, with the client's protocolVersion echoed.
        let (_st, v) = call(
            &state,
            None,
            r#"{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
        )
        .await;
        assert!(v["result"]["capabilities"].is_object());
        assert_eq!(v["result"]["protocolVersion"], "2025-03-26");

        // tools/list → non-empty tools array.
        let (_st, v) = call(
            &state,
            None,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/list"}"#,
        )
        .await;
        assert!(v["result"]["tools"]
            .as_array()
            .is_some_and(|t| !t.is_empty()));

        // tools/call → real dispatch through the full chain.
        let (_st, v) = call(
            &state,
            None,
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"list_allowed_directories","arguments":{}}}"#,
        )
        .await;
        assert_eq!(v["result"]["isError"], false);

        // notifications/initialized → 202 Accepted, no body (MCP Streamable HTTP spec).
        let (st, _) = call(
            &state,
            None,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn auth_enforced_when_configured() {
        let (state, _rs) = build_state("s3cret").await;
        let list = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;

        let (st, _) = call(&state, None, list).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);

        let (st, _) = call(&state, Some("Bearer nope"), list).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);

        let (st, v) = call(&state, Some("Bearer s3cret"), list).await;
        assert_eq!(st, StatusCode::OK);
        assert!(v["result"]["tools"].is_array());
    }
}
