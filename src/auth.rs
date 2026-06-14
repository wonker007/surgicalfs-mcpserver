//! Bearer-token authentication middleware for the HTTP transport's `/mcp` route
//! (DEC-DRAFT-F). The token is configured via `[server] auth_token`; when empty,
//! authentication is disabled (the request passes through). Mounted only on the
//! `/mcp` router — `/health` is intentionally left unauthenticated (DOC-002 §7.3).
//!
//! The expected token is supplied through axum's `State` extractor via
//! `from_fn_with_state(token, bearer_auth)`, so this layer is self-contained and
//! does not depend on the router's state type.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

/// Reject requests that do not present `Authorization: Bearer <token>` matching
/// the configured token. An empty configured token disables the check.
///
/// Token comparison is constant-time (XOR fold, no early exit) to prevent timing
/// side-channels — mirrors `handler::constant_time_eq`. Both implementations
/// must stay in sync until extracted to a shared utility (candidate for Stage 3).
pub async fn bearer_auth(
    State(expected_token): State<String>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if expected_token.is_empty() {
        return Ok(next.run(req).await);
    }
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());
    match auth_header {
        Some(v)
            if v.starts_with("Bearer ")
                && constant_time_eq(&v.as_bytes()[7..], expected_token.as_bytes()) =>
        {
            Ok(next.run(req).await)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
/// Constant-time byte comparison: XOR fold with no early exit, so request timing
/// does not leak the token byte-by-byte. Length is not secret (compared first).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (*x ^ *y))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt; // for `oneshot`

    /// Build a router whose `/mcp` route is guarded by `bearer_auth` with the
    /// given configured token.
    fn app(configured_token: &str) -> Router {
        Router::new().route("/mcp", get(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(configured_token.to_string(), bearer_auth),
        )
    }

    /// Drive one request through the middleware and return the resulting status.
    async fn status_for(configured_token: &str, auth_header: Option<&str>) -> StatusCode {
        let mut builder = Request::builder().uri("/mcp");
        if let Some(h) = auth_header {
            builder = builder.header("authorization", h);
        }
        let req = builder.body(Body::empty()).unwrap();
        app(configured_token).oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn valid_token_is_authorized() {
        assert_eq!(
            status_for("secret", Some("Bearer secret")).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn missing_header_is_rejected() {
        assert_eq!(status_for("secret", None).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_token_is_rejected() {
        assert_eq!(
            status_for("secret", Some("Bearer nope")).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn malformed_scheme_is_rejected() {
        // Correct token value but not a Bearer scheme.
        assert_eq!(
            status_for("secret", Some("secret")).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn empty_config_disables_auth() {
        assert_eq!(status_for("", None).await, StatusCode::OK);
        assert_eq!(
            status_for("", Some("Bearer anything")).await,
            StatusCode::OK
        );
    }
}
