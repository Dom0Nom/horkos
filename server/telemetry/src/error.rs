//! src/error.rs
//! Role: Telemetry library error type. `thiserror` only — no `unwrap()`
//!       outside tests (CLAUDE.md guardrail #8).
//! Target platforms: server.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("invalid payload: {0}")]
    InvalidPayload(String),

    #[error("rate limit exceeded")]
    RateLimited,

    #[error("internal telemetry error")]
    Internal,
}

impl IntoResponse for TelemetryError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            TelemetryError::InvalidPayload(msg) => (
                StatusCode::BAD_REQUEST,
                json!({ "status": "invalid_payload", "reason": msg }),
            ),
            TelemetryError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                json!({ "status": "rate_limited" }),
            ),
            TelemetryError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "status": "error" }),
            ),
        };
        (status, Json(body)).into_response()
    }
}
