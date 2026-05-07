//! src/error.rs
//! Role: API binary error type. Library code uses `thiserror`; only `main` may
//!       use `anyhow` per CLAUDE.md guardrail #8.
//! Target platforms: server (any tokio-supported OS).

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found")]
    NotFound,

    #[error("service unavailable: {reason}")]
    ServiceUnavailable { reason: &'static str },

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("internal error")]
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            ApiError::NotFound => (StatusCode::NOT_FOUND, json!({ "status": "not_found" })),
            ApiError::ServiceUnavailable { reason } => (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({ "status": "unavailable", "reason": reason }),
            ),
            ApiError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                json!({ "status": "bad_request", "reason": msg }),
            ),
            ApiError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "status": "error" }),
            ),
        };
        (status, Json(body)).into_response()
    }
}
