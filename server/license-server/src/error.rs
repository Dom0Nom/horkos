//! src/error.rs
//! Role: License-server library error type.
//! Target platforms: server.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum LicenseError {
    #[error("invalid request: {0}")]
    Invalid(String),

    #[error("not implemented")]
    NotImplemented,
}

impl IntoResponse for LicenseError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            LicenseError::Invalid(msg) => (
                StatusCode::BAD_REQUEST,
                json!({ "status": "invalid", "reason": msg }),
            ),
            LicenseError::NotImplemented => (
                StatusCode::NOT_IMPLEMENTED,
                json!({
                    "status": "not_implemented",
                    "reason": "licence routes are reserved; persistence + crypto land in /tdd phase"
                }),
            ),
        };
        (status, Json(body)).into_response()
    }
}
