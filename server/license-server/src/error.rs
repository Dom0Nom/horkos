//! src/error.rs
//! Role: License-server library error type. Every verification failure is a
//!       distinct, fail-closed variant.
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

    #[error("malformed licence token: {0}")]
    InvalidToken(&'static str),

    #[error("licence signature invalid")]
    SignatureInvalid,

    #[error("licence bound to a different hardware id")]
    HardwareMismatch,

    #[error("licence expired")]
    Expired,

    #[error("licence revoked")]
    Revoked,

    #[error("licence not found")]
    NotFound,

    #[error("internal license error: {0}")]
    Internal(String),
}

impl IntoResponse for LicenseError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            LicenseError::Invalid(msg) => (
                StatusCode::BAD_REQUEST,
                json!({ "status": "invalid", "reason": msg }),
            ),
            LicenseError::InvalidToken(msg) => (
                StatusCode::BAD_REQUEST,
                json!({ "status": "invalid_token", "reason": msg }),
            ),
            // Signature / binding / expiry / revocation are all "not valid" —
            // 403 with a coarse reason; a prober learns nothing exploitable.
            LicenseError::SignatureInvalid => (
                StatusCode::FORBIDDEN,
                json!({ "status": "invalid", "reason": "signature" }),
            ),
            LicenseError::HardwareMismatch => (
                StatusCode::FORBIDDEN,
                json!({ "status": "invalid", "reason": "hardware_mismatch" }),
            ),
            LicenseError::Expired => (
                StatusCode::FORBIDDEN,
                json!({ "status": "invalid", "reason": "expired" }),
            ),
            LicenseError::Revoked => (
                StatusCode::FORBIDDEN,
                json!({ "status": "invalid", "reason": "revoked" }),
            ),
            LicenseError::NotFound => (StatusCode::NOT_FOUND, json!({ "status": "not_found" })),
            LicenseError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "status": "error" }),
            ),
        };
        (status, Json(body)).into_response()
    }
}
