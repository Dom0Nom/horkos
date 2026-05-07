//! src/error.rs
//! Role: Ban-engine library error type.
//! Target platforms: server.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum BanEngineError {
    #[error("rule bundle missing signature")]
    BundleUnsigned,

    #[error("rule bundle signature invalid")]
    BundleSignatureInvalid,

    #[error("rule bundle expired")]
    BundleExpired,

    #[error("verifier not implemented")]
    VerifierNotImplemented,
}

impl IntoResponse for BanEngineError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            BanEngineError::BundleUnsigned | BanEngineError::BundleSignatureInvalid => (
                StatusCode::BAD_REQUEST,
                json!({ "status": "bundle_invalid", "reason": self.to_string() }),
            ),
            BanEngineError::BundleExpired => {
                (StatusCode::GONE, json!({ "status": "bundle_expired" }))
            }
            BanEngineError::VerifierNotImplemented => (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({ "status": "verifier_not_implemented" }),
            ),
        };
        (status, Json(body)).into_response()
    }
}
