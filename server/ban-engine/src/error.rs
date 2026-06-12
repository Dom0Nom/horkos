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

    #[error("bundle trust root invalid (expected 32-byte hex Ed25519 key)")]
    InvalidTrustRoot,

    #[error("invalid fusion parameter: {0}")]
    InvalidFusionParams(&'static str),

    #[error("decision store I/O: {0}")]
    StoreIo(#[from] std::io::Error),

    #[error("decision store serialization: {0}")]
    StoreSerde(#[from] serde_json::Error),
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
            BanEngineError::InvalidTrustRoot => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "status": "trust_root_invalid" }),
            ),
            BanEngineError::InvalidFusionParams(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "status": "fusion_params_invalid", "reason": msg }),
            ),
            BanEngineError::StoreIo(_) | BanEngineError::StoreSerde(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "status": "decision_store_error" }),
            ),
        };
        (status, Json(body)).into_response()
    }
}
