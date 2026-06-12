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

    #[error("render finding schema mismatch: {0}")]
    RenderSchema(String),

    #[error("input finding schema mismatch: {0}")]
    InputSchema(String),

    #[error("device-trust finding schema mismatch: {0}")]
    DeviceTrustSchema(String),

    #[error("pointer-feature schema mismatch: {0}")]
    PointerModel(String),

    #[error("timing report schema mismatch: {0}")]
    Timing(String),

    #[error("anti-analysis payload invalid: {0}")]
    AntiAnalysis(String),

    #[error("memory-event record invalid: {0}")]
    MemEvent(String),

    #[error("hypervisor payload invalid: {0}")]
    Hv(String),

    #[error("rate limit exceeded")]
    RateLimited,

    #[error("ingest pipeline overloaded")]
    Overloaded,

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
            TelemetryError::RenderSchema(msg) => (
                StatusCode::BAD_REQUEST,
                json!({ "status": "render_schema_mismatch", "reason": msg }),
            ),
            TelemetryError::InputSchema(msg) => (
                StatusCode::BAD_REQUEST,
                json!({ "status": "input_schema_mismatch", "reason": msg }),
            ),
            TelemetryError::DeviceTrustSchema(msg) => (
                StatusCode::BAD_REQUEST,
                json!({ "status": "device_trust_schema_mismatch", "reason": msg }),
            ),
            TelemetryError::PointerModel(msg) => (
                StatusCode::BAD_REQUEST,
                json!({ "status": "pointer_model_schema_mismatch", "reason": msg }),
            ),
            TelemetryError::Timing(msg) => (
                StatusCode::BAD_REQUEST,
                json!({ "status": "timing_schema_mismatch", "reason": msg }),
            ),
            TelemetryError::AntiAnalysis(msg) => (
                StatusCode::BAD_REQUEST,
                json!({ "status": "anti_analysis_invalid", "reason": msg }),
            ),
            TelemetryError::MemEvent(msg) => (
                StatusCode::BAD_REQUEST,
                json!({ "status": "mem_event_invalid", "reason": msg }),
            ),
            TelemetryError::Hv(msg) => (
                StatusCode::BAD_REQUEST,
                json!({ "status": "hv_invalid", "reason": msg }),
            ),
            TelemetryError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                json!({ "status": "rate_limited" }),
            ),
            TelemetryError::Overloaded => (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({ "status": "overloaded" }),
            ),
            TelemetryError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "status": "error" }),
            ),
        };
        (status, Json(body)).into_response()
    }
}
