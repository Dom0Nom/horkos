//! src/routes/healthz.rs
//!
//! Role: Liveness route. `GET /healthz` returns `{"status":"ok"}`, or 503
//! `{"status":"degraded"}` once the analysis pipeline has died — a server
//! that ingests telemetry it can no longer analyze must not report healthy
//! (fail-closed posture). Future routes mount alongside this one in
//! `routes/mod.rs`.
//!
//! Target platforms: server.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use serde_json::{json, Value};

pub fn router() -> Router {
    Router::new().route("/healthz", get(healthz))
}

/// Liveness gated on the pipeline's alive flag (`ban_engine::pipeline`).
pub fn router_with_pipeline(alive: Arc<AtomicBool>) -> Router {
    Router::new()
        .route("/healthz", get(healthz_with_pipeline))
        .with_state(alive)
}

async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn healthz_with_pipeline(State(alive): State<Arc<AtomicBool>>) -> (StatusCode, Json<Value>) {
    if alive.load(Ordering::Acquire) {
        (StatusCode::OK, Json(json!({ "status": "ok" })))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "degraded", "pipeline": "dead" })),
        )
    }
}
