//! src/routes/healthz.rs
//!
//! Role: Liveness route. `GET /healthz` returns `{"status":"ok"}`.
//! Future routes mount alongside this one in `routes/mod.rs`.
//!
//! Target platforms: server.

use axum::{routing::get, Json, Router};
use serde_json::{json, Value};

pub fn router() -> Router {
    Router::new().route("/healthz", get(healthz))
}

async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}
