//! src/lib.rs
//!
//! Role: API library — exposes the composed Router for both the binary
//! entrypoint and integration tests. `build_app` is the live wiring (spawns
//! the analysis pipeline and connects ingest to it); `build_router` is the
//! pipelineless route surface kept for tests/tools. Library code uses
//! `thiserror` only (per CLAUDE.md guardrail #8).
//!
//! Target platforms: server.

pub mod error;
pub mod routes;

use std::path::PathBuf;
use std::sync::Arc;

use axum::{extract::DefaultBodyLimit, Router};
use ban_engine::pipeline::{self, PipelineConfig, PipelineHandle};
use ban_engine::store::DecisionStore;
use error::ApiError;
use telemetry::sink::TickSink;

/// Maximum accepted request body for all routes on this server.
const MAX_BODY_BYTES: usize = 256 * 1024;

/// Build the pipelineless route surface (validate-then-drop ingest, no
/// decision map). Kept for tests and tooling that only need the URL surface.
pub fn build_router() -> Router {
    Router::new()
        .merge(routes::healthz::router())
        .merge(routes::account::router())
        .merge(telemetry::router())
        .merge(ban_engine::router())
        .merge(license_server::router())
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// Build the live application: spawn the analysis pipeline and wire
/// ingest -> analyzers -> fusion -> persisted decisions.
///
/// Composes:
///   - `/healthz`                    — liveness, 503 once the pipeline dies
///   - `/api/account/...`            — GDPR-17 deletion stub (503)
///   - `/api/telemetry`              — ingest, forwarded into the pipeline
///   - `/api/rules/...`              — signed-rule surface (ban-engine crate)
///   - `/api/decisions/{player_id}`  — latest latched verdict
///   - `/api/license/...`            — licence routes (license-server crate)
///
/// Decision persistence: JSONL at `$HORKOS_DECISION_LOG` when set, else
/// in-memory (PoC default). Must be called from within a tokio runtime.
pub fn build_app() -> Result<(Router, PipelineHandle), ApiError> {
    let store = match std::env::var_os("HORKOS_DECISION_LOG") {
        Some(path) => DecisionStore::jsonl(&PathBuf::from(path))
            .map_err(|e| ApiError::DecisionLog(e.to_string()))?,
        None => DecisionStore::memory(),
    };
    let handle = pipeline::spawn(PipelineConfig::default(), Arc::new(store));
    let sink = Arc::new(TickSink::new(handle.tick_senders()));

    let router = Router::new()
        .merge(routes::healthz::router_with_pipeline(handle.alive.clone()))
        .merge(routes::account::router())
        .merge(telemetry::router_with_sink(sink))
        .merge(ban_engine::router_with_decisions(handle.decisions.clone()))
        .merge(license_server::router())
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES));
    Ok((router, handle))
}
