//! src/lib.rs
//!
//! Role: API library — exposes the composed Router for both the binary
//! entrypoint and integration tests. Library code uses `thiserror` only
//! (per CLAUDE.md guardrail #8).
//!
//! Target platforms: server.

pub mod error;
pub mod routes;

use axum::{extract::DefaultBodyLimit, Router};

/// Maximum accepted request body for all routes on this server.
const MAX_BODY_BYTES: usize = 256 * 1024;

/// Build the fully composed application router.
///
/// Composes:
///   - `/healthz`           — liveness
///   - `/api/account/...`   — GDPR-17 deletion stub (503)
///   - `/api/telemetry`     — telemetry ingest (telemetry crate)
///   - `/api/rules/...`     — ban engine (ban-engine crate)
///   - `/api/license/...`   — licence routes (license-server crate)
pub fn build_router() -> Router {
    Router::new()
        .merge(routes::healthz::router())
        .merge(routes::account::router())
        .merge(telemetry::router())
        .merge(ban_engine::router())
        .merge(license_server::router())
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}
