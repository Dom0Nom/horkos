//! src/lib.rs
//!
//! Role: Ban-engine crate. Exposes `router()` mounting `GET /api/rules/current`.
//! Verification details live in `bundle.rs`. See module docs there for
//! fail-closed invariants and the dev-only feature gate.
//!
//! Target platforms: server.

pub mod aim_kinematics;
pub mod arrival_cadence;
pub mod bundle;
pub mod error;
pub mod loader_inject;

use axum::{routing::get, Json, Router};
use bundle::{placeholder_metadata, BundleMetadata};

pub fn router() -> Router {
    Router::new().route("/api/rules/current", get(current_rules))
}

#[tracing::instrument]
async fn current_rules() -> Json<BundleMetadata> {
    // Phase 2 returns the placeholder metadata so clients can compile against
    // the URL surface. The fail-closed verifier defends against accepting a
    // bundle from an untrusted source.
    Json(placeholder_metadata())
}
