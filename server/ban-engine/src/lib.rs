//! src/lib.rs
//!
//! Role: Ban-engine crate. Exposes `router()` mounting `GET /api/rules/current`,
//! `router_with_decisions()` adding `GET /api/decisions/{player_id}`, and the
//! analysis pipeline (`pipeline::spawn`) that fuses analyzer suspicions into
//! latched, persisted verdicts. Verification details live in `bundle.rs`. See
//! module docs there for fail-closed invariants and the dev-only feature gate.
//!
//! Target platforms: server.

pub mod aim_kinematics;
pub mod arrival_cadence;
pub mod bundle;
pub mod error;
pub mod fusion;
pub mod loader_inject;
pub mod pipeline;
pub mod scoring;
pub mod store;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use bundle::{placeholder_metadata, BundleMetadata};
use pipeline::LatestDecision;

pub fn router() -> Router {
    Router::new().route("/api/rules/current", get(current_rules))
}

/// `router()` plus the decision read surface backed by the live pipeline's
/// shared latest-decision map.
pub fn router_with_decisions(decisions: Arc<RwLock<HashMap<u64, LatestDecision>>>) -> Router {
    Router::new()
        .route("/api/decisions/{player_id}", get(latest_decision))
        .with_state(decisions)
        .merge(router())
}

#[tracing::instrument(skip_all, fields(player_id))]
async fn latest_decision(
    State(decisions): State<Arc<RwLock<HashMap<u64, LatestDecision>>>>,
    Path(player_id): Path<u64>,
) -> Result<Json<LatestDecision>, StatusCode> {
    tracing::Span::current().record("player_id", player_id);
    let map = decisions.read().map_err(|_| {
        // Poisoned = a writer panicked mid-update; serving a maybe-torn map
        // is worse than degrading the read surface.
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    match map.get(&player_id) {
        Some(d) => Ok(Json(*d)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[tracing::instrument]
async fn current_rules() -> Json<BundleMetadata> {
    // Phase 2 returns the placeholder metadata so clients can compile against
    // the URL surface. The fail-closed verifier defends against accepting a
    // bundle from an untrusted source.
    Json(placeholder_metadata())
}
