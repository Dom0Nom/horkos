//! src/lib.rs
//!
//! Role: Telemetry crate. Exposes `router()` mounting `POST /api/telemetry`.
//! Phase 2 validates the payload schema and drops it on the floor (logged).
//! The real ingest path lands in a /tdd phase. The `ort` dependency is
//! wired here to confirm it builds on the target host; no model is loaded
//! in Phase 2.
//!
//! Target platforms: server.

pub mod error;
pub mod schema;

use axum::{routing::post, Json, Router};
use error::TelemetryError;
use schema::{TickPayload, SCHEMA_VERSION};

pub fn router() -> Router {
    Router::new().route("/api/telemetry", post(ingest))
}

#[tracing::instrument(skip_all, fields(player_id, tick))]
async fn ingest(
    Json(payload): Json<TickPayload>,
) -> Result<axum::http::StatusCode, TelemetryError> {
    if payload.schema_version != SCHEMA_VERSION {
        return Err(TelemetryError::InvalidPayload(format!(
            "schema_version {} not supported; expected {}",
            payload.schema_version, SCHEMA_VERSION
        )));
    }

    tracing::Span::current()
        .record("player_id", payload.player_id)
        .record("tick", payload.tick);

    tracing::trace!(
        aim_dx = payload.aim_delta_x,
        aim_dy = payload.aim_delta_y,
        input = payload.input_state,
        "telemetry tick accepted"
    );

    // Phase 2 stub: log only, no storage, no ML inference yet.
    let _ = payload;

    Ok(axum::http::StatusCode::ACCEPTED)
}

/// Sanity check that ort is linked. Called at startup-style sites in tests
/// to fail fast if the binary cannot find the ONNX Runtime backing library.
/// Not part of the steady-state code path.
pub fn ort_linked_marker() -> &'static str {
    // ort 2.x exposes its environment via `ort::Environment`. We don't
    // construct one here (that would attempt to load the library); we only
    // reference an exported type so the linker keeps the dependency.
    let _phantom = std::marker::PhantomData::<ort::session::Session>;
    "ort: linked"
}
