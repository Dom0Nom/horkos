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

/// Compile-time reference to an `ort` type so the dependency stays wired and any
/// API drift in the pinned `ort` version surfaces as a build error here. This
/// does NOT load or initialize the ONNX Runtime native library — that happens
/// when the real inference path constructs a session in a later phase.
pub fn ort_linked_marker() -> &'static str {
    let _phantom = std::marker::PhantomData::<ort::session::Session>;
    "ort: linked"
}
