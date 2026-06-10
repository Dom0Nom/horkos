//! src/lib.rs
//!
//! Role: Telemetry crate. Exposes `router()` mounting `POST /api/telemetry`.
//! Phase 2 validates the payload schema and drops it on the floor (logged).
//! The real ingest path lands in a /tdd phase. The `ort` dependency is
//! wired here to confirm it builds on the target host; no model is loaded
//! in Phase 2.
//!
//! Target platforms: server.

pub mod anti_analysis;
pub mod device_trust;
pub mod dma_forensics;
pub mod driver_integrity;
pub mod error;
pub mod hv;
pub mod input_cadence;
pub mod input_prov;
pub mod kernel_events;
pub mod launch_trust;
pub mod linux_proton;
pub mod loader_inject;
pub mod macos_codesign;
pub mod macos_inject;
pub mod mem_events;
pub mod pointer_model;
pub mod render_hook;
pub mod schema;
pub mod self_events;
pub mod thread_inject;
pub mod timing;
pub mod vm_access;

// behavioral-gamestate domain (catalog signals 172-180): server-side game-state
// knowledge analyzers replaying the authoritative snapshot stream against client
// telemetry. Compiled under the default-on `gamestate-analyzers` feature; the live
// shm reader is the separate default-on `gamestate-ipc-shm` feature (off in CI/tests,
// which run the analyzers from file-backed fixtures with no game-server peer).
#[cfg(feature = "gamestate-analyzers")]
pub mod analyzers;
#[cfg(feature = "gamestate-analyzers")]
pub mod geom;
#[cfg(feature = "gamestate-analyzers")]
pub mod snapshot;
#[cfg(feature = "gamestate-analyzers")]
pub mod stats;

use axum::{routing::post, Json, Router};
use error::TelemetryError;
use schema::{TickPayload, SCHEMA_VERSION};

pub fn router() -> Router {
    Router::new()
        .route("/api/telemetry", post(ingest))
        .merge(render_hook::router())
        .merge(input_prov::router())
        .merge(loader_inject::router())
        .merge(device_trust::router())
        .merge(input_cadence::router())
        .merge(pointer_model::router())
        .merge(timing::router())
}

#[tracing::instrument(skip_all, fields(player_id, tick))]
async fn ingest(
    Json(payload): Json<TickPayload>,
) -> Result<axum::http::StatusCode, TelemetryError> {
    // Migration window: accept every contract from v1 through the current
    // SCHEMA_VERSION. Older clients omit later additive blocks (v2 aim-feature,
    // v3 gamestate-binding, v4 network-anomaly), which deserialize to their
    // `#[serde(default)]` zeros, so the server simply gets no signal from those
    // blocks — never a fabricated anomaly. Any version above the current or
    // below the minimum is rejected.
    const MIN_SUPPORTED_SCHEMA_VERSION: u32 = 1;
    if payload.schema_version < MIN_SUPPORTED_SCHEMA_VERSION
        || payload.schema_version > SCHEMA_VERSION
    {
        return Err(TelemetryError::InvalidPayload(format!(
            "schema_version {} not supported; expected {}..={}",
            payload.schema_version, MIN_SUPPORTED_SCHEMA_VERSION, SCHEMA_VERSION
        )));
    }

    // The optional anti-analysis sub-payload (v5) is range-validated when present;
    // an out-of-range tier yields a typed error (never a panic). Absent = no signal.
    if let Some(aa) = &payload.anti_analysis {
        aa.validate()?;
    }

    // The optional hypervisor-state sub-payload (v6) is range-validated when
    // present; an out-of-range VM-identity class yields a typed error (never a
    // panic). Absent = no HV signal.
    if let Some(hv) = &payload.hv {
        hv.validate()?;
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
