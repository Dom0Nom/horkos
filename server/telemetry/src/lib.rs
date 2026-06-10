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
pub mod sink;
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

use std::sync::{Arc, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::{extract::DefaultBodyLimit, extract::State, routing::post, Json, Router};
use error::TelemetryError;
use schema::{TickPayload, SCHEMA_VERSION};
use sink::TickSink;

/// Maximum accepted request body for any telemetry route. Telemetry ticks are
/// compact JSON; 256 KiB is generous headroom while capping unbounded uploads.
const MAX_BODY_BYTES: usize = 256 * 1024;

pub fn router() -> Router {
    Router::new()
        .route("/api/telemetry", post(ingest))
        .merge(domain_routers())
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// `router()` plus a live pipeline: validated ticks are stamped and forwarded
/// into the sink's pipeline shards instead of dropped.
pub fn router_with_sink(sink: Arc<TickSink>) -> Router {
    Router::new()
        .route("/api/telemetry", post(ingest_to_pipeline))
        .with_state(sink)
        .merge(domain_routers())
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

fn domain_routers() -> Router {
    Router::new()
        .merge(render_hook::router())
        .merge(input_prov::router())
        .merge(loader_inject::router())
        .merge(device_trust::router())
        .merge(input_cadence::router())
        .merge(pointer_model::router())
        .merge(timing::router())
}

/// Validate one tick against the supported schema window and its optional
/// sub-payloads, then stamp `server_received_ts`. The stamp is UNCONDITIONAL:
/// `server_received_ts` is a server-authored field ("clients send 0"), and a
/// client-supplied nonzero value would otherwise ride `#[serde(default)]`
/// straight into the arrival-cadence clock — a forgeable signal-186 input.
fn validate_and_stamp(payload: &mut TickPayload) -> Result<(), TelemetryError> {
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

    payload.server_received_ts = unix_now_ns();
    Ok(())
}

/// Wall-clock ns since UNIX epoch, anchored once at first use and advanced by
/// the MONOTONIC clock. A raw `SystemTime::now()` per tick steps under NTP;
/// a backward step silently blinds the arrival-cadence detector (it discards
/// non-monotone samples), so the stamp must never go backward.
fn unix_now_ns() -> u64 {
    static ANCHOR: OnceLock<(u64, Instant)> = OnceLock::new();
    let (epoch_ns, anchor) = ANCHOR.get_or_init(|| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        (now, Instant::now())
    });
    epoch_ns.saturating_add(anchor.elapsed().as_nanos() as u64)
}

#[tracing::instrument(skip_all, fields(player_id, tick))]
async fn ingest(
    Json(mut payload): Json<TickPayload>,
) -> Result<axum::http::StatusCode, TelemetryError> {
    validate_and_stamp(&mut payload)?;

    tracing::Span::current()
        .record("player_id", payload.player_id)
        .record("tick", payload.tick);

    tracing::trace!(
        aim_dx = payload.aim_delta_x,
        aim_dy = payload.aim_delta_y,
        input = payload.input_state,
        "telemetry tick accepted"
    );

    // No-sink router: validate-then-drop (kept for tools/tests that mount the
    // route surface without a pipeline). The live binary uses `router_with_sink`.
    let _ = payload;

    Ok(axum::http::StatusCode::ACCEPTED)
}

#[tracing::instrument(skip_all, fields(player_id, tick))]
async fn ingest_to_pipeline(
    State(sink): State<Arc<TickSink>>,
    Json(mut payload): Json<TickPayload>,
) -> Result<axum::http::StatusCode, TelemetryError> {
    validate_and_stamp(&mut payload)?;

    tracing::Span::current()
        .record("player_id", payload.player_id)
        .record("tick", payload.tick);

    sink.send(payload)?;
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
