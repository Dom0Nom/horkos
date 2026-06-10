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

    // Live authoritative-snapshot source: attach the shm ring named by
    // HORKOS_SNAPSHOT_RING and run a dedicated reader thread that routes each
    // frame to its player's shard. Absent/unattachable = no live snapshots
    // (the gamestate analyzers then only see fixture/test traffic and
    // unpaired sessions surface as the Review-tier pairing anomaly).
    spawn_snapshot_reader(&handle);

    let router = Router::new()
        .merge(routes::healthz::router_with_pipeline(handle.alive.clone()))
        .merge(routes::account::router())
        .merge(telemetry::router_with_sink(sink))
        .merge(ban_engine::router_with_decisions(handle.decisions.clone()))
        .merge(license_server::router())
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES));
    Ok((router, handle))
}

/// Attach the live snapshot ring (if `HORKOS_SNAPSHOT_RING` is set) and spawn a
/// dedicated reader thread that forwards frames into the pipeline's sharded
/// snapshot channels. A blocking `try_send` on a full shard drops that frame
/// (counted by the pipeline); snapshots are high-rate, and a dropped one just
/// means that tick goes unpaired — never a crash, never silent unbounded growth.
fn spawn_snapshot_reader(handle: &PipelineHandle) {
    let Some(name) = std::env::var_os("HORKOS_SNAPSHOT_RING") else {
        return;
    };
    let name = name.to_string_lossy().into_owned();
    let senders = handle.snapshot_senders();
    if senders.is_empty() {
        return;
    }
    use telemetry::snapshot::ipc::SnapshotRingAttach as _;
    let ring = match telemetry::snapshot::backends::DefaultRingAttach::attach(&name) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(%name, error = %e, "snapshot ring attach failed; no live snapshots");
            return;
        }
    };
    tracing::info!(%name, "snapshot ring attached; starting reader thread");
    std::thread::Builder::new()
        .name("horkos-snapshot-reader".into())
        .spawn(move || {
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let n = senders.len() as u64;
            telemetry::snapshot::ipc::run_reader(
                ring,
                move |snap| {
                    let idx = (snap.local_player_id % n) as usize;
                    // try_send: drop on a full shard (counted downstream), never
                    // block the reader on one slow shard.
                    match senders[idx].try_send(snap) {
                        Ok(()) => true,
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => true,
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
                    }
                },
                stop,
                std::time::Duration::from_millis(1),
            );
        })
        .ok();
}
