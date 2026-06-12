//! Role: Input-cadence feature ingest plane (hardware-input-devices domain, catalog
//! signals 139 poll-interval-ceiling + 144 device arrival/lifetime). Serde mirror of
//! the C99 `hk_pointer_cadence_features` record in
//! `sdk/include/horkos/device_trust_schema.h`. Exposes `POST /api/input-cadence`.
//! FEATURES ONLY — there is deliberately no verdict field (catalog mandate: never a
//! client-side ban on cadence). The server thresholds `ceiling_violation_ratio`
//! (> 1.0 = physically impossible for a compliant endpoint) and weighs the low-weight
//! 144 lifetime/correlation features.
//!
//! Shared ownership: this plane is co-owned with `win-input-automation` (the poll-rate
//! feature, signal 62, lands in `input_prov.rs`'s timing block; this plane owns the
//! descriptor-ceiling field 139 + the arrival/lifetime fields 144). The two domains
//! agree on ONE `input_cadence.rs` record shape — `hk_pointer_cadence_features`.
//!
//! Target platforms: server.
//!
//! Phase 2 stub parity: validate the schema version, record a span, drop on the floor.
//! No `unwrap()`/`expect()` outside `#[cfg(test)]` (guardrail #8); errors flow through
//! `TelemetryError`.

use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::TelemetryError;

/// Mirrors `HK_DEVICE_TRUST_SCHEMA_VERSION`. Bump in lockstep with the C header.
pub const DEVICE_TRUST_SCHEMA_VERSION: u32 = 1;

/// Byte-for-byte serde mirror of the C `hk_pointer_cadence_features`. FEATURES ONLY —
/// no verdict. `reserved0`/`reserved1` keep the float block 8-aligned and the
/// documented 48-byte size stable; they must be zero.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CadenceFeatures {
    /// `HK_DEVICE_TRUST_SCHEMA_VERSION` at emit.
    pub schema_version: u32,
    /// Must be zero (alignment pad mirror).
    pub reserved0: u32,
    /// Opaque per-session id (same space as input_prov `hdevice_token`).
    pub hdevice_token: u64,
    /// bInterval-derived permitted period (ms).
    pub declared_interval_ms: f32,
    /// Sustained observed report rate (Hz).
    pub observed_rate_hz: f32,
    /// observed_rate / descriptor-permitted ceiling. Server thresholds; > 1.0 is the
    /// physically-impossible region.
    pub ceiling_violation_ratio: f32,
    /// Device arrival -> now (144).
    pub device_lifetime_s: f32,
    /// corr(new-source activity, gameplay bursts) (144); low-weight feature.
    pub activity_burst_corr: f32,
    /// `HK_CAD_*` bitmask.
    pub flags: u32,
    /// Must be zero.
    pub reserved1: u32,
}

/// A batch of cadence features for one player, as sent by the client per tick.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CadenceBatch {
    /// Envelope schema version; must equal `DEVICE_TRUST_SCHEMA_VERSION`.
    pub schema_version: u32,
    /// Server-assigned player identifier.
    pub player_id: u64,
    /// Zero or more cadence-feature blocks.
    #[serde(default)]
    pub features: Vec<CadenceFeatures>,
}

/// Mounts `POST /api/input-cadence`.
pub fn router() -> Router {
    Router::new().route("/api/input-cadence", post(ingest))
}

#[tracing::instrument(skip_all, fields(player_id, feature_count))]
async fn ingest(Json(batch): Json<CadenceBatch>) -> Result<axum::http::StatusCode, TelemetryError> {
    if batch.schema_version != DEVICE_TRUST_SCHEMA_VERSION {
        return Err(TelemetryError::DeviceTrustSchema(format!(
            "cadence envelope schema_version {} not supported; expected {}",
            batch.schema_version, DEVICE_TRUST_SCHEMA_VERSION
        )));
    }
    for f in &batch.features {
        if f.schema_version != DEVICE_TRUST_SCHEMA_VERSION {
            return Err(TelemetryError::DeviceTrustSchema(format!(
                "cadence feature schema_version {} not supported; expected {}",
                f.schema_version, DEVICE_TRUST_SCHEMA_VERSION
            )));
        }
        // A NaN ratio would poison any server-side threshold; reject it here so a
        // malformed client cannot smuggle one past the gate.
        if f.ceiling_violation_ratio.is_nan() || f.observed_rate_hz.is_nan() {
            return Err(TelemetryError::DeviceTrustSchema(
                "cadence feature carries NaN rate/ratio".to_string(),
            ));
        }
    }

    tracing::Span::current()
        .record("player_id", batch.player_id)
        .record("feature_count", batch.features.len());

    tracing::trace!(
        features = batch.features.len(),
        "input-cadence feature batch accepted"
    );

    // Phase 2 stub: log only, no thresholding (mirrors `telemetry::ingest`). FEATURES
    // ONLY — the server thresholds the ceiling ratio + weighs the 144 features later.
    let _ = batch;

    Ok(axum::http::StatusCode::ACCEPTED)
}
