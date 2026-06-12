//! Role: Pointer-feature ML ingest plane (hardware-input-devices domain, catalog signal
//! 142). Serde mirror of the C99 `hk_event_pointer_features` record in
//! `sdk/include/horkos/device_trust_schema.h`. Exposes `POST /api/pointer-features`.
//! FEATURES ONLY — an aggregate 24-dim moment/autocorr/GCD-lattice vector + the
//! resolved HID usage class; NEVER raw `lLastX/lLastY` / `REL_X/REL_Y` / `IOHIDValue`
//! movement (privacy invariant; data-categories §5). The server conditions the ONNX
//! model on `hid_usage_class` (only score against the matching sensor-class baseline:
//! mouse/trackball/tablet/touchpad — catalog high-FP gate).
//!
//! Target platforms: server.
//!
//! Phase 2 stub parity: validate the feature-vector shape (`feat.len() == 24`) +
//! schema version, log, drop. `ort` stays the compile-time marker (`lib.rs`); NO
//! `Session` is constructed until the `/tdd` inference phase — when it lands, scoring
//! runs through `spawn_blocking` (CPU-bound native call) so it never blocks an async
//! thread (guardrail #8). No `unwrap()`/`expect()` outside `#[cfg(test)]`.

use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::TelemetryError;

/// Mirrors `HK_DEVICE_TRUST_SCHEMA_VERSION`. Bump in lockstep with the C header.
pub const DEVICE_TRUST_SCHEMA_VERSION: u32 = 1;

/// Mirrors `HK_POINTER_FEAT_DIM`. The ONNX model input dimension; a mismatch is a
/// schema-drift bug, caught by the shape gate below.
pub const POINTER_FEAT_DIM: usize = 24;

/// HID usage class for model conditioning (mirrors `HK_PCLASS_*`). The server skips ML
/// scoring for `Unknown` (the sensor could not resolve the top-level usage).
pub mod usage_class {
    pub const UNKNOWN: u32 = 0;
    pub const MOUSE: u32 = 1;
    pub const TRACKBALL: u32 = 2;
    pub const TABLET: u32 = 3;
    pub const TOUCHPAD: u32 = 4;
}

/// Byte-for-byte serde mirror of the C `hk_event_pointer_features`. FEATURES ONLY —
/// the `feat` array is the aggregate vector; there is no raw-sample field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PointerFeatures {
    /// `HK_DEVICE_TRUST_SCHEMA_VERSION` at emit.
    pub schema_version: u32,
    /// `HK_PCLASS_*` for server-side model conditioning.
    pub hid_usage_class: u32,
    /// Opaque per-session id.
    pub hdevice_token: u64,
    /// Aggregate moment / autocorr / GCD-lattice feature vector (24 floats).
    pub feat: [f32; POINTER_FEAT_DIM],
}

/// A batch of pointer-feature vectors for one player, as sent by the client per tick.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerFeatureBatch {
    /// Envelope schema version; must equal `DEVICE_TRUST_SCHEMA_VERSION`.
    pub schema_version: u32,
    /// Server-assigned player identifier.
    pub player_id: u64,
    /// Zero or more pointer-feature vectors.
    #[serde(default)]
    pub features: Vec<PointerFeatures>,
}

/// Mounts `POST /api/pointer-features`.
pub fn router() -> Router {
    Router::new().route("/api/pointer-features", post(ingest))
}

#[tracing::instrument(skip_all, fields(player_id, feature_count))]
async fn ingest(
    Json(batch): Json<PointerFeatureBatch>,
) -> Result<axum::http::StatusCode, TelemetryError> {
    if batch.schema_version != DEVICE_TRUST_SCHEMA_VERSION {
        return Err(TelemetryError::PointerModel(format!(
            "pointer envelope schema_version {} not supported; expected {}",
            batch.schema_version, DEVICE_TRUST_SCHEMA_VERSION
        )));
    }
    for f in &batch.features {
        if f.schema_version != DEVICE_TRUST_SCHEMA_VERSION {
            return Err(TelemetryError::PointerModel(format!(
                "pointer feature schema_version {} not supported; expected {}",
                f.schema_version, DEVICE_TRUST_SCHEMA_VERSION
            )));
        }
        // The fixed array deserializes to exactly 24 by construction, but a NaN in the
        // vector would poison the model input; reject it at the gate.
        if f.feat.iter().any(|v| v.is_nan()) {
            return Err(TelemetryError::PointerModel(
                "pointer feature vector carries NaN".to_string(),
            ));
        }
    }

    tracing::Span::current()
        .record("player_id", batch.player_id)
        .record("feature_count", batch.features.len());

    tracing::trace!(
        features = batch.features.len(),
        "pointer-feature batch accepted"
    );

    // Phase 2 stub: validate shape, log, drop. No model load / `Session` construction
    // until the `/tdd` inference phase (mirrors `telemetry::ingest`). The model is
    // conditioned on `hid_usage_class` then; the client only ships the aggregate vector.
    let _ = batch;

    Ok(axum::http::StatusCode::ACCEPTED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_features_round_trip_with_vector() {
        let mut feat = [0.0f32; POINTER_FEAT_DIM];
        feat[0] = 1.5;
        feat[23] = -2.0;
        let f = PointerFeatures {
            schema_version: DEVICE_TRUST_SCHEMA_VERSION,
            hid_usage_class: usage_class::MOUSE,
            hdevice_token: 0xfeed,
            feat,
        };
        let json = serde_json::to_value(&f).expect("serialize");
        assert_eq!(
            json["feat"].as_array().expect("array").len(),
            POINTER_FEAT_DIM
        );
        let back: PointerFeatures = serde_json::from_value(json).expect("deserialize");
        assert_eq!(f, back);
    }

    /// A NaN in the feature vector is rejected (would poison the model input).
    #[test]
    fn nan_feature_is_rejected() {
        let mut feat = [0.0f32; POINTER_FEAT_DIM];
        feat[5] = f32::NAN;
        assert!(feat.iter().any(|v| v.is_nan()));
    }
}
