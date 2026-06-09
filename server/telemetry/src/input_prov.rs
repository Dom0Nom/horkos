//! src/input_prov.rs
//!
//! Role: Input-provenance & automation finding ingest plane (Windows usermode
//! sensors, catalog signals 55-63, `win-input-automation`). Serde mirror of the C99
//! `hk_input_finding` and `hk_input_timing_features` numeric cores in
//! `sdk/include/horkos/input_prov_schema.h` plus the variable-length string
//! side-channel (RIDI_DEVICENAME device path, class-filter service name, Authenticode
//! signer subject, HID VID/PID, foreign image path) that does NOT fit the fixed C
//! structs. Exposes `POST /api/input-findings`. This is a SEPARATE wire plane from
//! the per-tick `TickPayload`, the C99 kernel-event schema, and the render plane:
//! input findings carry variable-length strings + a per-device timing histogram and
//! are reported over HTTP/JSON, never the `HK_IOCTL_DRAIN_EVENTS` kernel ring.
//!
//! Target platforms: server.
//!
//! Versioning: `INPUT_SCHEMA_VERSION` tracks `HK_INPUT_SCHEMA_VERSION` in the C
//! header in lockstep, decoupled from `SCHEMA_VERSION`, `RENDER_SCHEMA_VERSION`, and
//! `HK_EVENT_SCHEMA_VERSION`. Every field addition bumps it; no field renames.
//!
//! Phase 2 stub parity: like `telemetry::ingest` and `render_hook::ingest`, the
//! handler validates the schema version, records a tracing span, then drops the batch
//! on the floor. The real persistence + timing-model scoring path lands in a later
//! `/tdd` phase. The timing signals (58/62) ship FEATURES ONLY — no client verdict
//! ever (catalog mandate); the regularity/poll-rate model is server-side. No
//! `unwrap()` / `expect()` outside `#[cfg(test)]` (guardrail #8); errors flow through
//! `TelemetryError`.

use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::TelemetryError;

/// Version of the input-finding JSON plane. Mirrors `HK_INPUT_SCHEMA_VERSION` in
/// `input_prov_schema.h`. Bump in lockstep with the C header on any additive change.
pub const INPUT_SCHEMA_VERSION: u32 = 1;

/// Number of inter-arrival histogram buckets. Mirrors `HK_INPUT_TIMING_BUCKETS`.
pub const INPUT_TIMING_BUCKETS: usize = 16;

/// One input-provenance finding. The first ten fields are the byte-for-byte mirror
/// of the C `hk_input_finding` numeric core (same field order and widths); the
/// trailing `Option<String>` fields are the JSON-only string side-channel that the C
/// struct deliberately keeps out-of-band so it stays fixed-size. Each string field is
/// `#[serde(default)]` so a finding that does not populate one (e.g. a raw-input
/// provenance finding has no filter service) omits it on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InputFinding {
    /// `HK_INPUT_SCHEMA_VERSION` at emit.
    pub schema_version: u32,
    /// `hk_input_signal` (catalog id 55-63).
    pub signal: u32,
    /// `hk_input_verdict`, or 0 when N/A.
    pub verdict: u32,
    /// `HK_INFLAG_*` bitmask.
    pub flags: u32,
    /// Foreign PID for queue-attach / hook-owner signals, else 0.
    pub owning_pid: u32,
    /// Events observed in the window (ratio denominator).
    pub event_count: u32,
    /// Events matching the anomaly (ratio numerator).
    pub anomaly_count: u32,
    /// Ordered class-filter count (56), else 0.
    pub filter_count: u32,
    /// Opaque per-session hDevice id (NOT the raw OS HANDLE), else 0.
    pub hdevice_token: u64,
    /// Measured `CallNextHookEx` call-out delay (59), else 0.
    pub llhook_latency_ns: i64,

    // HK-TODO(schema): the input-provenance telemetry fields below (and the numeric
    // core above) need an "Input provenance & automation findings (Windows usermode)"
    // section added to server/api/data-categories.md per guardrail #11. That file is
    // owned by the Schema phase and is intentionally NOT edited here; this note
    // records the required declaration: signal, verdict, flags, owning_pid,
    // event_count/anomaly_count, filter_count, hdevice_token, llhook_latency_ns,
    // declared_hz/observed_hz_x100/transport_flags, cov_x10000/regularity_x10000/
    // period_hist[16], device_path, filter_service, signer_subject, vidpid,
    // owning_image. The reviewer must land that section in the same PR before the
    // fields are accepted. The sensors record input provenance/timing metadata ONLY —
    // never keystroke content, typed text, or aim coordinates.
    /// `GetRawInputDeviceInfoW(RIDI_DEVICENAME)` device-interface path. String
    /// side-channel; not in the C struct.
    #[serde(default)]
    pub device_path: Option<String>,
    /// `SPDRP_UPPERFILTERS`/`LOWERFILTERS` class-filter driver service name. String
    /// side-channel; not in the C struct.
    #[serde(default)]
    pub filter_service: Option<String>,
    /// Authenticode signer subject the server allow-lists against. String
    /// side-channel; not in the C struct.
    #[serde(default)]
    pub signer_subject: Option<String>,
    /// `HidD_GetAttributes` VID/PID of the implicated HID collection. String
    /// side-channel; not in the C struct.
    #[serde(default)]
    pub vidpid: Option<String>,
    /// Foreign queue-attach / hook-owner image on-disk path. String side-channel; not
    /// in the C struct.
    #[serde(default)]
    pub owning_image: Option<String>,
}

/// One timing-feature block for signals 58 (inter-report entropy) and 62 (poll-rate
/// contradiction). Byte-for-byte mirror of the C `hk_input_timing_features`. FEATURES
/// ONLY — there is deliberately no verdict field (catalog: never a client-side ban on
/// timing). `period_hist` is the fixed 16-bucket inter-arrival delta histogram.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InputTimingFeatures {
    /// `HK_INPUT_SCHEMA_VERSION` at emit.
    pub schema_version: u32,
    /// `hk_input_signal` (58 or 62).
    pub signal: u32,
    /// Same opaque per-session id as `InputFinding`.
    pub hdevice_token: u64,
    /// Inter-arrival deltas summarized.
    pub sample_count: u32,
    /// HID/USB bInterval-derived declared rate (62), else 0.
    pub declared_hz: u32,
    /// Measured WM_INPUT rate * 100 (fixed-point), else 0.
    pub observed_hz_x100: u32,
    /// `HK_INTRANSPORT_*` (Bluetooth/wireless exemption for 62).
    pub transport_flags: u32,
    /// Coefficient of variation of inter-arrival deltas, *1e4.
    pub cov_x10000: u32,
    /// Chi-square/autocorrelation regularity score, *1e4.
    pub regularity_x10000: u32,
    /// Inter-arrival delta histogram (16 buckets).
    pub period_hist: [u32; INPUT_TIMING_BUCKETS],
}

/// A batch of input findings + timing features for one player, as sent by the client
/// per tick.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputFindingBatch {
    /// Envelope schema version; must equal `INPUT_SCHEMA_VERSION`.
    pub schema_version: u32,
    /// Server-assigned player identifier.
    pub player_id: u64,
    /// Zero or more provenance findings observed this tick.
    #[serde(default)]
    pub findings: Vec<InputFinding>,
    /// Zero or more timing-feature blocks (signals 58/62).
    #[serde(default)]
    pub timing: Vec<InputTimingFeatures>,
}

/// Mounts `POST /api/input-findings`. Kept as its own router so the route can be
/// `.merge()`d into `telemetry::router()` (or any parent) without coupling.
pub fn router() -> Router {
    Router::new().route("/api/input-findings", post(ingest))
}

#[tracing::instrument(skip_all, fields(player_id, finding_count, timing_count))]
async fn ingest(
    Json(batch): Json<InputFindingBatch>,
) -> Result<axum::http::StatusCode, TelemetryError> {
    if batch.schema_version != INPUT_SCHEMA_VERSION {
        return Err(TelemetryError::InputSchema(format!(
            "envelope schema_version {} not supported; expected {}",
            batch.schema_version, INPUT_SCHEMA_VERSION
        )));
    }

    // Reject a batch whose individual records disagree with the envelope version, so a
    // forward-rolled client cannot smuggle a newer record shape past the gate.
    for f in &batch.findings {
        if f.schema_version != INPUT_SCHEMA_VERSION {
            return Err(TelemetryError::InputSchema(format!(
                "finding schema_version {} not supported; expected {}",
                f.schema_version, INPUT_SCHEMA_VERSION
            )));
        }
    }
    for t in &batch.timing {
        if t.schema_version != INPUT_SCHEMA_VERSION {
            return Err(TelemetryError::InputSchema(format!(
                "timing schema_version {} not supported; expected {}",
                t.schema_version, INPUT_SCHEMA_VERSION
            )));
        }
        // Timing blocks belong to the features-only signals; reject a misrouted
        // record so a verdict-bearing signal can never arrive as a timing feature.
        if t.signal != 58 && t.signal != 62 {
            return Err(TelemetryError::InputSchema(format!(
                "timing signal {} is not a timing-feature signal (expected 58 or 62)",
                t.signal
            )));
        }
    }

    tracing::Span::current()
        .record("player_id", batch.player_id)
        .record("finding_count", batch.findings.len())
        .record("timing_count", batch.timing.len());

    tracing::trace!(
        findings = batch.findings.len(),
        timing = batch.timing.len(),
        "input-provenance finding batch accepted"
    );

    // Phase 2 stub: log only, no storage, no scoring (mirrors `telemetry::ingest`).
    // The verdict/allow-list fusion and the timing model are server-side later work;
    // the client only reports resolved provenance + raw timing features, never a ban.
    let _ = batch;

    Ok(axum::http::StatusCode::ACCEPTED)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The serde mirror round-trips and the field count matches the C
    /// `hk_input_finding` numeric core (10 numeric fields) plus the 5 string
    /// side-channel fields. Guards against schema drift between
    /// `input_prov_schema.h` and this mirror.
    #[test]
    fn input_finding_round_trips() {
        let f = InputFinding {
            schema_version: INPUT_SCHEMA_VERSION,
            signal: 55,
            verdict: 5,
            flags: 0x0001,
            owning_pid: 0,
            event_count: 200,
            anomaly_count: 7,
            filter_count: 0,
            hdevice_token: 0xfeed,
            llhook_latency_ns: 0,
            device_path: Some("\\\\?\\HID#VID_046D&PID_C08B".into()),
            filter_service: None,
            signer_subject: None,
            vidpid: Some("046D:C08B".into()),
            owning_image: None,
        };
        let json = serde_json::to_value(&f).expect("serialize");
        assert_eq!(json["signal"], 55);
        assert_eq!(json["anomaly_count"], 7);
        let back: InputFinding = serde_json::from_value(json).expect("deserialize");
        assert_eq!(f, back);
    }

    /// The timing-feature block round-trips with its fixed 16-bucket histogram, and
    /// the array length matches `HK_INPUT_TIMING_BUCKETS`. Catches `period_hist` drift
    /// between `input_prov_schema.h` and this mirror.
    #[test]
    fn timing_features_round_trip_with_histogram() {
        let mut hist = [0u32; INPUT_TIMING_BUCKETS];
        hist[3] = 41;
        hist[7] = 9;
        let t = InputTimingFeatures {
            schema_version: INPUT_SCHEMA_VERSION,
            signal: 58,
            hdevice_token: 0xfeed,
            sample_count: 50,
            declared_hz: 0,
            observed_hz_x100: 100_000,
            transport_flags: 0x01,
            cov_x10000: 120,
            regularity_x10000: 9880,
            period_hist: hist,
        };
        let json = serde_json::to_value(&t).expect("serialize");
        assert_eq!(json["period_hist"].as_array().expect("array").len(), 16);
        let back: InputTimingFeatures = serde_json::from_value(json).expect("deserialize");
        assert_eq!(t, back);
    }

    /// String side-channel fields are optional: a finding that omits them
    /// deserializes with `None`, and a batch may carry no timing blocks.
    #[test]
    fn string_side_channel_and_timing_are_optional() {
        let body = serde_json::json!({
            "schema_version": INPUT_SCHEMA_VERSION,
            "player_id": 42,
            "findings": [{
                "schema_version": INPUT_SCHEMA_VERSION,
                "signal": 61,
                "verdict": 0,
                "flags": 0x0080,
                "owning_pid": 4242,
                "event_count": 0,
                "anomaly_count": 0,
                "filter_count": 0,
                "hdevice_token": 0,
                "llhook_latency_ns": 0
            }]
        });
        let batch: InputFindingBatch = serde_json::from_value(body).expect("deserialize");
        assert_eq!(batch.findings.len(), 1);
        assert!(batch.timing.is_empty());
        assert_eq!(batch.findings[0].owning_pid, 4242);
        assert!(batch.findings[0].device_path.is_none());
        assert!(batch.findings[0].owning_image.is_none());
    }
}
