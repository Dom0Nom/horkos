//! Role: Render/overlay-hook finding ingest plane (Windows usermode sensors,
//! catalog signals 46-54, `win-usermode-overlay`). Serde mirror of the C99
//! `hk_render_finding` numeric core in `sdk/include/horkos/render_hook_schema.h`
//! plus the variable-length string side-channel (module path, Authenticode signer
//! subject, window class) that does NOT fit the fixed C struct. Exposes
//! `POST /api/render-findings`. This is a SEPARATE wire plane from both the
//! per-tick `TickPayload` and the C99 kernel-event schema: render findings carry
//! variable-length strings and are reported over HTTP/JSON, never the
//! `HK_IOCTL_DRAIN_EVENTS` kernel ring.
//!
//! Target platforms: server.
//!
//! Versioning: `RENDER_SCHEMA_VERSION` tracks `HK_RENDER_SCHEMA_VERSION` in the C
//! header in lockstep, decoupled from `SCHEMA_VERSION` and
//! `HK_EVENT_SCHEMA_VERSION`. Every field addition bumps it; no field renames.
//!
//! Phase 2 stub parity: like `telemetry::ingest`, the handler validates the
//! schema version, records a tracing span, then drops the batch on the floor. The
//! real persistence + scoring path lands in a later `/tdd` phase. No `unwrap()` /
//! `expect()` outside `#[cfg(test)]` (guardrail #8); errors flow through
//! `TelemetryError`.

use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::TelemetryError;

/// Version of the render-finding JSON plane. Mirrors `HK_RENDER_SCHEMA_VERSION`
/// in `render_hook_schema.h`. Bump in lockstep with the C header on any additive
/// change to `RenderFinding`.
pub const RENDER_SCHEMA_VERSION: u32 = 1;

/// One render/overlay finding. The first nine fields are the byte-for-byte mirror
/// of the C `hk_render_finding` numeric core (same field order and widths); the
/// trailing `Option<String>` fields are the JSON-only string side-channel that the
/// C struct deliberately keeps out-of-band so it stays fixed-size. The string
/// fields are `#[serde(default)]` so a finding that does not populate one (e.g. a
/// pure window finding has no signer subject) omits it on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RenderFinding {
    /// `HK_RENDER_SCHEMA_VERSION` at emit.
    pub schema_version: u32,
    /// `hk_render_signal` (catalog id 46-54).
    pub signal: u32,
    /// `hk_provenance_verdict`, or 0 when N/A.
    pub verdict: u32,
    /// `HK_WSTYLE_*` bitmask (signals 49/51), else 0.
    pub style_bits: u32,
    /// Foreign PID for window/footprint signals, else 0.
    pub owning_pid: u32,
    /// vtable slot (46) or export ordinal (47), else 0.
    pub slot_index: u32,
    /// Resolved vtable/prologue target VA (46/47), else 0.
    pub target_addr: u64,
    /// Divergent-region hash (47) / cadence fingerprint, else 0.
    pub region_hash: u64,
    /// Signed frame-stat / cadence drift (48/50/53), else 0.
    pub cadence_drift_ns: i64,

    // HK-TODO(schema): the render/overlay telemetry fields below (and the numeric
    // core above) need a "Render/overlay hook findings (Windows usermode)" section
    // added to server/api/data-categories.md per guardrail #11. That file is owned
    // by the Schema phase and is intentionally NOT edited here; this note records
    // the required declaration: signal, verdict, style_bits, owning_pid,
    // slot_index/target_addr/region_hash, cadence_drift_ns, module_path,
    // signer_subject, window_class. The reviewer must land that section in the same
    // PR before the fields are accepted.
    /// Resolved module / hook-DLL / layer-DLL on-disk path. String side-channel;
    /// not in the C struct. Declared in `server/api/data-categories.md`.
    #[serde(default)]
    pub module_path: Option<String>,
    /// Authenticode signer subject the server allow-lists against. String
    /// side-channel; not in the C struct.
    #[serde(default)]
    pub signer_subject: Option<String>,
    /// Foreign window class name (e.g. `WC_MAGNIFIER`). String side-channel; not
    /// in the C struct.
    #[serde(default)]
    pub window_class: Option<String>,
}

/// A batch of render findings for one player, as sent by the client per tick.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderFindingBatch {
    /// Envelope schema version; must equal `RENDER_SCHEMA_VERSION`.
    pub schema_version: u32,
    /// Server-assigned player identifier.
    pub player_id: u64,
    /// Zero or more findings observed this tick.
    pub findings: Vec<RenderFinding>,
}

/// Mounts `POST /api/render-findings`. Kept as its own router so the route can be
/// `.merge()`d into `telemetry::router()` (or any parent) without coupling.
pub fn router() -> Router {
    Router::new().route("/api/render-findings", post(ingest))
}

#[tracing::instrument(skip_all, fields(player_id, finding_count))]
async fn ingest(
    Json(batch): Json<RenderFindingBatch>,
) -> Result<axum::http::StatusCode, TelemetryError> {
    if batch.schema_version != RENDER_SCHEMA_VERSION {
        return Err(TelemetryError::RenderSchema(format!(
            "envelope schema_version {} not supported; expected {}",
            batch.schema_version, RENDER_SCHEMA_VERSION
        )));
    }

    // Reject a batch whose individual findings disagree with the envelope version,
    // so a forward-rolled client cannot smuggle a newer record shape past the gate.
    for f in &batch.findings {
        if f.schema_version != RENDER_SCHEMA_VERSION {
            return Err(TelemetryError::RenderSchema(format!(
                "finding schema_version {} not supported; expected {}",
                f.schema_version, RENDER_SCHEMA_VERSION
            )));
        }
    }

    tracing::Span::current()
        .record("player_id", batch.player_id)
        .record("finding_count", batch.findings.len());

    tracing::trace!(
        findings = batch.findings.len(),
        "render-hook finding batch accepted"
    );

    // Phase 2 stub: log only, no storage, no scoring (mirrors `telemetry::ingest`).
    // The verdict/allow-list fusion is server-side signed-rule plumbing in a later
    // phase; the client only reports resolved provenance, it never decides a ban.
    let _ = batch;

    Ok(axum::http::StatusCode::ACCEPTED)
}
