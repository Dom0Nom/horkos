//! Role: Server-side decode + feature extraction for the Linux eBPF
//! loader-injection event records (linux-ebpf-injection, catalog signals 82-90):
//! DT_NEEDED-divergence + load-order (`hk_event_dso_anomaly`), GOT/PLT redirect
//! (`hk_event_got_anomaly`), and the multiplexed loader/interp/text integrity
//! record (`hk_event_loader_integrity`, kind-tagged: PT_INTERP mismatch, transient
//! preload, _r_debug r_brk, RELRO-writable, text COW-broken, LD_AUDIT active).
//! Two planes: the fixed 16-byte C records (decoded here into `#[repr(C)]`
//! mirrors), and the variable-length JSON side-channel (full soname / path /
//! NT_GNU_BUILD_ID strings + the env value + ancestor pid) that does NOT fit the
//! fixed C record and rides the userspace->server HTTP/JSON plane. Exposes
//! `POST /api/loader-findings`. This module extracts features only — it never bans
//! (that authority is the ban-engine's, server-side).
//!
//! Target platforms: server.
//!
//! Guardrail #8: fully async-compatible (pure, no blocking), `thiserror` error
//! type, NO `unwrap()`/`expect()` outside `#[cfg(test)]`. A malformed/short wire
//! record or schema-version mismatch yields a typed error, never a panic.
//!
//! HK-TODO(schema): the event types (`HK_EVENT_DSO_PROVENANCE` = 5 .. =12) and the
//! three 16-byte payload structs are owned by the Schema phase and are NOT yet in
//! the frozen `sdk/include/horkos/event_schema.h` (still
//! `HK_EVENT_SCHEMA_VERSION` = 2, enum tops at `HK_EVENT_HANDLE_OPEN` = 4). The
//! decoders below are written against the impl-plan's pinned field layout/sizes so
//! they are ready when the schema lands; the discriminants are mirrored here as
//! local consts until then. The values 5..12 collide pre-Schema with the Windows
//! vm_access / thread-origin provisional discriminants — the Schema phase assigns
//! the final distinct values; dispatch by the resolved type once it lands.

use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::TelemetryError;

/// Version of the loader-finding JSON plane. Mirrors the bumped
/// `HK_EVENT_SCHEMA_VERSION` (2 -> 3) the impl-plan specifies. Bump in lockstep
/// with the C schema on any additive change.
pub const LOADER_SCHEMA_VERSION: u32 = 3;

// ---------------------------------------------------------------------------
// Event-type discriminants (HK-TODO(schema)).
// ---------------------------------------------------------------------------
pub const HK_EVENT_DSO_PROVENANCE: u32 = 5; // signal 82
pub const HK_EVENT_GOT_ANOMALY: u32 = 6; // signal 83
pub const HK_EVENT_INTERP_MISMATCH: u32 = 7; // signal 84
pub const HK_EVENT_PRELOAD_ANOMALY: u32 = 8; // signals 85, 89
pub const HK_EVENT_DLOPEN_BACKING: u32 = 9; // signal 86
pub const HK_EVENT_LOADORDER_INVERT: u32 = 10; // signal 87 (corroborating-only)
pub const HK_EVENT_RDEBUG_ANOMALY: u32 = 11; // signal 88
pub const HK_EVENT_TEXT_PATCH: u32 = 12; // signal 90

// ---------------------------------------------------------------------------
// Fixed-payload flag bits (mirror InjectionEvents.h).
// ---------------------------------------------------------------------------
pub const HK_DSO_FLAG_NO_DT_NEEDED: u32 = 0x1;
pub const HK_DSO_FLAG_ORDER_INVERT: u32 = 0x2;
pub const HK_DSO_FLAG_OUTSIDE_ALLOW: u32 = 0x4;
pub const HK_DSO_FLAG_MEMFD_DELETED: u32 = 0x8;

pub const HK_GOT_FLAG_RWX_TARGET: u32 = 0x1;
pub const HK_GOT_FLAG_ANON_TARGET: u32 = 0x2;
pub const HK_GOT_FLAG_FOREIGN_DSO: u32 = 0x4;

pub const HK_LI_INTERP_MISMATCH: u32 = 0x01;
pub const HK_LI_PRELOAD_TRANSIENT: u32 = 0x02;
pub const HK_LI_RDEBUG_FOREIGN: u32 = 0x04;
pub const HK_LI_RELRO_WRITABLE: u32 = 0x08;
pub const HK_LI_TEXT_COW_BROKEN: u32 = 0x10;
pub const HK_LI_LD_AUDIT_ACTIVE: u32 = 0x20;

/// Decode errors for the fixed C records.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LoaderInjectError {
    #[error("record too short: need {need} bytes for {what}, got {got}")]
    Short {
        what: &'static str,
        need: usize,
        got: usize,
    },
    #[error("unknown loader-inject event type {0}")]
    UnknownType(u32),
}

fn read_u32(buf: &[u8], off: usize, what: &'static str) -> Result<u32, LoaderInjectError> {
    let end = off + 4;
    if buf.len() < end {
        return Err(LoaderInjectError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 4];
    a.copy_from_slice(&buf[off..end]);
    Ok(u32::from_le_bytes(a))
}

fn read_u64(buf: &[u8], off: usize, what: &'static str) -> Result<u64, LoaderInjectError> {
    let end = off + 8;
    if buf.len() < end {
        return Err(LoaderInjectError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&buf[off..end]);
    Ok(u64::from_le_bytes(a))
}

// ---------------------------------------------------------------------------
// `#[repr(C)]` mirrors of the three 16-byte fixed payloads (impl-plan §3.1).
// ---------------------------------------------------------------------------

/// Mirror of `hk_event_dso_anomaly` (16 bytes) — signals 82/87.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DsoAnomaly {
    pub pid: u32,
    pub flags: u32,
    pub buildid_prefix: u64,
}

/// Mirror of `hk_event_got_anomaly` (16 bytes) — signal 83.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GotAnomaly {
    pub pid: u32,
    pub got_flags: u32,
    pub slot_target: u64,
}

/// Mirror of `hk_event_loader_integrity` (16 bytes) — signals 84/85/88/90/89.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoaderIntegrity {
    pub pid: u32,
    pub kind_flags: u32,
    pub detail: u64,
}

const _: () = assert!(core::mem::size_of::<DsoAnomaly>() == 16);
const _: () = assert!(core::mem::size_of::<GotAnomaly>() == 16);
const _: () = assert!(core::mem::size_of::<LoaderIntegrity>() == 16);

impl DsoAnomaly {
    pub fn decode(buf: &[u8]) -> Result<Self, LoaderInjectError> {
        Ok(Self {
            pid: read_u32(buf, 0, "dso_anomaly.pid")?,
            flags: read_u32(buf, 4, "dso_anomaly.flags")?,
            buildid_prefix: read_u64(buf, 8, "dso_anomaly.buildid_prefix")?,
        })
    }
}

impl GotAnomaly {
    pub fn decode(buf: &[u8]) -> Result<Self, LoaderInjectError> {
        Ok(Self {
            pid: read_u32(buf, 0, "got_anomaly.pid")?,
            got_flags: read_u32(buf, 4, "got_anomaly.got_flags")?,
            slot_target: read_u64(buf, 8, "got_anomaly.slot_target")?,
        })
    }
}

impl LoaderIntegrity {
    pub fn decode(buf: &[u8]) -> Result<Self, LoaderInjectError> {
        Ok(Self {
            pid: read_u32(buf, 0, "loader_integrity.pid")?,
            kind_flags: read_u32(buf, 4, "loader_integrity.kind_flags")?,
            detail: read_u64(buf, 8, "loader_integrity.detail")?,
        })
    }
}

/// A decoded loader-inject fixed payload, tagged by wire type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderInjectEvent {
    Dso(DsoAnomaly),
    Got(GotAnomaly),
    Integrity(LoaderIntegrity),
}

/// Decode one fixed payload buffer given its wire event type.
pub fn decode_event(
    event_type: u32,
    payload: &[u8],
) -> Result<LoaderInjectEvent, LoaderInjectError> {
    match event_type {
        HK_EVENT_DSO_PROVENANCE | HK_EVENT_LOADORDER_INVERT => {
            Ok(LoaderInjectEvent::Dso(DsoAnomaly::decode(payload)?))
        }
        HK_EVENT_GOT_ANOMALY => Ok(LoaderInjectEvent::Got(GotAnomaly::decode(payload)?)),
        HK_EVENT_INTERP_MISMATCH
        | HK_EVENT_PRELOAD_ANOMALY
        | HK_EVENT_DLOPEN_BACKING
        | HK_EVENT_RDEBUG_ANOMALY
        | HK_EVENT_TEXT_PATCH => Ok(LoaderInjectEvent::Integrity(LoaderIntegrity::decode(
            payload,
        )?)),
        other => Err(LoaderInjectError::UnknownType(other)),
    }
}

// ---------------------------------------------------------------------------
// JSON ingest plane (the variable-length side-channel, impl-plan §3.1 option B).
// ---------------------------------------------------------------------------

/// One loader-injection finding on the HTTP/JSON plane. The numeric core mirrors
/// the fixed C record (event_type + pid + flags + detail); the trailing
/// `Option<...>` fields are the JSON-only side channel (full soname/path, full
/// build-id, env value, ancestor pid) the fixed C record deliberately keeps
/// out-of-band so it stays 16 bytes. Each string field is `#[serde(default)]` so
/// a finding that does not populate one omits it on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoaderFinding {
    /// `LOADER_SCHEMA_VERSION` at emit.
    pub schema_version: u32,
    /// One of the `HK_EVENT_*` loader-inject discriminants above.
    pub event_type: u32,
    /// Subject (protected game) pid.
    pub pid: u32,
    /// The matching fixed-payload flags word (HK_DSO_/HK_GOT_/HK_LI_*).
    pub flags: u32,
    /// slot_target / detail / buildid_prefix per event type.
    #[serde(default)]
    pub detail: u64,
    /// Full soname or resolved path (JSON-only).
    #[serde(default)]
    pub soname_or_path: Option<String>,
    /// Full NT_GNU_BUILD_ID, hex-encoded (JSON-only).
    #[serde(default)]
    pub build_id_hex: Option<String>,
    /// LD_PRELOAD/LD_AUDIT/LD_LIBRARY_PATH raw value for preload findings
    /// (JSON-only; HIGHEST-sensitivity field — can embed a home dir path; see
    /// data-categories §2b DPIA note).
    #[serde(default)]
    pub preload_env_value: Option<String>,
    /// Env-setting ancestor pid for signal-85 attribution (JSON-only).
    #[serde(default)]
    pub ancestor_pid: Option<u32>,
}

/// Router exposing the loader-finding ingest plane.
pub fn router() -> Router {
    Router::new().route("/api/loader-findings", post(ingest))
}

#[tracing::instrument(skip_all, fields(pid, event_type))]
async fn ingest(
    Json(findings): Json<Vec<LoaderFinding>>,
) -> Result<axum::http::StatusCode, TelemetryError> {
    for f in &findings {
        if f.schema_version != LOADER_SCHEMA_VERSION {
            return Err(TelemetryError::InvalidPayload(format!(
                "loader finding schema_version {} not supported; expected {}",
                f.schema_version, LOADER_SCHEMA_VERSION
            )));
        }
    }

    // Phase stub parity with telemetry::ingest / render_hook::ingest: validate the
    // schema, record a span, drop on the floor. Real persistence + ban-engine
    // scoring lands in the M5 /tdd phase. No client verdict is ever derived here —
    // the server holds all ban authority (signal 87 stays corroborating-only).
    let _ = findings;
    Ok(axum::http::StatusCode::ACCEPTED)
}

// ---------------------------------------------------------------------------
// Feature extraction. Pure, allocation-free; the ban-engine consumes these.
// ---------------------------------------------------------------------------

/// Normalized features handed to the ban-engine. Booleans are derived evidence,
/// not verdicts. `corroborating_only` marks the signal-87 load-order finding,
/// which the ban-engine must never let reach the ban threshold standalone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LoaderInjectFeatures {
    /// A mapped DSO with no DT_NEEDED provenance (signal 82).
    pub no_dt_needed: bool,
    /// Outside the signed overlay/allocator allowlist (every signal's FP gate).
    pub outside_allowlist: bool,
    /// Fileless backing: memfd/(deleted)/anon exec mapping (signals 82/86).
    pub fileless_backing: bool,
    /// Load-order inversion — CORROBORATING-ONLY (signal 87).
    pub corroborating_only: bool,
    /// A GOT/PLT slot resolved to a RWX or anon target (signal 83).
    pub got_redirect: bool,
    /// Live interpreter build-id != expected/manifest (signal 84).
    pub interp_mismatch: bool,
    /// A transient per-launch LD_PRELOAD/LD_AUDIT not in steady state (signal 85).
    pub preload_transient: bool,
    /// rtld-audit la_symbind active with no provenanced LD_AUDIT (signal 89).
    pub ld_audit_active: bool,
    /// _r_debug.r_brk repointed outside ld.so, no tracer (signal 88).
    pub rdebug_foreign: bool,
    /// File-backed exec page gone private-dirty, no tracer (signal 90).
    pub text_cow_broken: bool,
}

impl DsoAnomaly {
    pub fn features(&self) -> LoaderInjectFeatures {
        LoaderInjectFeatures {
            no_dt_needed: (self.flags & HK_DSO_FLAG_NO_DT_NEEDED) != 0,
            outside_allowlist: (self.flags & HK_DSO_FLAG_OUTSIDE_ALLOW) != 0,
            fileless_backing: (self.flags & HK_DSO_FLAG_MEMFD_DELETED) != 0,
            // The DSO record is reused for signal 87; the order-invert bit marks
            // the corroborating-only path.
            corroborating_only: (self.flags & HK_DSO_FLAG_ORDER_INVERT) != 0,
            ..Default::default()
        }
    }
}

impl GotAnomaly {
    pub fn features(&self) -> LoaderInjectFeatures {
        LoaderInjectFeatures {
            got_redirect: (self.got_flags
                & (HK_GOT_FLAG_RWX_TARGET | HK_GOT_FLAG_ANON_TARGET | HK_GOT_FLAG_FOREIGN_DSO))
                != 0,
            outside_allowlist: (self.got_flags & HK_GOT_FLAG_FOREIGN_DSO) != 0,
            ..Default::default()
        }
    }
}

impl LoaderIntegrity {
    pub fn features(&self) -> LoaderInjectFeatures {
        LoaderInjectFeatures {
            interp_mismatch: (self.kind_flags & HK_LI_INTERP_MISMATCH) != 0,
            preload_transient: (self.kind_flags & HK_LI_PRELOAD_TRANSIENT) != 0,
            ld_audit_active: (self.kind_flags & HK_LI_LD_AUDIT_ACTIVE) != 0,
            rdebug_foreign: (self.kind_flags & HK_LI_RDEBUG_FOREIGN) != 0,
            text_cow_broken: (self.kind_flags & HK_LI_TEXT_COW_BROKEN) != 0,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc16(a: u32, b: u32, c: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(16);
        v.extend_from_slice(&a.to_le_bytes());
        v.extend_from_slice(&b.to_le_bytes());
        v.extend_from_slice(&c.to_le_bytes());
        v
    }

    #[test]
    fn dso_anomaly_round_trip_and_features() {
        let d = DsoAnomaly {
            pid: 1234,
            flags: HK_DSO_FLAG_NO_DT_NEEDED | HK_DSO_FLAG_OUTSIDE_ALLOW,
            buildid_prefix: 0x0807_0605_0403_0201,
        };
        let bytes = enc16(d.pid, d.flags, d.buildid_prefix);
        assert_eq!(bytes.len(), 16);
        let decoded = DsoAnomaly::decode(&bytes).expect("decode");
        assert_eq!(decoded, d);
        let f = decoded.features();
        assert!(f.no_dt_needed && f.outside_allowlist);
        assert!(!f.corroborating_only);
    }

    #[test]
    fn loadorder_invert_is_corroborating_only() {
        let d = DsoAnomaly {
            pid: 9,
            flags: HK_DSO_FLAG_ORDER_INVERT | HK_DSO_FLAG_OUTSIDE_ALLOW | HK_DSO_FLAG_NO_DT_NEEDED,
            buildid_prefix: 0,
        };
        assert!(d.features().corroborating_only);
        // Dispatch via decode_event for the 87 type.
        let bytes = enc16(d.pid, d.flags, d.buildid_prefix);
        match decode_event(HK_EVENT_LOADORDER_INVERT, &bytes).expect("decode") {
            LoaderInjectEvent::Dso(x) => assert!(x.features().corroborating_only),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn got_anomaly_rwx_target() {
        let g = GotAnomaly {
            pid: 5,
            got_flags: HK_GOT_FLAG_RWX_TARGET,
            slot_target: 0x5000_0000,
        };
        let bytes = enc16(g.pid, g.got_flags, g.slot_target);
        let decoded = GotAnomaly::decode(&bytes).expect("decode");
        assert_eq!(decoded, g);
        assert!(decoded.features().got_redirect);
    }

    #[test]
    fn loader_integrity_kinds() {
        let li = LoaderIntegrity {
            pid: 7,
            kind_flags: HK_LI_INTERP_MISMATCH | HK_LI_LD_AUDIT_ACTIVE,
            detail: 0xdead,
        };
        let f = li.features();
        assert!(f.interp_mismatch);
        assert!(f.ld_audit_active);
        assert!(!f.text_cow_broken);
    }

    #[test]
    fn short_buffer_is_typed_error_not_panic() {
        let short = [0u8; 10];
        let err = DsoAnomaly::decode(&short).expect_err("must be Short");
        match err {
            LoaderInjectError::Short { got, .. } => assert_eq!(got, 10),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn unknown_type_is_typed_error() {
        let err = decode_event(99, &[0u8; 16]).expect_err("unknown");
        assert_eq!(err, LoaderInjectError::UnknownType(99));
    }

    #[test]
    fn json_finding_round_trips_with_optional_fields_omitted() {
        let f = LoaderFinding {
            schema_version: LOADER_SCHEMA_VERSION,
            event_type: HK_EVENT_PRELOAD_ANOMALY,
            pid: 20,
            flags: HK_LI_PRELOAD_TRANSIENT,
            detail: 19,
            soname_or_path: Some("/tmp/cheat.so".into()),
            build_id_hex: None,
            preload_env_value: Some("/tmp/cheat.so".into()),
            ancestor_pid: Some(19),
        };
        let json = serde_json::to_string(&f).expect("ser");
        let back: LoaderFinding = serde_json::from_str(&json).expect("de");
        assert_eq!(back, f);
        // A minimal finding (numeric core only) deserializes with defaults.
        let minimal = r#"{"schema_version":3,"event_type":5,"pid":1,"flags":4}"#;
        let m: LoaderFinding = serde_json::from_str(minimal).expect("de minimal");
        assert_eq!(m.detail, 0);
        assert!(m.soname_or_path.is_none());
        assert!(m.ancestor_pid.is_none());
    }
}
