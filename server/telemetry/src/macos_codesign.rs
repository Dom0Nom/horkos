//! src/macos_codesign.rs
//!
//! Role: Server-side serde/`#[repr(C)]` mirror + scoring for the macOS
//! code-signing / platform-trust finding payload (`hk_event_cs_finding`, catalog
//! signals 118-126). Decodes the 16-byte macOS daemon-sink record into a mirror
//! of the C99 wire struct in `sdk/include/horkos/event_schema_cs.h`, maps the
//! `finding` code to a typed enum + weight class, and carries the separate
//! variable-length `CsEvidence` JSON report plane (cdhash hex, diffed entitlement
//! keys, offending signing_id, CSR breakdown). This module extracts/scores only —
//! it never bans (that authority is the ban-engine's, server-side). Per the
//! catalog FP gates, signals 124 (AMFI posture) and 125 (Gatekeeper) feed a
//! TRUST-TIER input, never a standalone ban.
//!
//! Target platforms: server.
//!
//! Guardrail #8: pure/sync decoders run inline on the async path (CPU-bound,
//! short); `thiserror` error type; NO `unwrap()`/`expect()` outside `#[cfg(test)]`.
//! A malformed/short record yields a typed `CsError`, never a panic; an unknown
//! `finding` code decodes to a typed quarantine value, never a panic.
//!
//! HK-TODO(schema): the event-type discriminant (`HK_EVENT_CS_FINDING`) lives in
//! `event_schema_cs.h` (a macOS-only header, NOT the frozen shared
//! `event_schema.h`); it is mirrored here as a local const in lockstep. The
//! macOS-plane value (13) avoids a same-value clash with the injection plane's
//! `HK_EVENT_ES_*` (5..12) within a daemon TU; the final shared-enum value the
//! Schema phase assigns is a mechanical rename and does not change the 16-byte
//! layout this decoder pins.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Event-type discriminant for the CS-finding record. HK-TODO(schema): mirror of
/// `event_schema_cs.h` `HK_EVENT_CS_FINDING` (macOS plane value 13).
pub const HK_EVENT_CS_FINDING: u32 = 13;

/// Finding codes — mirror of the C `HK_CS_*` constants.
pub const HK_CS_OK: u32 = 0x00;
pub const HK_CS_FLAGS_DRIFT: u32 = 0x01; // signal 118
pub const HK_CS_CDHASH_MISMATCH: u32 = 0x02; // signal 119
pub const HK_CS_DYNAMIC_INVALID: u32 = 0x03; // signal 120
pub const HK_CS_INVALIDATED_TAMPER: u32 = 0x04; // signal 121
pub const HK_CS_LV_TEAMID_DIVERGENCE: u32 = 0x05; // signal 122
pub const HK_CS_AMFID_TASKPORT: u32 = 0x06; // signal 123
pub const HK_CS_AMFI_POSTURE_WEAK: u32 = 0x07; // signal 124 (trust-tier)
pub const HK_CS_GATEKEEPER_BYPASS: u32 = 0x08; // signal 125 (corroborating only)
pub const HK_CS_ENTITLEMENT_DRIFT: u32 = 0x09; // signal 126

/// team-id class carried in `detail` for signal 122 — mirror of HK_CS_TEAMID_*.
pub const HK_CS_TEAMID_APPLE_PLATFORM: u32 = 0;
pub const HK_CS_TEAMID_SAME_TEAM: u32 = 1;
pub const HK_CS_TEAMID_ALLOWLISTED: u32 = 2;
pub const HK_CS_TEAMID_FOREIGN: u32 = 3;

/// Decode errors. A short record surfaces as one of these — never a panic
/// (guardrail #8). An unknown `finding` code is NOT an error here: it decodes to
/// `CsFinding` with `weight_class() == WeightClass::Quarantine` so the record is
/// retained and typed rather than dropped/panicked.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CsError {
    #[error("record too short: need {need} bytes for cs_finding, got {got}")]
    Short { need: usize, got: usize },

    #[error("unexpected cs event type {0}")]
    UnexpectedType(u32),
}

fn read_u32(buf: &[u8], off: usize) -> Result<u32, CsError> {
    let end = off + 4;
    if buf.len() < end {
        return Err(CsError::Short {
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 4];
    a.copy_from_slice(&buf[off..end]);
    Ok(u32::from_le_bytes(a))
}

/// `#[repr(C)]` mirror of `hk_event_cs_finding` (16 bytes). Field names and order
/// track `sdk/include/horkos/event_schema_cs.h` exactly.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CsFinding {
    /// Catalog signal 118..126, or 0 on an `HK_CS_OK` heartbeat.
    pub signal_id: u32,
    /// `HK_CS_*` finding code.
    pub finding: u32,
    /// Game PID the finding pertains to (0 = host-wide, e.g. AMFI posture/amfid).
    pub target_pid: u32,
    /// Masked compact discriminant (csflags delta, CSR bitfield, team-id class,
    /// or low-32 cdhash fold). NEVER a raw cdhash/pointer — the masking happens
    /// on-box, so the server may log it as-is.
    pub detail: u32,
}

// Compile-time size pin mirroring the C HK_STATIC_ASSERT (== 16).
const _: () = assert!(core::mem::size_of::<CsFinding>() == 16);

impl CsFinding {
    pub fn decode(buf: &[u8]) -> Result<Self, CsError> {
        Ok(Self {
            signal_id: read_u32(buf, 0)?,
            finding: read_u32(buf, 4)?,
            target_pid: read_u32(buf, 8)?,
            detail: read_u32(buf, 12)?,
        })
    }
}

/// Decode one CS-finding payload given its wire event type.
pub fn decode_event(event_type: u32, payload: &[u8]) -> Result<CsFinding, CsError> {
    if event_type != HK_EVENT_CS_FINDING {
        return Err(CsError::UnexpectedType(event_type));
    }
    CsFinding::decode(payload)
}

/// Weight class the ban-engine uses to bucket a finding. The numeric score per
/// class lives in the ban-engine config (not here). `Heartbeat` is the
/// `HK_CS_OK` scan-completed signal and is never scored. `TrustTier` is the
/// catalog's report-only input (signals 124/125) that NEVER bans on its own —
/// server policy decides whether a reduced-security boot may play. `Corroborating`
/// (signal 125 as surfaced) only contributes alongside another finding. An
/// unknown finding code maps to `Quarantine` (typed, retained, never scored as a
/// ban) so the decoder never panics on a future code (guardrail #8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeightClass {
    /// `HK_CS_OK` scan-completed heartbeat. Not a finding.
    Heartbeat,
    /// High-confidence tamper (flags drift, cdhash mismatch, dynamic invalid,
    /// invalidation+exec mmap, entitlement drift).
    High,
    /// Medium-confidence (LV/team-id divergence, amfid task-port).
    Medium,
    /// Report-only trust-tier input (AMFI posture). NEVER a standalone ban.
    TrustTier,
    /// Corroborating-only (Gatekeeper bypass). Contributes only alongside a
    /// 119/126 finding for the same PID.
    Corroborating,
    /// Unknown finding code — retained, typed, never scored as a ban.
    Quarantine,
}

impl CsFinding {
    /// Map the `finding` code to its qualitative weight class (the catalog FP
    /// gates). The numeric score is the ban-engine's; this is the tier only.
    pub fn weight_class(&self) -> WeightClass {
        match self.finding {
            HK_CS_OK => WeightClass::Heartbeat,
            HK_CS_FLAGS_DRIFT
            | HK_CS_CDHASH_MISMATCH
            | HK_CS_DYNAMIC_INVALID
            | HK_CS_INVALIDATED_TAMPER
            | HK_CS_ENTITLEMENT_DRIFT => WeightClass::High,
            HK_CS_LV_TEAMID_DIVERGENCE | HK_CS_AMFID_TASKPORT => WeightClass::Medium,
            HK_CS_AMFI_POSTURE_WEAK => WeightClass::TrustTier,
            HK_CS_GATEKEEPER_BYPASS => WeightClass::Corroborating,
            _ => WeightClass::Quarantine,
        }
    }

    /// Signal 122 helper: the team-id class encoded in `detail`. Only
    /// `HK_CS_TEAMID_FOREIGN` is a genuine LV-bypass; the others are FP-gated
    /// classes the server treats as benign.
    pub fn teamid_class(&self) -> u32 {
        self.detail
    }

    /// Signal 123 helper: whether SIP was enabled when the amfid task-port was
    /// acquired (detail low bit). SIP-off (dev box) is scored SEPARATELY, never as
    /// cheating (plan FP gate).
    pub fn amfid_sip_enabled(&self) -> bool {
        self.detail & 0x1 != 0
    }
}

/// Variable-length evidence report plane (daemon -> server JSON), distinct from
/// the fixed 16-byte record. Carries the full evidence the masked `detail` cannot
/// hold. Every field is a declared telemetry category (see
/// `server/api/data-categories.md` §5). All optional: a given finding fills only
/// the fields relevant to its signal.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CsEvidence {
    /// Live kernel cdhash hex (signal 119, `csops CS_OPS_PIDCDHASH`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cs_live_cdhash: Option<String>,
    /// On-disk cdhash hex (signal 119, `SecCodeCopySigningInformation`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cs_disk_cdhash: Option<String>,
    /// Offending dylib `signing_id` (signal 122).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cs_dylib_signing_id: Option<String>,
    /// Security-relevant entitlement keys that drifted (signal 126).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cs_entitlement_diff_keys: Vec<String>,
    /// AMFI/SIP posture: SIP state, Dev-Mode, boot-arg presence flags (signal 124).
    /// Reported VERBATIM as a trust-tier input, NOT a ban trigger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amfi_posture: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(f: &CsFinding) -> Vec<u8> {
        let mut v = Vec::with_capacity(16);
        v.extend_from_slice(&f.signal_id.to_le_bytes());
        v.extend_from_slice(&f.finding.to_le_bytes());
        v.extend_from_slice(&f.target_pid.to_le_bytes());
        v.extend_from_slice(&f.detail.to_le_bytes());
        v
    }

    #[test]
    fn finding_round_trips() {
        let f = CsFinding {
            signal_id: 118,
            finding: HK_CS_FLAGS_DRIFT,
            target_pid: 0x1234,
            detail: 0x0300, // CS_KILL|CS_HARD masked delta
        };
        let bytes = encode(&f);
        assert_eq!(bytes.len(), 16);
        assert_eq!(CsFinding::decode(&bytes).expect("decode"), f);
    }

    #[test]
    fn short_record_is_typed_error_not_panic() {
        let short = [0u8; 10];
        let err = CsFinding::decode(&short).expect_err("must be Short");
        match err {
            CsError::Short { got, .. } => assert_eq!(got, 10),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn unexpected_event_type_is_typed_error() {
        let f = CsFinding {
            signal_id: 118,
            finding: HK_CS_FLAGS_DRIFT,
            target_pid: 1,
            detail: 0,
        };
        let err = decode_event(99, &encode(&f)).expect_err("unexpected type");
        assert_eq!(err, CsError::UnexpectedType(99));
    }

    #[test]
    fn unknown_finding_code_quarantines_not_panics() {
        // A future finding code must decode to a typed Quarantine, never panic.
        let f = CsFinding {
            signal_id: 200,
            finding: 0xDEAD_BEEF,
            target_pid: 1,
            detail: 0,
        };
        let decoded = decode_event(HK_EVENT_CS_FINDING, &encode(&f)).expect("decode");
        assert_eq!(decoded.weight_class(), WeightClass::Quarantine);
    }

    #[test]
    fn heartbeat_is_not_a_finding() {
        let f = CsFinding {
            signal_id: 0,
            finding: HK_CS_OK,
            target_pid: 0,
            detail: 0,
        };
        assert_eq!(f.weight_class(), WeightClass::Heartbeat);
    }

    #[test]
    fn amfi_posture_is_trust_tier_never_high() {
        // Catalog FP gate: AMFI posture (124) is a trust-tier input, never a ban.
        let f = CsFinding {
            signal_id: 124,
            finding: HK_CS_AMFI_POSTURE_WEAK,
            target_pid: 0,
            detail: 0x2, // SIP_OFF
        };
        assert_eq!(f.weight_class(), WeightClass::TrustTier);
    }

    #[test]
    fn gatekeeper_is_corroborating_only() {
        let f = CsFinding {
            signal_id: 125,
            finding: HK_CS_GATEKEEPER_BYPASS,
            target_pid: 7,
            detail: 0,
        };
        assert_eq!(f.weight_class(), WeightClass::Corroborating);
    }

    #[test]
    fn high_confidence_tamper_signals() {
        for code in [
            HK_CS_FLAGS_DRIFT,
            HK_CS_CDHASH_MISMATCH,
            HK_CS_DYNAMIC_INVALID,
            HK_CS_INVALIDATED_TAMPER,
            HK_CS_ENTITLEMENT_DRIFT,
        ] {
            let f = CsFinding {
                signal_id: 118,
                finding: code,
                target_pid: 1,
                detail: 0,
            };
            assert_eq!(f.weight_class(), WeightClass::High);
        }
    }

    #[test]
    fn teamid_foreign_vs_benign_classes() {
        let foreign = CsFinding {
            signal_id: 122,
            finding: HK_CS_LV_TEAMID_DIVERGENCE,
            target_pid: 1,
            detail: HK_CS_TEAMID_FOREIGN,
        };
        assert_eq!(foreign.weight_class(), WeightClass::Medium);
        assert_eq!(foreign.teamid_class(), HK_CS_TEAMID_FOREIGN);
    }

    #[test]
    fn amfid_sip_bit() {
        let sip_on = CsFinding {
            signal_id: 123,
            finding: HK_CS_AMFID_TASKPORT,
            target_pid: 50,
            detail: 1,
        };
        assert!(sip_on.amfid_sip_enabled());
        let sip_off = CsFinding {
            detail: 0,
            ..sip_on
        };
        assert!(!sip_off.amfid_sip_enabled());
    }

    #[test]
    fn cs_evidence_serde_round_trip() {
        let ev = CsEvidence {
            cs_live_cdhash: Some("aabbccdd".into()),
            cs_disk_cdhash: Some("aabbccde".into()),
            cs_entitlement_diff_keys: vec!["com.apple.security.get-task-allow".into()],
            ..Default::default()
        };
        let json = serde_json::to_string(&ev).expect("serialize");
        // Skipped-None fields must be absent.
        assert!(!json.contains("cs_dylib_signing_id"));
        assert!(!json.contains("amfi_posture"));
        let back: CsEvidence = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ev, back);
    }
}
