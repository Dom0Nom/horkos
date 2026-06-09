//! src/driver_integrity.rs
//!
//! Role: Server-side decode + feature extraction for the Windows driver/module
//! integrity event record (win-kernel-driver-integrity): the single
//! `hk_event_integrity_finding` payload carrying `{signal_id, finding, detail}`
//! emitted by signals 28-36 (minifilter owner, .text hash, code-integrity state,
//! callback residency, non-image exec, kernel-debug attach, DRIVER_OBJECT
//! divergence, SSDT range, boot/ELAM load order). Decodes the drained kernel-event
//! byte stream into a `#[repr(C)]` mirror of the C99 wire struct in
//! `sdk/include/horkos/event_schema.h`, then maps the `finding` code to a typed
//! enum and a normalized weight class for the ban-engine. This module extracts
//! features only — it never bans (that authority is the ban-engine's).
//!
//! Target platforms: server.
//!
//! Guardrail #8: pure/non-blocking (async-compatible), `thiserror` error type, NO
//! `unwrap()`/`expect()` outside `#[cfg(test)]`. A malformed/short or unknown-code
//! record yields a typed `IntegrityError`, never a panic. The weight is read from
//! a code->class map here; the ban-engine config owns the numeric scoring (the
//! plan: "scoring weights per finding live in the ban-engine config, not
//! hardcoded panics").
//!
//! HK-TODO(schema): the event type (`HK_EVENT_INTEGRITY_FINDING` = 5) and the
//! schema bump (2 -> 3) are owned by the Schema phase and are NOT yet in the
//! frozen `sdk/include/horkos/event_schema.h`. The decoder below is written
//! against the plan's pinned 16-byte layout so it is ready when the schema lands;
//! the event-type discriminant is mirrored here as a local const until then. Note
//! the value `5` collides pre-Schema with the thread-origin and callback-integrity
//! domains' provisional discriminants — the Schema phase assigns the final
//! distinct values; this decoder must be dispatched by the resolved type, not by
//! the provisional `5`, once Schema lands.

use thiserror::Error;

/// Event-type discriminant for the integrity-finding record. HK-TODO(schema):
/// provisional mirror of the value the Schema phase appends to `hk_event_type`.
pub const HK_EVENT_INTEGRITY_FINDING: u32 = 5;

/// Finding codes (mirror of the C `HK_INTEGRITY_*` constants).
pub const HK_INTEGRITY_OK: u32 = 0x00;
pub const HK_INTEGRITY_FLT_OUT_OF_IMAGE: u32 = 0x01; // signal 28
pub const HK_INTEGRITY_TEXT_HASH_DELTA: u32 = 0x02; // signal 29
pub const HK_INTEGRITY_CI_STATE_DELTA: u32 = 0x03; // signal 30
pub const HK_INTEGRITY_CALLBACK_NO_IMAGE: u32 = 0x04; // signal 31
pub const HK_INTEGRITY_NONIMAGE_EXEC: u32 = 0x05; // signal 32
pub const HK_INTEGRITY_KDBG_ATTACHED: u32 = 0x06; // signal 33 (high)
pub const HK_INTEGRITY_KDBG_BOOT_ALLOWED: u32 = 0x07; // signal 33 (low)
pub const HK_INTEGRITY_DRVOBJ_DIVERGENCE: u32 = 0x08; // signal 34
pub const HK_INTEGRITY_SSDT_OUT_OF_IMAGE: u32 = 0x09; // signal 35
pub const HK_INTEGRITY_BOOTLOAD_SUPPRESS: u32 = 0x0A; // signal 36

// Syscall / ETW / PatchGuard surface integrity (win-kernel-syscall-etw-integrity,
// signals 208..216). Disjoint 0x20..0x2F range from the 0x01..0x0A driver-
// integrity codes above; same `hk_event_integrity_finding` wire type, no new
// struct. Mirror of the kernel-private `HK_INTEGRITY_*` constants in
// kernel/win/include/horkos_kernel.h. HK-TODO(schema): these belong in the frozen
// event_schema.h alongside the 0x01..0x0A codes; the Schema phase owns that edit.
pub const HK_INTEGRITY_SSDT_ENTRY_OOI: u32 = 0x20; // 208 native SSDT entry out-of-image
pub const HK_INTEGRITY_SHADOW_SSDT_OOI: u32 = 0x21; // 209 shadow SSDT entry out-of-image
pub const HK_INTEGRITY_LSTAR_MISMATCH: u32 = 0x22; // 210 LSTAR != KiSystemCall64[Shadow]
pub const HK_INTEGRITY_LSTAR_CPU_DIVERGE: u32 = 0x23; // 210 per-CPU LSTAR divergence
pub const HK_INTEGRITY_INFINITY_HOOK: u32 = 0x24; // 211 perf-trace callback out-of-image
pub const HK_INTEGRITY_ETWTI_DOWN: u32 = 0x25; // 212 ETW-TI handle nulled / disabled
pub const HK_INTEGRITY_ETWTI_NO_KEEPALIVE: u32 = 0x26; // 212 consumer keepalive stale
pub const HK_INTEGRITY_SYSCALL_PROLOGUE: u32 = 0x27; // 213 KiSystemCall64 prologue delta
pub const HK_INTEGRITY_IDT_OOI: u32 = 0x28; // 214 IDT gate handler out-of-image
pub const HK_INTEGRITY_ETW_SESSION_SUPPR: u32 = 0x29; // 215 security session disabled vs baseline
pub const HK_INTEGRITY_SSDT_BASE_SWAP: u32 = 0x2A; // 216 ServiceTableBase/Limit changed
                                                   // Build-fragility outcome: a signal resolved to "unverifiable" on an unknown
                                                   // build rather than false-positive. Weighted as no-signal (never bans).
pub const HK_INTEGRITY_UNVERIFIABLE: u32 = 0x2F;

/// Decode errors. A short or unknown-code record must surface as one of these —
/// never a panic (guardrail #8).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IntegrityError {
    #[error("record too short: need {need} bytes for integrity_finding, got {got}")]
    Short { need: usize, got: usize },

    #[error("unknown integrity finding code {0}")]
    UnknownFinding(u32),

    #[error("unexpected integrity event type {0}")]
    UnexpectedType(u32),
}

fn read_u32(buf: &[u8], off: usize) -> Result<u32, IntegrityError> {
    let end = off + 4;
    if buf.len() < end {
        return Err(IntegrityError::Short {
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 4];
    a.copy_from_slice(&buf[off..end]);
    Ok(u32::from_le_bytes(a))
}

fn read_u64(buf: &[u8], off: usize) -> Result<u64, IntegrityError> {
    let end = off + 8;
    if buf.len() < end {
        return Err(IntegrityError::Short {
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&buf[off..end]);
    Ok(u64::from_le_bytes(a))
}

/// `#[repr(C)]` mirror of `hk_event_integrity_finding` (16 bytes). Field names and
/// order track `sdk/include/horkos/event_schema.h` exactly (per the plan).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegrityFinding {
    /// Catalog signal number 28..36, or 0 on a completion heartbeat.
    pub signal_id: u32,
    /// `HK_INTEGRITY_*` finding code.
    pub finding: u32,
    /// Signal-specific masked detail (image-relative offset, altitude,
    /// CodeIntegrityOptions bitfield, SSDT index, or masked address). Per the
    /// plan's KASLR-leak gate (Risk 7) this is NEVER a raw kernel pointer; the
    /// kernel masks it before emit, so the server may log it as-is.
    pub detail: u64,
}

// Compile-time size pin mirroring the C HK_STATIC_ASSERT (== 16).
const _: () = assert!(core::mem::size_of::<IntegrityFinding>() == 16);

/// Weight class the ban-engine uses to bucket a finding. The numeric score per
/// class lives in the ban-engine config (not here) — this is the qualitative tier
/// the plan/catalog assign. `Heartbeat` is the `HK_INTEGRITY_OK` scan-completed
/// signal and is never scored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeightClass {
    /// Scan-completed heartbeat (`HK_INTEGRITY_OK`). Not a finding.
    Heartbeat,
    /// High-confidence on HVCI/PatchGuard systems or a live attach.
    High,
    /// Standard anti-cheat-relevant finding.
    Medium,
    /// Low weight / high-FP, server-scored corroboration only (never standalone).
    Low,
    /// Build-fragility no-signal (`HK_INTEGRITY_UNVERIFIABLE`). A sensor could not
    /// verify on an unknown build and declined to false-positive. Scored as
    /// no-signal — it never contributes to a ban (plan: "UNVERIFIABLE weights as
    /// no-signal so build-fragility never produces a ban").
    Unverifiable,
}

impl IntegrityFinding {
    pub fn decode(buf: &[u8]) -> Result<Self, IntegrityError> {
        Ok(Self {
            signal_id: read_u32(buf, 0)?,
            finding: read_u32(buf, 4)?,
            detail: read_u64(buf, 8)?,
        })
    }

    /// Map the `finding` code to its qualitative weight class. An unknown code is
    /// a typed error, NOT a panic and NOT silently dropped — the caller decides
    /// whether to quarantine (guardrail #8).
    pub fn weight_class(&self) -> Result<WeightClass, IntegrityError> {
        match self.finding {
            HK_INTEGRITY_OK => Ok(WeightClass::Heartbeat),
            // Attach-now and SSDT-out-of-image on HVCI are high-confidence.
            HK_INTEGRITY_KDBG_ATTACHED | HK_INTEGRITY_SSDT_OUT_OF_IMAGE => Ok(WeightClass::High),
            HK_INTEGRITY_FLT_OUT_OF_IMAGE
            | HK_INTEGRITY_TEXT_HASH_DELTA
            | HK_INTEGRITY_CI_STATE_DELTA
            | HK_INTEGRITY_CALLBACK_NO_IMAGE
            | HK_INTEGRITY_DRVOBJ_DIVERGENCE
            | HK_INTEGRITY_BOOTLOAD_SUPPRESS => Ok(WeightClass::Medium),
            // High-FP / lower-weight per catalog: boot-debug-allowed and
            // non-image-exec are corroboration only.
            HK_INTEGRITY_KDBG_BOOT_ALLOWED | HK_INTEGRITY_NONIMAGE_EXEC => Ok(WeightClass::Low),

            // ---- Syscall / ETW surface integrity (208..216) ----
            // High-confidence: an out-of-image SSDT/IDT/perf-callback target or an
            // LSTAR mismatch on an HVCI/PatchGuard box is what would have
            // bugchecked the OS, and a descriptor base-swap is the low-FP
            // clone-table case (plan: LSTAR_MISMATCH high-confidence).
            HK_INTEGRITY_SSDT_ENTRY_OOI
            | HK_INTEGRITY_SHADOW_SSDT_OOI
            | HK_INTEGRITY_LSTAR_MISMATCH
            | HK_INTEGRITY_LSTAR_CPU_DIVERGE
            | HK_INTEGRITY_IDT_OOI
            | HK_INTEGRITY_SSDT_BASE_SWAP => Ok(WeightClass::High),
            // Medium per catalog FP risk: prologue delta and ETW-TI down are
            // anti-cheat-relevant but boot-self-patch / EDR-toggle adjacent.
            HK_INTEGRITY_SYSCALL_PROLOGUE
            | HK_INTEGRITY_ETWTI_DOWN
            | HK_INTEGRITY_ETWTI_NO_KEEPALIVE => Ok(WeightClass::Medium),
            // Low / corroboration-only per catalog medium-FP: infinity-hook and
            // ETW-session suppression need session-census corroboration.
            HK_INTEGRITY_INFINITY_HOOK | HK_INTEGRITY_ETW_SESSION_SUPPR => Ok(WeightClass::Low),
            // Build-fragility no-signal — never bans.
            HK_INTEGRITY_UNVERIFIABLE => Ok(WeightClass::Unverifiable),

            other => Err(IntegrityError::UnknownFinding(other)),
        }
    }

    /// True iff this record is the scan-completed heartbeat, not a finding.
    pub fn is_heartbeat(&self) -> bool {
        self.finding == HK_INTEGRITY_OK
    }
}

/// Decode one payload buffer asserted to be an integrity-finding record. The
/// event type is checked so the decoder can be used standalone (the ingest path
/// dispatches by type before calling this; tests pass the type explicitly).
pub fn decode_event(event_type: u32, payload: &[u8]) -> Result<IntegrityFinding, IntegrityError> {
    if event_type != HK_EVENT_INTEGRITY_FINDING {
        return Err(IntegrityError::UnexpectedType(event_type));
    }
    IntegrityFinding::decode(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(f: &IntegrityFinding) -> Vec<u8> {
        let mut v = Vec::with_capacity(16);
        v.extend_from_slice(&f.signal_id.to_le_bytes());
        v.extend_from_slice(&f.finding.to_le_bytes());
        v.extend_from_slice(&f.detail.to_le_bytes());
        v
    }

    #[test]
    fn round_trip_ci_state_delta() {
        let f = IntegrityFinding {
            signal_id: 30,
            finding: HK_INTEGRITY_CI_STATE_DELTA,
            detail: 0x0000_0411, // a CodeIntegrityOptions bitfield
        };
        let bytes = encode(&f);
        assert_eq!(bytes.len(), 16);
        let decoded = IntegrityFinding::decode(&bytes).expect("decode");
        assert_eq!(decoded, f);
        assert_eq!(decoded.weight_class().expect("class"), WeightClass::Medium);
        assert!(!decoded.is_heartbeat());
    }

    #[test]
    fn kdbg_attach_is_high_boot_allowed_is_low() {
        let attached = IntegrityFinding {
            signal_id: 33,
            finding: HK_INTEGRITY_KDBG_ATTACHED,
            detail: 1,
        };
        let boot = IntegrityFinding {
            signal_id: 33,
            finding: HK_INTEGRITY_KDBG_BOOT_ALLOWED,
            detail: 0,
        };
        assert_eq!(attached.weight_class().expect("c"), WeightClass::High);
        assert_eq!(boot.weight_class().expect("c"), WeightClass::Low);
    }

    #[test]
    fn ssdt_out_of_image_is_high() {
        let f = IntegrityFinding {
            signal_id: 35,
            finding: HK_INTEGRITY_SSDT_OUT_OF_IMAGE,
            detail: 42, // service index, not an address (no KASLR leak)
        };
        assert_eq!(f.weight_class().expect("c"), WeightClass::High);
    }

    #[test]
    fn heartbeat_is_not_scored() {
        let f = IntegrityFinding {
            signal_id: 0,
            finding: HK_INTEGRITY_OK,
            detail: 0,
        };
        assert!(f.is_heartbeat());
        assert_eq!(f.weight_class().expect("c"), WeightClass::Heartbeat);
    }

    #[test]
    fn short_buffer_is_typed_error_not_panic() {
        let short = [0u8; 9];
        let err = IntegrityFinding::decode(&short).expect_err("must be Short");
        match err {
            IntegrityError::Short { got, .. } => assert_eq!(got, 9),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn unknown_finding_code_is_typed_error() {
        let f = IntegrityFinding {
            signal_id: 99,
            finding: 0xDEAD,
            detail: 0,
        };
        let err = f.weight_class().expect_err("unknown");
        assert_eq!(err, IntegrityError::UnknownFinding(0xDEAD));
    }

    #[test]
    fn wrong_event_type_is_typed_error() {
        let err = decode_event(4, &[0u8; 16]).expect_err("wrong type");
        assert_eq!(err, IntegrityError::UnexpectedType(4));
    }

    #[test]
    fn syscall_etw_high_confidence_codes() {
        for code in [
            HK_INTEGRITY_SSDT_ENTRY_OOI,
            HK_INTEGRITY_LSTAR_MISMATCH,
            HK_INTEGRITY_LSTAR_CPU_DIVERGE,
            HK_INTEGRITY_IDT_OOI,
            HK_INTEGRITY_SSDT_BASE_SWAP,
            HK_INTEGRITY_SHADOW_SSDT_OOI,
        ] {
            let f = IntegrityFinding {
                signal_id: 210,
                finding: code,
                detail: 1,
            };
            assert_eq!(
                f.weight_class().expect("class"),
                WeightClass::High,
                "code {code:#x} should be High"
            );
        }
    }

    #[test]
    fn syscall_etw_medium_and_low_codes() {
        let medium = [
            HK_INTEGRITY_SYSCALL_PROLOGUE,
            HK_INTEGRITY_ETWTI_DOWN,
            HK_INTEGRITY_ETWTI_NO_KEEPALIVE,
        ];
        for code in medium {
            let f = IntegrityFinding {
                signal_id: 212,
                finding: code,
                detail: 0,
            };
            assert_eq!(f.weight_class().expect("class"), WeightClass::Medium);
        }
        let low = [HK_INTEGRITY_INFINITY_HOOK, HK_INTEGRITY_ETW_SESSION_SUPPR];
        for code in low {
            let f = IntegrityFinding {
                signal_id: 215,
                finding: code,
                detail: 0,
            };
            assert_eq!(f.weight_class().expect("class"), WeightClass::Low);
        }
    }

    #[test]
    fn unverifiable_scores_as_no_signal_never_bans() {
        let f = IntegrityFinding {
            signal_id: 208,
            finding: HK_INTEGRITY_UNVERIFIABLE,
            detail: 0,
        };
        // Unverifiable is its own class; it is NOT High/Medium/Low, so the
        // ban-engine never accrues weight from a build-fragility outcome.
        assert_eq!(f.weight_class().expect("class"), WeightClass::Unverifiable);
        assert!(!f.is_heartbeat());
    }

    #[test]
    fn lstar_diverge_detail_is_cpu_index_round_trips() {
        // detail carries a small CPU index, never a raw MSR value (no KASLR leak).
        let f = IntegrityFinding {
            signal_id: 210,
            finding: HK_INTEGRITY_LSTAR_CPU_DIVERGE,
            detail: 3,
        };
        let bytes = encode(&f);
        let decoded = decode_event(HK_EVENT_INTEGRITY_FINDING, &bytes).expect("decode");
        assert_eq!(decoded.detail, 3);
        assert_eq!(decoded.weight_class().expect("c"), WeightClass::High);
    }

    #[test]
    fn decode_event_accepts_integrity_type() {
        let f = IntegrityFinding {
            signal_id: 34,
            finding: HK_INTEGRITY_DRVOBJ_DIVERGENCE,
            detail: 0x1234,
        };
        let bytes = encode(&f);
        let decoded = decode_event(HK_EVENT_INTEGRITY_FINDING, &bytes).expect("decode");
        assert_eq!(decoded.signal_id, 34);
    }
}
