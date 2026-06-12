//! Role: Server-side decode + feature extraction for the Windows thread-origin
//! event records (win-kernel-thread-injection): thread-create provenance
//! (`hk_event_thread_create`), alloc/setcontext/resume injection causality
//! (`hk_event_thread_inject`), remote-APC injection (`hk_event_apc_inject`), and
//! userspace provenance enrichment (`hk_event_thread_provenance`). Decodes the
//! drained kernel-event byte stream into `#[repr(C)]` mirrors of the C99 wire
//! structs in `sdk/include/horkos/event_schema.h`, then extracts normalized
//! features for the ban-engine / ONNX path (chain completeness, start mismatch,
//! cross-session, unbacked-stack). This module extracts features only — it never
//! bans (that authority is the ban-engine's, server-side).
//!
//! Target platforms: server.
//!
//! Guardrail #8: fully async-compatible (pure, no blocking), `thiserror` error
//! type, NO `unwrap()`/`expect()` outside `#[cfg(test)]`. A malformed/short wire
//! record yields a typed `ThreadInjectError`, never a panic.
//!
//! HK-TODO(schema): the event types (`HK_EVENT_THREAD_CREATE` = 5 .. =8) and the
//! grown `HK_EVENT_PAYLOAD_MAX` (16 -> 56, re-pinning `hk_event_record` to 80B)
//! are owned by the Schema phase and are NOT yet in the frozen
//! `sdk/include/horkos/event_schema.h`. The decoders below are written against
//! the plan's pinned field layout/sizes so they are ready when the schema lands;
//! the event-type discriminants are mirrored here as local consts until then.

use thiserror::Error;

/// Event-type discriminants for the thread-origin records. HK-TODO(schema):
/// mirror of the values the Schema phase appends to `hk_event_type`.
pub const HK_EVENT_THREAD_CREATE: u32 = 5;
pub const HK_EVENT_THREAD_INJECT: u32 = 6;
pub const HK_EVENT_APC_INJECT: u32 = 7;
pub const HK_EVENT_THREAD_PROVENANCE: u32 = 8;

/// Thread-create flag bits (mirror of `HK_THREAD_FLAG_*`).
pub const HK_THREAD_FLAG_WOW64_TARGET: u32 = 0x0000_0001;
pub const HK_THREAD_FLAG_CROSS_SESSION: u32 = 0x0000_0002;

/// Injection-chain bits (mirror of `HK_INJECT_CHAIN_*` / `HK_INJECT_FLAG_*`).
pub const HK_INJECT_CHAIN_ALLOCVM: u32 = 0x0000_0001;
pub const HK_INJECT_CHAIN_SETCONTEXT: u32 = 0x0000_0002;
pub const HK_INJECT_CHAIN_RESUME: u32 = 0x0000_0004;
pub const HK_INJECT_FLAG_SOURCE_DEBUGGER: u32 = 0x0000_0008;
pub const HK_INJECT_FLAG_SOURCE_OVERLAY: u32 = 0x0000_0010;

/// Provenance flag bits (mirror of `HK_PROV_*`).
pub const HK_PROV_START_MISMATCH: u32 = 0x0000_0001;
pub const HK_PROV_ENTRY_STOMPED: u32 = 0x0000_0002;
pub const HK_PROV_ENTRY_PRIVATE: u32 = 0x0000_0004;
pub const HK_PROV_HIDE_FROM_DEBUGGER: u32 = 0x0000_0008;
pub const HK_PROV_WOW64_64BIT_START: u32 = 0x0000_0010;
pub const HK_PROV_JIT_ALLOWLISTED: u32 = 0x0000_0020;

/// Decode errors. A short or otherwise malformed drained record must surface as
/// one of these — never a panic (guardrail #8).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ThreadInjectError {
    #[error("record too short: need {need} bytes for {what}, got {got}")]
    Short {
        what: &'static str,
        need: usize,
        got: usize,
    },

    #[error("unknown thread-origin event type {0}")]
    UnknownType(u32),
}

// ---------------------------------------------------------------------------
// Little-endian fixed-width readers. The kernel emits native-endian; Horkos
// targets little-endian hosts (x86_64/aarch64-LE), so the wire is LE. Each
// reader bounds-checks and returns a typed error rather than panicking.
// ---------------------------------------------------------------------------

fn read_u32(buf: &[u8], off: usize, what: &'static str) -> Result<u32, ThreadInjectError> {
    let end = off + 4;
    if buf.len() < end {
        return Err(ThreadInjectError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 4];
    a.copy_from_slice(&buf[off..end]);
    Ok(u32::from_le_bytes(a))
}

fn read_u64(buf: &[u8], off: usize, what: &'static str) -> Result<u64, ThreadInjectError> {
    let end = off + 8;
    if buf.len() < end {
        return Err(ThreadInjectError::Short {
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
// `#[repr(C)]` mirrors of the wire payloads. Field names and sizes track
// sdk/include/horkos/event_schema.h exactly (per the plan). Sizes are asserted
// at compile time below, matching the C-side HK_STATIC_ASSERT pins.
// ---------------------------------------------------------------------------

/// Mirror of `hk_event_thread_create` (48 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadCreate {
    pub tid: u32,
    pub pid: u32,
    pub creator_tid: u32,
    pub creator_pid: u32,
    pub kernel_start_address: u64,
    pub target_session_id: u32,
    pub creator_session_id: u32,
    pub flags: u32,
    pub reserved: u32,
    pub create_time_ns: u64,
}

/// Mirror of `hk_event_thread_inject` (56 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadInject {
    pub source_pid: u32,
    pub target_pid: u32,
    pub target_tid: u32,
    pub chain_flags: u32,
    pub alloc_base: u64,
    pub alloc_size: u64,
    pub window_ns: u64,
    pub context_rip: u64,
    pub source_session_id: u32,
    pub flags: u32,
}

/// Mirror of `hk_event_apc_inject` (40 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApcInject {
    pub source_pid: u32,
    pub target_pid: u32,
    pub target_tid: u32,
    pub apc_flags: u32,
    pub apc_routine: u64,
    pub routine_region_type: u32,
    pub reserved: u32,
    pub event_time_ns: u64,
}

/// Mirror of `hk_event_thread_provenance` (48 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadProvenance {
    pub tid: u32,
    pub pid: u32,
    pub user_start_address: u64,
    pub entry_region_base: u64,
    pub entry_region_type: u32,
    pub prov_flags: u32,
    pub entry_page_disk_delta: u64,
    pub backing_module_hash32: u32,
    pub reserved: u32,
}

// Compile-time size pins mirroring the C HK_STATIC_ASSERTs (48/56/40/48).
const _: () = assert!(core::mem::size_of::<ThreadCreate>() == 48);
const _: () = assert!(core::mem::size_of::<ThreadInject>() == 56);
const _: () = assert!(core::mem::size_of::<ApcInject>() == 40);
const _: () = assert!(core::mem::size_of::<ThreadProvenance>() == 48);

impl ThreadCreate {
    pub fn decode(buf: &[u8]) -> Result<Self, ThreadInjectError> {
        Ok(Self {
            tid: read_u32(buf, 0, "thread_create.tid")?,
            pid: read_u32(buf, 4, "thread_create.pid")?,
            creator_tid: read_u32(buf, 8, "thread_create.creator_tid")?,
            creator_pid: read_u32(buf, 12, "thread_create.creator_pid")?,
            kernel_start_address: read_u64(buf, 16, "thread_create.kernel_start_address")?,
            target_session_id: read_u32(buf, 24, "thread_create.target_session_id")?,
            creator_session_id: read_u32(buf, 28, "thread_create.creator_session_id")?,
            flags: read_u32(buf, 32, "thread_create.flags")?,
            reserved: read_u32(buf, 36, "thread_create.reserved")?,
            create_time_ns: read_u64(buf, 40, "thread_create.create_time_ns")?,
        })
    }
}

impl ThreadInject {
    pub fn decode(buf: &[u8]) -> Result<Self, ThreadInjectError> {
        Ok(Self {
            source_pid: read_u32(buf, 0, "thread_inject.source_pid")?,
            target_pid: read_u32(buf, 4, "thread_inject.target_pid")?,
            target_tid: read_u32(buf, 8, "thread_inject.target_tid")?,
            chain_flags: read_u32(buf, 12, "thread_inject.chain_flags")?,
            alloc_base: read_u64(buf, 16, "thread_inject.alloc_base")?,
            alloc_size: read_u64(buf, 24, "thread_inject.alloc_size")?,
            window_ns: read_u64(buf, 32, "thread_inject.window_ns")?,
            context_rip: read_u64(buf, 40, "thread_inject.context_rip")?,
            source_session_id: read_u32(buf, 48, "thread_inject.source_session_id")?,
            flags: read_u32(buf, 52, "thread_inject.flags")?,
        })
    }
}

impl ApcInject {
    pub fn decode(buf: &[u8]) -> Result<Self, ThreadInjectError> {
        Ok(Self {
            source_pid: read_u32(buf, 0, "apc_inject.source_pid")?,
            target_pid: read_u32(buf, 4, "apc_inject.target_pid")?,
            target_tid: read_u32(buf, 8, "apc_inject.target_tid")?,
            apc_flags: read_u32(buf, 12, "apc_inject.apc_flags")?,
            apc_routine: read_u64(buf, 16, "apc_inject.apc_routine")?,
            routine_region_type: read_u32(buf, 24, "apc_inject.routine_region_type")?,
            reserved: read_u32(buf, 28, "apc_inject.reserved")?,
            event_time_ns: read_u64(buf, 32, "apc_inject.event_time_ns")?,
        })
    }
}

impl ThreadProvenance {
    pub fn decode(buf: &[u8]) -> Result<Self, ThreadInjectError> {
        Ok(Self {
            tid: read_u32(buf, 0, "thread_provenance.tid")?,
            pid: read_u32(buf, 4, "thread_provenance.pid")?,
            user_start_address: read_u64(buf, 8, "thread_provenance.user_start_address")?,
            entry_region_base: read_u64(buf, 16, "thread_provenance.entry_region_base")?,
            entry_region_type: read_u32(buf, 24, "thread_provenance.entry_region_type")?,
            prov_flags: read_u32(buf, 28, "thread_provenance.prov_flags")?,
            entry_page_disk_delta: read_u64(buf, 32, "thread_provenance.entry_page_disk_delta")?,
            backing_module_hash32: read_u32(buf, 40, "thread_provenance.backing_module_hash32")?,
            reserved: read_u32(buf, 44, "thread_provenance.reserved")?,
        })
    }
}

/// A decoded thread-origin payload, tagged by wire type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadOriginEvent {
    Create(ThreadCreate),
    Inject(ThreadInject),
    Apc(ApcInject),
    Provenance(ThreadProvenance),
}

/// Decode one payload buffer given its wire event type. Unknown types yield a
/// typed error (the caller already degrades unknown types gracefully; this lets
/// the thread-origin decoder be used standalone in tests).
pub fn decode_event(
    event_type: u32,
    payload: &[u8],
) -> Result<ThreadOriginEvent, ThreadInjectError> {
    match event_type {
        HK_EVENT_THREAD_CREATE => Ok(ThreadOriginEvent::Create(ThreadCreate::decode(payload)?)),
        HK_EVENT_THREAD_INJECT => Ok(ThreadOriginEvent::Inject(ThreadInject::decode(payload)?)),
        HK_EVENT_APC_INJECT => Ok(ThreadOriginEvent::Apc(ApcInject::decode(payload)?)),
        HK_EVENT_THREAD_PROVENANCE => Ok(ThreadOriginEvent::Provenance(ThreadProvenance::decode(
            payload,
        )?)),
        other => Err(ThreadInjectError::UnknownType(other)),
    }
}

// ---------------------------------------------------------------------------
// Feature extraction. Pure, allocation-light; the ban-engine consumes these as
// ONNX features. No thresholding/ban here — signal 27's rate weighting is the
// model's job (the catalog is explicit the client never thresholds).
// ---------------------------------------------------------------------------

/// Normalized features handed to the ban-engine's model. Booleans are derived,
/// not decided: a `true` is evidence, not a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ThreadOriginFeatures {
    /// Count of the three injection-chain stages observed (0..=3).
    pub chain_stage_count: u8,
    /// All three stages (alloc + setcontext + resume) present.
    pub chain_complete: bool,
    /// Source PID differs from target PID (cross-process).
    pub cross_process: bool,
    /// A documented FP-gate flag was reported on the chain (debugger/overlay).
    pub has_fp_gate_flag: bool,
    /// Kernel-vs-user start address mismatch (signal 23).
    pub start_mismatch: bool,
    /// Entry page is a stomped system image (signal 24).
    pub entry_stomped: bool,
    /// Creator/target session differ (signal 26).
    pub cross_session: bool,
    /// HideFromDebugger co-signal present (signal 25).
    pub hide_from_debugger: bool,
}

impl ThreadInject {
    /// Number of distinct chain stages present (popcount of the three bits).
    pub fn chain_stage_count(&self) -> u8 {
        let bits = self.chain_flags
            & (HK_INJECT_CHAIN_ALLOCVM | HK_INJECT_CHAIN_SETCONTEXT | HK_INJECT_CHAIN_RESUME);
        bits.count_ones() as u8
    }

    pub fn features(&self) -> ThreadOriginFeatures {
        let stages = self.chain_stage_count();
        ThreadOriginFeatures {
            chain_stage_count: stages,
            chain_complete: stages == 3,
            cross_process: self.source_pid != self.target_pid,
            has_fp_gate_flag: (self.flags
                & (HK_INJECT_FLAG_SOURCE_DEBUGGER | HK_INJECT_FLAG_SOURCE_OVERLAY))
                != 0,
            ..Default::default()
        }
    }
}

impl ThreadCreate {
    pub fn features(&self) -> ThreadOriginFeatures {
        ThreadOriginFeatures {
            cross_session: (self.flags & HK_THREAD_FLAG_CROSS_SESSION) != 0,
            ..Default::default()
        }
    }
}

impl ThreadProvenance {
    pub fn features(&self) -> ThreadOriginFeatures {
        ThreadOriginFeatures {
            start_mismatch: (self.prov_flags & HK_PROV_START_MISMATCH) != 0,
            entry_stomped: (self.prov_flags & HK_PROV_ENTRY_STOMPED) != 0,
            hide_from_debugger: (self.prov_flags & HK_PROV_HIDE_FROM_DEBUGGER) != 0,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a ThreadCreate the way the kernel would (LE), for round-trip tests.
    fn encode_thread_create(tc: &ThreadCreate) -> Vec<u8> {
        let mut v = Vec::with_capacity(48);
        v.extend_from_slice(&tc.tid.to_le_bytes());
        v.extend_from_slice(&tc.pid.to_le_bytes());
        v.extend_from_slice(&tc.creator_tid.to_le_bytes());
        v.extend_from_slice(&tc.creator_pid.to_le_bytes());
        v.extend_from_slice(&tc.kernel_start_address.to_le_bytes());
        v.extend_from_slice(&tc.target_session_id.to_le_bytes());
        v.extend_from_slice(&tc.creator_session_id.to_le_bytes());
        v.extend_from_slice(&tc.flags.to_le_bytes());
        v.extend_from_slice(&tc.reserved.to_le_bytes());
        v.extend_from_slice(&tc.create_time_ns.to_le_bytes());
        v
    }

    fn encode_thread_inject(ti: &ThreadInject) -> Vec<u8> {
        let mut v = Vec::with_capacity(56);
        v.extend_from_slice(&ti.source_pid.to_le_bytes());
        v.extend_from_slice(&ti.target_pid.to_le_bytes());
        v.extend_from_slice(&ti.target_tid.to_le_bytes());
        v.extend_from_slice(&ti.chain_flags.to_le_bytes());
        v.extend_from_slice(&ti.alloc_base.to_le_bytes());
        v.extend_from_slice(&ti.alloc_size.to_le_bytes());
        v.extend_from_slice(&ti.window_ns.to_le_bytes());
        v.extend_from_slice(&ti.context_rip.to_le_bytes());
        v.extend_from_slice(&ti.source_session_id.to_le_bytes());
        v.extend_from_slice(&ti.flags.to_le_bytes());
        v
    }

    #[test]
    fn thread_create_round_trip() {
        let tc = ThreadCreate {
            tid: 0x1111,
            pid: 0x2222,
            creator_tid: 0x3333,
            creator_pid: 0x4444,
            kernel_start_address: 0x7FFF_DEAD_BEEF,
            target_session_id: 1,
            creator_session_id: 0,
            flags: HK_THREAD_FLAG_WOW64_TARGET | HK_THREAD_FLAG_CROSS_SESSION,
            reserved: 0,
            create_time_ns: 123_456_789,
        };
        let bytes = encode_thread_create(&tc);
        assert_eq!(bytes.len(), 48);
        let decoded = ThreadCreate::decode(&bytes).expect("decode");
        assert_eq!(decoded, tc);
        assert!(decoded.features().cross_session);
    }

    #[test]
    fn thread_inject_chain_completeness() {
        let ti = ThreadInject {
            source_pid: 10,
            target_pid: 20,
            target_tid: 21,
            chain_flags: HK_INJECT_CHAIN_ALLOCVM
                | HK_INJECT_CHAIN_SETCONTEXT
                | HK_INJECT_CHAIN_RESUME,
            alloc_base: 0x4000_0000,
            alloc_size: 0x1000,
            window_ns: 5_000_000,
            context_rip: 0x4000_0040,
            source_session_id: 0,
            flags: HK_INJECT_FLAG_SOURCE_DEBUGGER,
        };
        let bytes = encode_thread_inject(&ti);
        assert_eq!(bytes.len(), 56);
        let decoded = ThreadInject::decode(&bytes).expect("decode");
        assert_eq!(decoded, ti);

        let f = decoded.features();
        assert_eq!(f.chain_stage_count, 3);
        assert!(f.chain_complete);
        assert!(f.cross_process);
        assert!(f.has_fp_gate_flag); // debugger-sourced: reported, not suppressed
    }

    #[test]
    fn partial_chain_is_not_complete() {
        let ti = ThreadInject {
            source_pid: 10,
            target_pid: 20,
            target_tid: 21,
            chain_flags: HK_INJECT_CHAIN_ALLOCVM | HK_INJECT_CHAIN_RESUME,
            alloc_base: 0,
            alloc_size: 0,
            window_ns: 0,
            context_rip: 0,
            source_session_id: 0,
            flags: 0,
        };
        let f = ti.features();
        assert_eq!(f.chain_stage_count, 2);
        assert!(!f.chain_complete);
        assert!(!f.has_fp_gate_flag);
    }

    #[test]
    fn short_buffer_is_typed_error_not_panic() {
        let short = [0u8; 10];
        let err = ThreadCreate::decode(&short).expect_err("must be Short");
        match err {
            ThreadInjectError::Short { got, .. } => assert_eq!(got, 10),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn unknown_type_is_typed_error() {
        let err = decode_event(99, &[0u8; 48]).expect_err("unknown");
        assert_eq!(err, ThreadInjectError::UnknownType(99));
    }

    #[test]
    fn provenance_flags_to_features() {
        let p = ThreadProvenance {
            tid: 1,
            pid: 2,
            user_start_address: 0x1000,
            entry_region_base: 0x1000,
            entry_region_type: 1,
            prov_flags: HK_PROV_START_MISMATCH | HK_PROV_HIDE_FROM_DEBUGGER,
            entry_page_disk_delta: 42,
            backing_module_hash32: 0xDEAD_BEEF,
            reserved: 0,
        };
        let f = p.features();
        assert!(f.start_mismatch);
        assert!(f.hide_from_debugger);
        assert!(!f.entry_stomped);
    }

    #[test]
    fn decode_event_dispatches_by_type() {
        let tc = ThreadCreate {
            tid: 7,
            pid: 8,
            creator_tid: 0,
            creator_pid: 0,
            kernel_start_address: 0,
            target_session_id: 0,
            creator_session_id: 0,
            flags: 0,
            reserved: 0,
            create_time_ns: 0,
        };
        let bytes = encode_thread_create(&tc);
        match decode_event(HK_EVENT_THREAD_CREATE, &bytes).expect("decode") {
            ThreadOriginEvent::Create(d) => assert_eq!(d.tid, 7),
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
