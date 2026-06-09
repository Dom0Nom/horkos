//! src/vm_access.rs
//!
//! Role: Server-side decode + feature extraction for the Windows external-memory-
//! access event records (win-handle-memory-access, signals 64-72): cross-process
//! ReadVm/WriteVm/AllocVm/ProtectVm (`hk_event_vm_access`), Ob handle provenance /
//! granted-access delta (`hk_event_handle_provenance`), foreign handle-table holders
//! (`hk_event_foreign_holder`), and page-protection drift (`hk_event_protect_drift`).
//! Decodes the drained kernel-event byte stream into `#[repr(C)]` mirrors of the C99
//! wire structs (currently the kernel-private mirrors in
//! `kernel/win/include/horkos_kernel.h`), then extracts normalized features for the
//! ban-engine. This module extracts features only — it never bans (that authority is
//! the ban-engine's, server-side).
//!
//! Target platforms: server.
//!
//! Guardrail #8: fully async-compatible (pure, no blocking), `thiserror` error type,
//! NO `unwrap()`/`expect()` outside `#[cfg(test)]`. A malformed/short wire record
//! yields a typed `VmAccessError`, never a panic.
//!
//! HK-TODO(schema): the event types (`HK_EVENT_VM_ACCESS` = 5 .. = 8) and the grown
//! `HK_EVENT_PAYLOAD_MAX` (16 -> 28, re-pinning `hk_event_record`) are owned by the
//! Schema phase and are NOT yet in the frozen `sdk/include/horkos/event_schema.h`.
//! The decoders below are written against the plan's pinned field layout/sizes so
//! they are ready when the schema lands; the event-type discriminants are mirrored
//! here as local consts until then. The value `5` collides pre-Schema with the
//! thread-origin / callback-integrity / driver-integrity domains — the Schema phase
//! assigns the final distinct values; this decoder must be dispatched by the
//! resolved type, not by the provisional `5`, once Schema lands.

use thiserror::Error;

/// Event-type discriminants for the VM-access records. HK-TODO(schema): mirror of
/// the values the Schema phase appends to `hk_event_type`.
pub const HK_EVENT_VM_ACCESS: u32 = 5;
pub const HK_EVENT_HANDLE_PROVENANCE: u32 = 6;
pub const HK_EVENT_FOREIGN_HOLDER: u32 = 7;
pub const HK_EVENT_PROTECT_DRIFT: u32 = 8;

/// `access_kind` bits (mirror of `HK_VM_*`).
pub const HK_VM_READ: u32 = 0x0000_0001;
pub const HK_VM_WRITE: u32 = 0x0000_0002;
pub const HK_VM_ALLOC: u32 = 0x0000_0004;
pub const HK_VM_PROTECT: u32 = 0x0000_0008;

/// `hk_event_vm_access.flags` bits.
pub const HK_VM_REMOTE: u32 = 0x0000_0001;
pub const HK_VM_STAGING_SEQ: u32 = 0x0000_0002;
pub const HK_VM_ETWTI_SILENT: u32 = 0x0000_0004;

/// `hk_event_handle_provenance.flags` bits.
pub const HK_HND_DUP_LAUNDERED: u32 = 0x0000_0001;
pub const HK_HND_GRANT_EXCEEDS_PREOP: u32 = 0x0000_0002;

/// `hk_event_foreign_holder.flags` bits.
pub const HK_HND_DANGEROUS_RIGHTS: u32 = 0x0000_0001;
pub const HK_HND_UNSIGNED_OWNER: u32 = 0x0000_0002;

/// `hk_event_protect_drift.flags` bits.
pub const HK_PROT_WX_ON_SHIPPED: u32 = 0x0000_0001;
pub const HK_PROT_FOREIGN_INITIATED: u32 = 0x0000_0002;

/// IMAGE_SCN_MEM_EXECUTE (for the section-flag feature derivation).
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Decode errors. A short or otherwise malformed drained record must surface as one
/// of these — never a panic (guardrail #8).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VmAccessError {
    #[error("record too short: need {need} bytes for {what}, got {got}")]
    Short {
        what: &'static str,
        need: usize,
        got: usize,
    },

    #[error("unknown vm-access event type {0}")]
    UnknownType(u32),
}

// ---------------------------------------------------------------------------
// Little-endian fixed-width readers (LE wire; Horkos targets LE hosts). Each
// bounds-checks and returns a typed error rather than panicking.
// ---------------------------------------------------------------------------

fn read_u32(buf: &[u8], off: usize, what: &'static str) -> Result<u32, VmAccessError> {
    let end = off + 4;
    if buf.len() < end {
        return Err(VmAccessError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 4];
    a.copy_from_slice(&buf[off..end]);
    Ok(u32::from_le_bytes(a))
}

fn read_u64(buf: &[u8], off: usize, what: &'static str) -> Result<u64, VmAccessError> {
    let end = off + 8;
    if buf.len() < end {
        return Err(VmAccessError::Short {
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
// `#[repr(C)]` mirrors of the wire payloads. Field names/sizes track the
// kernel-private mirrors in kernel/win/include/horkos_kernel.h exactly (32/24/12/24;
// the u64 members force an explicit tail-pad u32 on the vm_access/protect_drift structs).
// ---------------------------------------------------------------------------

/// Mirror of `hk_event_vm_access` (32 bytes). The named fields sum to 28, but the
/// u64 `target_va` forces 8-byte alignment; the C struct makes the tail pad an
/// explicit `reserved` u32 (size 32), mirrored here so the `#[repr(C)]` layout and
/// the C `HK_STATIC_ASSERT` agree exactly.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmAccess {
    pub source_pid: u32,
    pub target_pid: u32,
    pub target_va: u64,
    pub access_kind: u32,
    pub target_section_flags: u32,
    pub flags: u32,
    pub reserved: u32,
}

/// Mirror of `hk_event_handle_provenance` (24 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleProvenance {
    pub requester_pid: u32,
    pub source_pid: u32,
    pub target_pid: u32,
    pub original_desired_access: u32,
    pub granted_access: u32,
    pub flags: u32,
}

/// Mirror of `hk_event_foreign_holder` (12 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForeignHolder {
    pub owner_pid: u32,
    pub granted_access: u32,
    pub flags: u32,
}

/// Mirror of `hk_event_protect_drift` (24 bytes). The named fields sum to 20, but
/// the leading u64 `region_base` forces 8-byte alignment; the C struct makes the
/// tail pad an explicit `reserved` u32 (size 24), mirrored here.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectDrift {
    pub region_base: u64,
    pub live_protect: u32,
    pub expected_protect: u32,
    pub flags: u32,
    pub reserved: u32,
}

// Compile-time size pins mirroring the C HK_STATIC_ASSERTs (32/24/12/24).
const _: () = assert!(core::mem::size_of::<VmAccess>() == 32);
const _: () = assert!(core::mem::size_of::<HandleProvenance>() == 24);
const _: () = assert!(core::mem::size_of::<ForeignHolder>() == 12);
const _: () = assert!(core::mem::size_of::<ProtectDrift>() == 24);

impl VmAccess {
    pub fn decode(buf: &[u8]) -> Result<Self, VmAccessError> {
        Ok(Self {
            source_pid: read_u32(buf, 0, "vm_access.source_pid")?,
            target_pid: read_u32(buf, 4, "vm_access.target_pid")?,
            target_va: read_u64(buf, 8, "vm_access.target_va")?,
            access_kind: read_u32(buf, 16, "vm_access.access_kind")?,
            target_section_flags: read_u32(buf, 20, "vm_access.target_section_flags")?,
            flags: read_u32(buf, 24, "vm_access.flags")?,
            reserved: read_u32(buf, 28, "vm_access.reserved")?,
        })
    }
}

impl HandleProvenance {
    pub fn decode(buf: &[u8]) -> Result<Self, VmAccessError> {
        Ok(Self {
            requester_pid: read_u32(buf, 0, "handle_provenance.requester_pid")?,
            source_pid: read_u32(buf, 4, "handle_provenance.source_pid")?,
            target_pid: read_u32(buf, 8, "handle_provenance.target_pid")?,
            original_desired_access: read_u32(
                buf,
                12,
                "handle_provenance.original_desired_access",
            )?,
            granted_access: read_u32(buf, 16, "handle_provenance.granted_access")?,
            flags: read_u32(buf, 20, "handle_provenance.flags")?,
        })
    }
}

impl ForeignHolder {
    pub fn decode(buf: &[u8]) -> Result<Self, VmAccessError> {
        Ok(Self {
            owner_pid: read_u32(buf, 0, "foreign_holder.owner_pid")?,
            granted_access: read_u32(buf, 4, "foreign_holder.granted_access")?,
            flags: read_u32(buf, 8, "foreign_holder.flags")?,
        })
    }
}

impl ProtectDrift {
    pub fn decode(buf: &[u8]) -> Result<Self, VmAccessError> {
        Ok(Self {
            region_base: read_u64(buf, 0, "protect_drift.region_base")?,
            live_protect: read_u32(buf, 8, "protect_drift.live_protect")?,
            expected_protect: read_u32(buf, 12, "protect_drift.expected_protect")?,
            flags: read_u32(buf, 16, "protect_drift.flags")?,
            reserved: read_u32(buf, 20, "protect_drift.reserved")?,
        })
    }
}

/// A decoded VM-access payload, tagged by wire type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmAccessEvent {
    Vm(VmAccess),
    Provenance(HandleProvenance),
    Holder(ForeignHolder),
    Drift(ProtectDrift),
}

/// Decode one payload buffer given its wire event type. Unknown types yield a typed
/// error (the caller already degrades unknown types gracefully; this lets the
/// VM-access decoder be used standalone in tests).
pub fn decode_event(event_type: u32, payload: &[u8]) -> Result<VmAccessEvent, VmAccessError> {
    match event_type {
        HK_EVENT_VM_ACCESS => Ok(VmAccessEvent::Vm(VmAccess::decode(payload)?)),
        HK_EVENT_HANDLE_PROVENANCE => Ok(VmAccessEvent::Provenance(HandleProvenance::decode(
            payload,
        )?)),
        HK_EVENT_FOREIGN_HOLDER => Ok(VmAccessEvent::Holder(ForeignHolder::decode(payload)?)),
        HK_EVENT_PROTECT_DRIFT => Ok(VmAccessEvent::Drift(ProtectDrift::decode(payload)?)),
        other => Err(VmAccessError::UnknownType(other)),
    }
}

// ---------------------------------------------------------------------------
// Feature extraction. Pure, allocation-free; the ban-engine consumes these as
// ONNX features. No thresholding/ban here — the model decides.
// ---------------------------------------------------------------------------

/// Normalized features handed to the ban-engine's model. Booleans are derived
/// evidence, not verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VmAccessFeatures {
    /// Cross-process (remote) operation against the protected pid.
    pub remote: bool,
    /// A write/alloc/protect touched an executable shipped section (code write).
    pub touches_executable_code: bool,
    /// A full alloc->protect->write staging triad completed (#72).
    pub staging_sequence: bool,
    /// A residency burst had no matching ReadVm (#69 correlation).
    pub etwti_silent: bool,
    /// A DuplicateHandle chain whose root opener never appeared (#66).
    pub dup_laundered: bool,
    /// Post-op granted access exceeded the pre-op requested mask (#67).
    pub grant_exceeds_preop: bool,
    /// A foreign holder with VM read/write/operation rights (#70).
    pub dangerous_holder: bool,
    /// That foreign holder's owning image is unsigned (#70 weight-up).
    pub unsigned_holder: bool,
    /// Live RWX on a shipped read-only-exec section (#71).
    pub wx_on_shipped: bool,
    /// The page-protect drift correlated to a foreign ProtectVm (#71).
    pub foreign_protect: bool,
}

impl VmAccess {
    pub fn features(&self) -> VmAccessFeatures {
        let writes_or_changes =
            (self.access_kind & (HK_VM_WRITE | HK_VM_ALLOC | HK_VM_PROTECT)) != 0;
        VmAccessFeatures {
            remote: (self.flags & HK_VM_REMOTE) != 0,
            touches_executable_code: writes_or_changes
                && (self.target_section_flags & IMAGE_SCN_MEM_EXECUTE) != 0,
            staging_sequence: (self.flags & HK_VM_STAGING_SEQ) != 0,
            etwti_silent: (self.flags & HK_VM_ETWTI_SILENT) != 0,
            ..Default::default()
        }
    }
}

impl HandleProvenance {
    pub fn features(&self) -> VmAccessFeatures {
        VmAccessFeatures {
            dup_laundered: (self.flags & HK_HND_DUP_LAUNDERED) != 0,
            grant_exceeds_preop: (self.flags & HK_HND_GRANT_EXCEEDS_PREOP) != 0,
            ..Default::default()
        }
    }
}

impl ForeignHolder {
    pub fn features(&self) -> VmAccessFeatures {
        VmAccessFeatures {
            dangerous_holder: (self.flags & HK_HND_DANGEROUS_RIGHTS) != 0,
            unsigned_holder: (self.flags & HK_HND_UNSIGNED_OWNER) != 0,
            ..Default::default()
        }
    }
}

impl ProtectDrift {
    pub fn features(&self) -> VmAccessFeatures {
        VmAccessFeatures {
            wx_on_shipped: (self.flags & HK_PROT_WX_ON_SHIPPED) != 0,
            foreign_protect: (self.flags & HK_PROT_FOREIGN_INITIATED) != 0,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_vm_access(v: &VmAccess) -> Vec<u8> {
        let mut b = Vec::with_capacity(28);
        b.extend_from_slice(&v.source_pid.to_le_bytes());
        b.extend_from_slice(&v.target_pid.to_le_bytes());
        b.extend_from_slice(&v.target_va.to_le_bytes());
        b.extend_from_slice(&v.access_kind.to_le_bytes());
        b.extend_from_slice(&v.target_section_flags.to_le_bytes());
        b.extend_from_slice(&v.flags.to_le_bytes());
        b.extend_from_slice(&v.reserved.to_le_bytes());
        b
    }

    fn encode_provenance(p: &HandleProvenance) -> Vec<u8> {
        let mut b = Vec::with_capacity(24);
        b.extend_from_slice(&p.requester_pid.to_le_bytes());
        b.extend_from_slice(&p.source_pid.to_le_bytes());
        b.extend_from_slice(&p.target_pid.to_le_bytes());
        b.extend_from_slice(&p.original_desired_access.to_le_bytes());
        b.extend_from_slice(&p.granted_access.to_le_bytes());
        b.extend_from_slice(&p.flags.to_le_bytes());
        b
    }

    #[test]
    fn vm_access_round_trip_and_code_write() {
        let v = VmAccess {
            source_pid: 0x1111,
            target_pid: 0x2222,
            target_va: 0x7FFF_DEAD_0000,
            access_kind: HK_VM_WRITE,
            target_section_flags: IMAGE_SCN_MEM_EXECUTE,
            flags: HK_VM_REMOTE,
            reserved: 0,
        };
        let bytes = encode_vm_access(&v);
        assert_eq!(bytes.len(), 32);
        let decoded = VmAccess::decode(&bytes).expect("decode");
        assert_eq!(decoded, v);
        let f = decoded.features();
        assert!(f.remote);
        assert!(f.touches_executable_code); // remote write into a +X section
    }

    #[test]
    fn read_of_data_section_is_not_code_write() {
        let v = VmAccess {
            source_pid: 1,
            target_pid: 2,
            target_va: 0x4000_0000,
            access_kind: HK_VM_READ,
            target_section_flags: 0, // not in a tracked module section
            flags: HK_VM_REMOTE,
            reserved: 0,
        };
        let f = v.features();
        assert!(f.remote);
        assert!(!f.touches_executable_code); // a read, and not in a +X section
    }

    #[test]
    fn dup_laundered_provenance() {
        let p = HandleProvenance {
            requester_pid: 50,
            source_pid: 99,
            target_pid: 7,
            original_desired_access: 0x10,
            granted_access: 0x10,
            flags: HK_HND_DUP_LAUNDERED,
        };
        let bytes = encode_provenance(&p);
        assert_eq!(bytes.len(), 24);
        let decoded = HandleProvenance::decode(&bytes).expect("decode");
        assert_eq!(decoded, p);
        assert!(decoded.features().dup_laundered);
        assert!(!decoded.features().grant_exceeds_preop);
    }

    #[test]
    fn foreign_holder_features() {
        let h = ForeignHolder {
            owner_pid: 1234,
            granted_access: 0x0010, // PROCESS_VM_READ
            flags: HK_HND_DANGEROUS_RIGHTS | HK_HND_UNSIGNED_OWNER,
        };
        let f = h.features();
        assert!(f.dangerous_holder);
        assert!(f.unsigned_holder);
    }

    #[test]
    fn protect_drift_features() {
        let d = ProtectDrift {
            region_base: 0x1_4000_1000,
            live_protect: 0x40, // PAGE_EXECUTE_READWRITE
            expected_protect: 0x20,
            flags: HK_PROT_WX_ON_SHIPPED | HK_PROT_FOREIGN_INITIATED,
            reserved: 0,
        };
        let f = d.features();
        assert!(f.wx_on_shipped);
        assert!(f.foreign_protect);
    }

    #[test]
    fn short_buffer_is_typed_error_not_panic() {
        let short = [0u8; 10];
        let err = VmAccess::decode(&short).expect_err("must be Short");
        match err {
            VmAccessError::Short { got, .. } => assert_eq!(got, 10),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn unknown_type_is_typed_error() {
        let err = decode_event(99, &[0u8; 32]).expect_err("unknown");
        assert_eq!(err, VmAccessError::UnknownType(99));
    }

    #[test]
    fn decode_event_dispatches_by_type() {
        let v = VmAccess {
            source_pid: 3,
            target_pid: 4,
            target_va: 0,
            access_kind: HK_VM_ALLOC,
            target_section_flags: 0,
            flags: 0,
            reserved: 0,
        };
        let bytes = encode_vm_access(&v);
        match decode_event(HK_EVENT_VM_ACCESS, &bytes).expect("decode") {
            VmAccessEvent::Vm(d) => assert_eq!(d.source_pid, 3),
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
