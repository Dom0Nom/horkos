//! Role: Server-side decode + correlation for the client self-integrity events
//! (memory-integrity-selfcheck, catalog signals 145-153). Mirrors the `hk_event_self_*`
//! wire structs (`#[repr(C)]` over the C99 layout in `ac/src/selfcheck/self_wire.h`),
//! decodes the drained byte stream with bounds checks, joins the three cross-views
//! (145), and applies the FP gates that the catalog places server-side: 147/149/150
//! alert ONLY when correlated with a concurrent signature failure; the signed-overlay
//! allow-list keys on the patched RVA + trampoline target. This module extracts
//! evidence + correlation only — the ban authority is the ban-engine's, server-side.
//!
//! Target platforms: server.
//!
//! Guardrail #8: pure / async-compatible (no blocking, no I/O — heavy SHA-256 compares
//! belong on `spawn_blocking` at the call site), `thiserror` error type, NO
//! `unwrap()`/`expect()` outside `#[cfg(test)]`. A malformed/short record or a hostile
//! length field yields a typed `SelfEventError`, never a panic.
//!
//! Schema: the event types (`HK_EVENT_SELF_CROSSVIEW` = 29 .. = 37) are now FROZEN
//! in `sdk/include/horkos/event_schema.h` (schema v6) — renumbered from the old
//! provisional 14..22, which collided with the HV (14..17) and create-ex (18)
//! ranges. The `hk_event_self_*` payload structs are large (120/144 bytes) and
//! still ride the large-record drain plane (`HK_EVENT_MEM_PAYLOAD_MAX` /
//! `HK_IOCTL_DRAIN_MEM_EVENTS`), whose self-record transport is HK-TODO(schema)
//! kernel-side work. The decoders below mirror the frozen discriminants.

use thiserror::Error;

/// Event-type discriminants. FROZEN in `hk_event_type` (event_schema.h) as types
/// 29..37 (schema v6); mirror exactly.
pub const HK_EVENT_SELF_CROSSVIEW: u32 = 29;
pub const HK_EVENT_SELF_PAGE_COW: u32 = 30;
pub const HK_EVENT_SELF_RETADDR: u32 = 31;
pub const HK_EVENT_SELF_HWBP: u32 = 32;
pub const HK_EVENT_SELF_IAT_TARGET: u32 = 33;
pub const HK_EVENT_SELF_VEH_UNWIND: u32 = 34;
pub const HK_EVENT_SELF_LOADER: u32 = 35;
pub const HK_EVENT_SELF_WX_DRIFT: u32 = 36;
pub const HK_EVENT_SELF_TLS_INIT: u32 = 37;

/// `match_matrix` bits (set = the two views AGREE).
pub const HK_SELF_MATCH_INPROC_KERNEL: u32 = 1 << 0;
pub const HK_SELF_MATCH_KERNEL_DISK: u32 = 1 << 1;
pub const HK_SELF_MATCH_INPROC_DISK: u32 = 1 << 2;

/// `target_flags` bits (signal 149).
pub const HK_SELF_TGT_PRIVATE: u32 = 1 << 0;
pub const HK_SELF_TGT_UNSIGNED: u32 = 1 << 1;
pub const HK_SELF_TGT_WRONG_MODULE: u32 = 1 << 2;
pub const HK_SELF_TGT_DISPLACED: u32 = 1 << 3;
pub const HK_SELF_TGT_FORWARDER: u32 = 1 << 4;

/// Bounded frame array length (mirror of `HK_SELF_MAX_FRAMES`). A wire `frame_count`
/// above this is rejected as malformed, never trusted as a slice length.
pub const HK_SELF_MAX_FRAMES: usize = 16;
/// `unsigned_frame_idx` sentinel (no unsigned frame).
pub const HK_SELF_FRAME_NONE: u16 = 0xFFFF;

/// Decode / correlation errors. A short or otherwise malformed drained record must
/// surface as one of these — never a panic (guardrail #8).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SelfEventError {
    #[error("record too short: need {need} bytes for {what}, got {got}")]
    Short {
        what: &'static str,
        need: usize,
        got: usize,
    },

    #[error("field {what} out of range: {value} exceeds max {max}")]
    OutOfRange {
        what: &'static str,
        value: u64,
        max: u64,
    },

    #[error("unknown self-event type {0}")]
    UnknownType(u32),
}

// ---------------------------------------------------------------------------
// Little-endian fixed-width readers. Each bounds-checks and returns a typed error.
// ---------------------------------------------------------------------------

fn read_u32(buf: &[u8], off: usize, what: &'static str) -> Result<u32, SelfEventError> {
    let end = off + 4;
    if buf.len() < end {
        return Err(SelfEventError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 4];
    a.copy_from_slice(&buf[off..end]);
    Ok(u32::from_le_bytes(a))
}

fn read_u16(buf: &[u8], off: usize, what: &'static str) -> Result<u16, SelfEventError> {
    let end = off + 2;
    if buf.len() < end {
        return Err(SelfEventError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 2];
    a.copy_from_slice(&buf[off..end]);
    Ok(u16::from_le_bytes(a))
}

fn read_u64(buf: &[u8], off: usize, what: &'static str) -> Result<u64, SelfEventError> {
    let end = off + 8;
    if buf.len() < end {
        return Err(SelfEventError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&buf[off..end]);
    Ok(u64::from_le_bytes(a))
}

fn read_hash32(buf: &[u8], off: usize, what: &'static str) -> Result<[u8; 32], SelfEventError> {
    let end = off + 32;
    if buf.len() < end {
        return Err(SelfEventError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&buf[off..end]);
    Ok(a)
}

// ---------------------------------------------------------------------------
// `#[repr(C)]` wire mirrors. Field names/sizes track ac/src/selfcheck/self_wire.h.
// ---------------------------------------------------------------------------

/// Mirror of `hk_event_self_crossview` (120 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfCrossView {
    pub pid: u32,
    pub section_rva: u32,
    pub image_base: u64,
    pub hash_inproc: [u8; 32],
    pub hash_kernel: [u8; 32],
    pub hash_disk: [u8; 32],
    pub match_matrix: u32,
    pub first_diff_rva: u32,
}

/// Mirror of `hk_event_self_page_cow` (32 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfPageCow {
    pub pid: u32,
    pub page_count: u32,
    pub image_base: u64,
    pub region_base: u64,
    pub private_pages: u32,
    pub dirty_pages: u32,
}

/// Mirror of `hk_event_self_retaddr` (144 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfRetAddr {
    pub pid: u32,
    pub guarded_fn_id: u32,
    pub frames: [u64; HK_SELF_MAX_FRAMES],
    pub frame_count: u16,
    pub unsigned_frame_idx: u16,
    pub shadow_stack_mismatch: u32,
}

/// Mirror of `hk_event_self_hwbp` (48 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfHwBp {
    pub pid: u32,
    pub thread_id: u32,
    pub dr: [u64; 4],
    pub dr7: u32,
    pub dr_in_text_mask: u32,
}

/// Mirror of `hk_event_self_iat_target` (32 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfIatTarget {
    pub pid: u32,
    pub slot_rva: u32,
    pub slot_target_va: u64,
    pub expected_va: u64,
    pub target_flags: u32,
    pub import_class: u32,
}

/// Mirror of `hk_event_self_compat` (48 bytes) — shared by 150/151/152/153.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfCompat {
    pub pid: u32,
    pub signal_id: u32,
    pub image_base: u64,
    pub table_rva: u64,
    pub expected_va: u64,
    pub actual_va: u64,
    pub flags: u32,
    pub reserved: u32,
}

// Compile-time size pins mirroring the C HK_STATIC_ASSERTs.
const _: () = assert!(core::mem::size_of::<SelfCrossView>() == 120);
const _: () = assert!(core::mem::size_of::<SelfPageCow>() == 32);
const _: () = assert!(core::mem::size_of::<SelfRetAddr>() == 144);
const _: () = assert!(core::mem::size_of::<SelfHwBp>() == 48);
const _: () = assert!(core::mem::size_of::<SelfIatTarget>() == 32);
const _: () = assert!(core::mem::size_of::<SelfCompat>() == 48);

impl SelfCrossView {
    pub fn decode(buf: &[u8]) -> Result<Self, SelfEventError> {
        Ok(Self {
            pid: read_u32(buf, 0, "crossview.pid")?,
            section_rva: read_u32(buf, 4, "crossview.section_rva")?,
            image_base: read_u64(buf, 8, "crossview.image_base")?,
            hash_inproc: read_hash32(buf, 16, "crossview.hash_inproc")?,
            hash_kernel: read_hash32(buf, 48, "crossview.hash_kernel")?,
            hash_disk: read_hash32(buf, 80, "crossview.hash_disk")?,
            match_matrix: read_u32(buf, 112, "crossview.match_matrix")?,
            first_diff_rva: read_u32(buf, 116, "crossview.first_diff_rva")?,
        })
    }
}

impl SelfPageCow {
    pub fn decode(buf: &[u8]) -> Result<Self, SelfEventError> {
        Ok(Self {
            pid: read_u32(buf, 0, "page_cow.pid")?,
            page_count: read_u32(buf, 4, "page_cow.page_count")?,
            image_base: read_u64(buf, 8, "page_cow.image_base")?,
            region_base: read_u64(buf, 16, "page_cow.region_base")?,
            private_pages: read_u32(buf, 24, "page_cow.private_pages")?,
            dirty_pages: read_u32(buf, 28, "page_cow.dirty_pages")?,
        })
    }
}

impl SelfRetAddr {
    pub fn decode(buf: &[u8]) -> Result<Self, SelfEventError> {
        let mut frames = [0u64; HK_SELF_MAX_FRAMES];
        for (i, slot) in frames.iter_mut().enumerate() {
            *slot = read_u64(buf, 8 + i * 8, "retaddr.frames")?;
        }
        let frame_count = read_u16(buf, 8 + HK_SELF_MAX_FRAMES * 8, "retaddr.frame_count")?;
        // A hostile frame_count above the bounded array is malformed — reject, never
        // use it to index/slice (guardrail #8: malicious length errors, not panics).
        if frame_count as usize > HK_SELF_MAX_FRAMES {
            return Err(SelfEventError::OutOfRange {
                what: "retaddr.frame_count",
                value: frame_count as u64,
                max: HK_SELF_MAX_FRAMES as u64,
            });
        }
        Ok(Self {
            pid: read_u32(buf, 0, "retaddr.pid")?,
            guarded_fn_id: read_u32(buf, 4, "retaddr.guarded_fn_id")?,
            frames,
            frame_count,
            unsigned_frame_idx: read_u16(
                buf,
                10 + HK_SELF_MAX_FRAMES * 8,
                "retaddr.unsigned_frame_idx",
            )?,
            shadow_stack_mismatch: read_u32(
                buf,
                12 + HK_SELF_MAX_FRAMES * 8,
                "retaddr.shadow_stack_mismatch",
            )?,
        })
    }
}

impl SelfHwBp {
    pub fn decode(buf: &[u8]) -> Result<Self, SelfEventError> {
        Ok(Self {
            pid: read_u32(buf, 0, "hwbp.pid")?,
            thread_id: read_u32(buf, 4, "hwbp.thread_id")?,
            dr: [
                read_u64(buf, 8, "hwbp.dr0")?,
                read_u64(buf, 16, "hwbp.dr1")?,
                read_u64(buf, 24, "hwbp.dr2")?,
                read_u64(buf, 32, "hwbp.dr3")?,
            ],
            dr7: read_u32(buf, 40, "hwbp.dr7")?,
            dr_in_text_mask: read_u32(buf, 44, "hwbp.dr_in_text_mask")?,
        })
    }
}

impl SelfIatTarget {
    pub fn decode(buf: &[u8]) -> Result<Self, SelfEventError> {
        Ok(Self {
            pid: read_u32(buf, 0, "iat.pid")?,
            slot_rva: read_u32(buf, 4, "iat.slot_rva")?,
            slot_target_va: read_u64(buf, 8, "iat.slot_target_va")?,
            expected_va: read_u64(buf, 16, "iat.expected_va")?,
            target_flags: read_u32(buf, 24, "iat.target_flags")?,
            import_class: read_u32(buf, 28, "iat.import_class")?,
        })
    }
}

impl SelfCompat {
    pub fn decode(buf: &[u8]) -> Result<Self, SelfEventError> {
        Ok(Self {
            pid: read_u32(buf, 0, "compat.pid")?,
            signal_id: read_u32(buf, 4, "compat.signal_id")?,
            image_base: read_u64(buf, 8, "compat.image_base")?,
            table_rva: read_u64(buf, 16, "compat.table_rva")?,
            expected_va: read_u64(buf, 24, "compat.expected_va")?,
            actual_va: read_u64(buf, 32, "compat.actual_va")?,
            flags: read_u32(buf, 40, "compat.flags")?,
            reserved: read_u32(buf, 44, "compat.reserved")?,
        })
    }
}

/// A decoded self-integrity payload, tagged by wire type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfEvent {
    CrossView(SelfCrossView),
    PageCow(SelfPageCow),
    RetAddr(SelfRetAddr),
    HwBp(SelfHwBp),
    IatTarget(SelfIatTarget),
    Compat(SelfCompat),
}

/// Decode one payload buffer given its wire event type.
pub fn decode_event(event_type: u32, payload: &[u8]) -> Result<SelfEvent, SelfEventError> {
    match event_type {
        HK_EVENT_SELF_CROSSVIEW => Ok(SelfEvent::CrossView(SelfCrossView::decode(payload)?)),
        HK_EVENT_SELF_PAGE_COW => Ok(SelfEvent::PageCow(SelfPageCow::decode(payload)?)),
        HK_EVENT_SELF_RETADDR => Ok(SelfEvent::RetAddr(SelfRetAddr::decode(payload)?)),
        HK_EVENT_SELF_HWBP => Ok(SelfEvent::HwBp(SelfHwBp::decode(payload)?)),
        HK_EVENT_SELF_IAT_TARGET => Ok(SelfEvent::IatTarget(SelfIatTarget::decode(payload)?)),
        HK_EVENT_SELF_VEH_UNWIND
        | HK_EVENT_SELF_LOADER
        | HK_EVENT_SELF_WX_DRIFT
        | HK_EVENT_SELF_TLS_INIT => Ok(SelfEvent::Compat(SelfCompat::decode(payload)?)),
        other => Err(SelfEventError::UnknownType(other)),
    }
}

// ---------------------------------------------------------------------------
// Correlation. The catalog places these decisions server-side; the client only
// ships raw evidence. None of these BANS — they classify evidence for the ban-engine.
// ---------------------------------------------------------------------------

/// 145 cross-view classification. Mirrors the client-side `crossview_classify` but is
/// the authoritative server copy (the server never trusts the client's classification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossViewClass {
    AllAgree,
    /// in-process diverges while kernel==disk: a self-read-restoring inline patch.
    InlinePatch,
    /// kernel diverges while in-process==disk: the kernel sees a different page.
    KernelDiverge,
    /// no two agree — escalate as raw evidence.
    Inconsistent,
}

impl SelfCrossView {
    pub fn classify(&self) -> CrossViewClass {
        let ik = (self.match_matrix & HK_SELF_MATCH_INPROC_KERNEL) != 0;
        let kd = (self.match_matrix & HK_SELF_MATCH_KERNEL_DISK) != 0;
        let id = (self.match_matrix & HK_SELF_MATCH_INPROC_DISK) != 0;
        if ik && kd && id {
            CrossViewClass::AllAgree
        } else if kd && !ik && !id {
            CrossViewClass::InlinePatch
        } else if id && !ik && !kd {
            CrossViewClass::KernelDiverge
        } else {
            CrossViewClass::Inconsistent
        }
    }
}

/// FP gate for the high-FP signals (147/149/150). The catalog requires these to alert
/// ONLY when correlated with a concurrent signature failure (a 145 InlinePatch /
/// Inconsistent, or a 149 displaced/wrong-module/private flag). Returns whether the
/// evidence should be promoted to an alert; raw evidence is still stored regardless.
pub fn fp_gated_alert(signal_id: u32, has_concurrent_signature_failure: bool) -> bool {
    match signal_id {
        // 147 return-address, 149 IAT, 150 VEH/unwind: require corroboration.
        HK_EVENT_SELF_RETADDR | HK_EVENT_SELF_IAT_TARGET | HK_EVENT_SELF_VEH_UNWIND => {
            has_concurrent_signature_failure
        }
        // 145/146/148/151/152/153 stand on their own evidence (low-FP / authoritative
        // kernel-side reads); the ban-engine still weights them.
        _ => true,
    }
}

/// 149 forwarder suppression: a slot whose only flag is FORWARDER is benign and must
/// not promote (a documented export forwarder is not a hook).
pub fn iat_is_benign(target_flags: u32) -> bool {
    target_flags == 0 || target_flags == HK_SELF_TGT_FORWARDER
}
