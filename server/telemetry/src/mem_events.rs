//! Role: Server-side decode + bounds-validation for the Windows kernel
//! memory/image-anomaly event records (win-kernel-memory-injection, signals
//! 10-18): unbacked executable region (`hk_mem_region`), W^X divergence
//! (`hk_event_mem_wx`), module stomp (`hk_event_mem_module_stomp`), ghost/hollow
//! image (`hk_event_mem_image_anomaly`), exec-origin anon
//! (`hk_event_mem_exec_origin`), and unsigned image (`hk_event_mem_unsigned_image`).
//! Decodes the large-record drain byte stream (ioctl.h `hk_event_mem_record`)
//! into normalized owned values, bounds-checking every variable-length field
//! (`*_len`) before slicing. This module extracts evidence only — it NEVER bans
//! (that authority is the ban-engine's, server-side). The client/kernel ships raw
//! observations; the server fuses and decides.
//!
//! Target platforms: server.
//!
//! Guardrail #8: pure, no blocking, `thiserror` error type, NO `unwrap()`/
//! `expect()` outside `#[cfg(test)]`. A short record or an out-of-range `*_len`
//! yields a typed `MemEventError`, never a panic.
//!
//! HK-TODO(schema): the memory-event discriminants (`HK_EVENT_MEM_UNBACKED_EXEC`
//! = 5 .. `HK_EVENT_MEM_UNSIGNED_IMAGE` = 13) are landed in the frozen
//! `sdk/include/horkos/event_schema.h` (schema v3) by this domain — the first
//! concrete claim past `HK_EVENT_HANDLE_OPEN` = 4. The provisional Rust mirrors in
//! `kernel_events.rs` (linux-module-integrity, values 5..14) and the vm-access /
//! memory-access provisional discriminants were always documented as rebasing onto
//! the resolved values once the Schema phase landed; this IS that landing for the
//! memory-injection block. Those domains must rebase onto the next free
//! discriminant range, and the server must dispatch by the resolved type. Tracked
//! by the repo-wide schema-reconciliation pass (the HK-TODO(schema) sites).

use thiserror::Error;

/// Memory-event mirror version — tracks `HK_EVENT_SCHEMA_VERSION` (3) for the
/// memory/image-anomaly family.
pub const MEM_EVENT_MIRROR_VERSION: u32 = 3;

// ---- event-type discriminants (mirror event_schema.h hk_event_type) --------
pub const HK_EVENT_MEM_UNBACKED_EXEC: u32 = 5;
pub const HK_EVENT_MEM_WX_DIVERGENCE: u32 = 6;
pub const HK_EVENT_MEM_MODULE_STOMP: u32 = 7;
pub const HK_EVENT_MEM_GHOST_IMAGE: u32 = 8;
pub const HK_EVENT_MEM_PRIV_EXEC_COMMIT: u32 = 9;
pub const HK_EVENT_MEM_EXOTIC_VAD: u32 = 10;
pub const HK_EVENT_MEM_HOLLOW_BACKING: u32 = 11;
pub const HK_EVENT_MEM_EXEC_ORIGIN_ANON: u32 = 12;
pub const HK_EVENT_MEM_UNSIGNED_IMAGE: u32 = 13;

// ---- fixed wire sizes (mirror the event_schema.h HK_STATIC_ASSERTs) --------
const SZ_REGION: usize = 32;
const SZ_WX: usize = 40;
const SZ_MODULE_STOMP: usize = 304;
const SZ_IMAGE_ANOMALY: usize = 232;
const SZ_EXEC_ORIGIN: usize = 24;
const SZ_UNSIGNED_IMAGE: usize = 264;

/// Max bytes in the variable-length path/name buffers (mirror the C arrays).
const PATH_CAP: usize = 208;
const SECTION_NAME_CAP: usize = 8;

/// signer_verdict enum (mirror event_schema.h HK_SIGN_*).
pub const HK_SIGN_UNKNOWN: u32 = 0;
pub const HK_SIGN_TRUSTED: u32 = 4;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MemEventError {
    /// The record buffer is shorter than the fixed wire size.
    #[error("{what} record short: need {need}, got {got}")]
    Short {
        what: &'static str,
        need: usize,
        got: usize,
    },
    /// A variable-length field declared a length beyond its fixed capacity.
    #[error("{what} length {len} exceeds capacity {cap}")]
    LenOutOfRange {
        what: &'static str,
        len: usize,
        cap: usize,
    },
}

impl From<MemEventError> for crate::error::TelemetryError {
    fn from(e: MemEventError) -> Self {
        crate::error::TelemetryError::MemEvent(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Little-endian fixed-width readers (LE wire; Horkos targets LE hosts).
// ---------------------------------------------------------------------------

fn read_u16(buf: &[u8], off: usize) -> u16 {
    // Callers validate buf.len() >= the fixed record size before calling, so the
    // slice is always in range; the explicit bound keeps it panic-free regardless.
    let mut a = [0u8; 2];
    a.copy_from_slice(&buf[off..off + 2]);
    u16::from_le_bytes(a)
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&buf[off..off + 4]);
    u32::from_le_bytes(a)
}

fn read_u64(buf: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(a)
}

fn ensure_len(buf: &[u8], need: usize, what: &'static str) -> Result<(), MemEventError> {
    if buf.len() < need {
        return Err(MemEventError::Short {
            what,
            need,
            got: buf.len(),
        });
    }
    Ok(())
}

/// A UTF-8 path extracted from a fixed wire buffer, with the declared length
/// validated against the buffer capacity. Lossy UTF-8 (the kernel ships a
/// truncated UTF-16->UTF-8 path; we never trust it to be valid UTF-8).
fn extract_path(
    buf: &[u8],
    field_off: usize,
    len: usize,
    cap: usize,
    what: &'static str,
) -> Result<String, MemEventError> {
    if len > cap {
        return Err(MemEventError::LenOutOfRange { what, len, cap });
    }
    Ok(String::from_utf8_lossy(&buf[field_off..field_off + len]).into_owned())
}

// ---------------------------------------------------------------------------
// Decoded owned records.
// ---------------------------------------------------------------------------

/// `hk_mem_region` (signals 10/14/15 — UNBACKED_EXEC / PRIV_EXEC_COMMIT / EXOTIC_VAD).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemRegion {
    pub pid: u32,
    pub vad_type: u32,
    pub region_base: u64,
    pub region_size: u64,
    pub protection: u32,
    pub flags: u32,
}

impl MemRegion {
    pub fn decode(buf: &[u8]) -> Result<Self, MemEventError> {
        ensure_len(buf, SZ_REGION, "mem_region")?;
        Ok(Self {
            pid: read_u32(buf, 0),
            vad_type: read_u32(buf, 4),
            region_base: read_u64(buf, 8),
            region_size: read_u64(buf, 16),
            protection: read_u32(buf, 24),
            flags: read_u32(buf, 28),
        })
    }
}

/// `hk_event_mem_wx` (signal 11 — W^X divergence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemWx {
    pub region: MemRegion,
    pub vad_says_exec: u32,
    pub pte_says_exec: u32,
}

impl MemWx {
    pub fn decode(buf: &[u8]) -> Result<Self, MemEventError> {
        ensure_len(buf, SZ_WX, "mem_wx")?;
        Ok(Self {
            region: MemRegion::decode(&buf[0..SZ_REGION])?,
            vad_says_exec: read_u32(buf, 32),
            pte_says_exec: read_u32(buf, 36),
        })
    }
}

/// `hk_event_mem_module_stomp` (signal 12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleStomp {
    pub pid: u32,
    pub first_diff_rva: u32,
    pub image_base: u64,
    pub live_section_sha256: [u8; 32],
    pub disk_section_sha256: [u8; 32],
    pub module_path: String,
    pub section_name: String,
}

impl ModuleStomp {
    pub fn decode(buf: &[u8]) -> Result<Self, MemEventError> {
        ensure_len(buf, SZ_MODULE_STOMP, "module_stomp")?;
        let module_path_len = read_u16(buf, 80) as usize;
        let section_name_len = read_u16(buf, 82) as usize;
        let mut live = [0u8; 32];
        let mut disk = [0u8; 32];
        live.copy_from_slice(&buf[16..48]);
        disk.copy_from_slice(&buf[48..80]);
        Ok(Self {
            pid: read_u32(buf, 0),
            first_diff_rva: read_u32(buf, 4),
            image_base: read_u64(buf, 8),
            live_section_sha256: live,
            disk_section_sha256: disk,
            module_path: extract_path(buf, 84, module_path_len, PATH_CAP, "module_path")?,
            section_name: extract_path(
                buf,
                292,
                section_name_len,
                SECTION_NAME_CAP,
                "section_name",
            )?,
        })
    }
}

/// `hk_event_mem_image_anomaly` (signals 13 ghost + 16 hollow).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageAnomaly {
    pub pid: u32,
    pub flags: u32,
    pub image_base: u64,
    pub path: String,
}

impl ImageAnomaly {
    pub fn decode(buf: &[u8]) -> Result<Self, MemEventError> {
        ensure_len(buf, SZ_IMAGE_ANOMALY, "image_anomaly")?;
        let path_len = read_u16(buf, 16) as usize;
        Ok(Self {
            pid: read_u32(buf, 0),
            flags: read_u32(buf, 4),
            image_base: read_u64(buf, 8),
            path: extract_path(buf, 20, path_len, PATH_CAP, "image_path")?,
        })
    }
}

/// `hk_event_mem_exec_origin` (signal 17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOrigin {
    pub pid: u32,
    pub thread_id: u32,
    pub start_address: u64,
    pub resolved_vad_type: u32,
    pub flags: u32,
}

impl ExecOrigin {
    pub fn decode(buf: &[u8]) -> Result<Self, MemEventError> {
        ensure_len(buf, SZ_EXEC_ORIGIN, "exec_origin")?;
        Ok(Self {
            pid: read_u32(buf, 0),
            thread_id: read_u32(buf, 4),
            start_address: read_u64(buf, 8),
            resolved_vad_type: read_u32(buf, 16),
            flags: read_u32(buf, 20),
        })
    }
}

/// `hk_event_mem_unsigned_image` (signal 18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedImage {
    pub pid: u32,
    pub signer_verdict: u32,
    pub image_base: u64,
    pub file_sha256: [u8; 32],
    pub file_path: String,
}

impl UnsignedImage {
    pub fn decode(buf: &[u8]) -> Result<Self, MemEventError> {
        ensure_len(buf, SZ_UNSIGNED_IMAGE, "unsigned_image")?;
        let path_len = read_u16(buf, 48) as usize;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&buf[16..48]);
        Ok(Self {
            pid: read_u32(buf, 0),
            signer_verdict: read_u32(buf, 4),
            image_base: read_u64(buf, 8),
            file_sha256: hash,
            file_path: extract_path(buf, 52, path_len, PATH_CAP, "file_path")?,
        })
    }
}
