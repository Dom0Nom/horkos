//! src/snapshot/ipc.rs
//!
//! Role: shm/mmap consumer bridging the game-server authoritative snapshot ring into
//! the async telemetry pipeline. Declares the `#[repr(C)]` Rust mirror of the C99
//! `HkSnapshotRecord` / `HkEntityState` / `HkVec3` / `HkOccluderVolume` frames in
//! `sdk/include/horkos/snapshot_schema.h` (with compile-time size asserts that fail
//! the build on any layout drift), and the safe parse that bound-checks
//! `entity_count`/`occluder_count` against the schema maxima before reading — a
//! torn/short/forged frame returns `TelemetryError::InvalidPayload` and is counted,
//! never panics (guardrail #8; shm trust boundary). The blocking shm syscalls live
//! on a dedicated std thread (see `SnapshotRingAttach` backends) feeding a bounded
//! `tokio::sync::mpsc`; nothing here blocks an async worker.
//!
//! Target platforms: server. The OS-specific attach is selected via `backends`
//! (guardrail #1 — no platform API in this module; the `cfg`-gated backends own it).

use crate::error::TelemetryError;
use crate::snapshot::Snapshot;

/// Mirrors `HK_SNAPSHOT_SCHEMA_VERSION`. Bump in lockstep with the C header.
pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;
/// Mirrors `HK_SNAP_MAX_ENTITIES`.
pub const SNAP_MAX_ENTITIES: usize = 256;
/// Mirrors `HK_SNAP_BITSET_WORDS` (`HK_SNAP_MAX_ENTITIES / 32`).
pub const SNAP_BITSET_WORDS: usize = SNAP_MAX_ENTITIES / 32;

// ---- Entity flags (mirror HK_ENT_*) ---------------------------------------
pub const ENT_ALIVE: u32 = 0x0000_0001;
pub const ENT_LOCAL: u32 = 0x0000_0002;
pub const ENT_TEAM: u32 = 0x0000_0004;

/// `#[repr(C)]` mirror of `HkVec3`. Field-for-field; size-pinned below.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HkVec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

/// `#[repr(C)]` mirror of `HkEntityState`. The trailing `_pad` keeps the struct a
/// clean 40 bytes and must be zero on the wire.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HkEntityState {
    pub entity_id: u64,
    pub position: HkVec3,
    pub velocity: HkVec3,
    pub flags: u32,
    pub _pad: u32,
}

/// `#[repr(C)]` mirror of `HkSnapshotRecord` (the fixed-size frame head + entities).
/// The variable-length occluder trailer is parsed separately from the bytes that
/// follow this struct in the ring slot, addressed by `occluder_count`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HkSnapshotRecord {
    pub schema_version: u32,
    pub entity_count: u32,
    pub tick: u64,
    pub mono_ns: u64,
    pub local_player_id: u64,
    pub cam_origin: HkVec3,
    pub cam_forward: HkVec3,
    pub cam_up: HkVec3,
    pub cam_fov_rad: f32,
    pub visibility_bits: [u32; SNAP_BITSET_WORDS],
    pub audiopath_bits: [u32; SNAP_BITSET_WORDS],
    pub occluder_count: u32,
    pub recoil_rng_vec: HkVec3,
    pub objective_seed: u64,
    pub entities: [HkEntityState; SNAP_MAX_ENTITIES],
}

/// `#[repr(C)]` mirror of `HkOccluderVolume` (the 175 dynamic-occluder trailer entry).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HkOccluderVolume {
    pub aabb_min: HkVec3,
    pub aabb_max: HkVec3,
    pub born_tick: u64,
    pub expire_tick: u64,
}

// Compile-time layout pins. These MUST match the HK_STATIC_ASSERTs in
// sdk/include/horkos/snapshot_schema.h or the build fails here (guardrail: the C
// header is the source of truth; a Rust-side drift is a hard error, not a runtime bug).
const _: () = assert!(core::mem::size_of::<HkVec3>() == 12);
const _: () = assert!(core::mem::size_of::<HkEntityState>() == 40);
const _: () = assert!(core::mem::size_of::<HkOccluderVolume>() == 40);
// Head (160) + 256 * 40 entities = 10400.
const _: () = assert!(core::mem::size_of::<HkSnapshotRecord>() == 160 + SNAP_MAX_ENTITIES * 40);

/// Minimum bytes a ring slot must hold to contain the fixed-size frame head.
pub const RECORD_HEAD_BYTES: usize = core::mem::size_of::<HkSnapshotRecord>();
/// Bytes per occluder trailer entry.
pub const OCCLUDER_BYTES: usize = core::mem::size_of::<HkOccluderVolume>();

/// Mirrors `HK_SNAP_RING_MAGIC` ('HKSP').
pub const SNAP_RING_MAGIC: u32 = 0x484B_5350;

/// `#[repr(C)]` mirror of `HkSnapshotSlotHeader` (per-slot seqlock + payload len).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HkSnapshotSlotHeader {
    pub seq: u64,
    pub payload_len: u32,
    pub _pad: u32,
}

/// `#[repr(C)]` mirror of `HkSnapshotRingHeader` (shm object header at offset 0).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HkSnapshotRingHeader {
    pub magic: u32,
    pub schema_version: u32,
    pub slot_count: u32,
    pub slot_stride: u32,
    pub write_seq: u64,
    pub _reserved: u64,
}

const _: () = assert!(core::mem::size_of::<HkSnapshotSlotHeader>() == 16);
const _: () = assert!(core::mem::size_of::<HkSnapshotRingHeader>() == 32);

/// Byte size of the ring-header prefix.
pub const RING_HEADER_BYTES: usize = core::mem::size_of::<HkSnapshotRingHeader>();
/// Byte size of the per-slot seqlock header.
pub const SLOT_HEADER_BYTES: usize = core::mem::size_of::<HkSnapshotSlotHeader>();

/// Backend-agnostic interface to attach a published snapshot ring. The two
/// implementations (`backends/posix.rs`, `backends/win.rs`) own the only platform
/// syscalls (guardrail #1) and are selected by `cfg`. A backend hands the reader a
/// readonly byte view of each ring slot; the parse below is platform-independent.
///
/// HK-UNCERTAIN(ipc-contract): the live shm ring protocol (slot count, the
/// publish/sequence handshake the game server uses, and whether a given engine
/// publishes server-side visibility/audio/RNG at all vs. requiring telemetry to
/// re-derive them) is NOT yet specified — see the impl-plan's first UNCERTAINTY
/// flag. The trait and parse below are the stable surface; the backends ship behind
/// the `gamestate-ipc-shm` feature and remain stubbed until the per-title integration
/// contract is fixed with the user. Do NOT wire a live ring to production without that.
pub trait SnapshotRingAttach: Send + Sized {
    /// Attach the named ring read-only.
    fn attach(name: &str) -> Result<Self, TelemetryError>;

    /// Copy the next published frame's payload into `buf`, returning `true` if a
    /// fresh, untorn frame was delivered (else `false` — no new frame, or every
    /// new generation was torn and skipped). Never blocks; never parses.
    fn next_frame(&mut self, buf: &mut Vec<u8>) -> Result<bool, TelemetryError>;
}

/// Volatile read of the ring header. SAFETY: `base` must point at a readable
/// mapping of at least `RING_HEADER_BYTES`, valid for the call's duration.
///
/// # Safety
/// See above — caller guarantees `base` is a live read-only mapping.
pub unsafe fn read_ring_header(base: *const u8) -> HkSnapshotRingHeader {
    core::ptr::read_volatile(base as *const HkSnapshotRingHeader)
}

/// Seqlock-read one slot's payload into `buf`. Returns `Ok(true)` on a stable
/// (even-sequence, unchanged-across-copy) frame, `Ok(false)` if the slot was
/// torn (producer mid-write or lapped). Bounds every read against `map_len`.
///
/// # Safety
/// `base` must point at a live read-only mapping of exactly `map_len` bytes for
/// the call's duration; `slot_stride`/`slot_count` are the validated ring
/// geometry. The function never forms a `&[u8]` over the live mapping; it reads
/// the seqlock words volatile and copies the payload with `copy_nonoverlapping`,
/// with acquire fences around the copy so the payload read cannot be reordered
/// past the sequence checks.
pub unsafe fn seqlock_read_slot(
    base: *const u8,
    map_len: usize,
    slot_count: u32,
    slot_stride: u32,
    slot_idx: u32,
    buf: &mut Vec<u8>,
) -> Result<bool, TelemetryError> {
    use core::sync::atomic::{fence, Ordering};

    if slot_idx >= slot_count {
        return Err(TelemetryError::InvalidPayload(
            "ring slot index out of range".into(),
        ));
    }
    let slot_off = RING_HEADER_BYTES
        .checked_add(
            (slot_idx as usize)
                .checked_mul(slot_stride as usize)
                .ok_or_else(|| {
                    TelemetryError::InvalidPayload("ring slot offset overflow".into())
                })?,
        )
        .ok_or_else(|| TelemetryError::InvalidPayload("ring slot offset overflow".into()))?;
    let slot_end = slot_off
        .checked_add(slot_stride as usize)
        .ok_or_else(|| TelemetryError::InvalidPayload("ring slot end overflow".into()))?;
    if slot_end > map_len {
        return Err(TelemetryError::InvalidPayload(
            "ring slot exceeds mapping".into(),
        ));
    }

    let slot_ptr = base.add(slot_off);
    let hdr: HkSnapshotSlotHeader =
        core::ptr::read_volatile(slot_ptr as *const HkSnapshotSlotHeader);
    // Odd sequence = producer is mid-write. Torn.
    if hdr.seq & 1 == 1 {
        return Ok(false);
    }
    let payload_cap = slot_stride as usize - SLOT_HEADER_BYTES;
    let payload_len = hdr.payload_len as usize;
    if payload_len > payload_cap {
        return Err(TelemetryError::InvalidPayload(
            "ring slot payload_len exceeds stride".into(),
        ));
    }

    fence(Ordering::Acquire);
    buf.clear();
    buf.reserve(payload_len);
    let payload_ptr = slot_ptr.add(SLOT_HEADER_BYTES);
    core::ptr::copy_nonoverlapping(payload_ptr, buf.as_mut_ptr(), payload_len);
    buf.set_len(payload_len);
    fence(Ordering::Acquire);

    // Re-read the sequence: a change (or odd) means the producer touched the
    // slot during our copy — the bytes we hold are torn, discard them.
    let seq2 = core::ptr::read_volatile(slot_ptr as *const u64);
    if seq2 != hdr.seq {
        buf.clear();
        return Ok(false);
    }
    Ok(true)
}

/// Validate a ring header's geometry against the mapped size. Returns the
/// validated `(slot_count, slot_stride)` or a typed error (fail-closed — a
/// forged/short header never yields a reader that indexes out of bounds).
pub fn validate_ring_geometry(
    hdr: &HkSnapshotRingHeader,
    map_len: usize,
) -> Result<(u32, u32), TelemetryError> {
    if hdr.magic != SNAP_RING_MAGIC {
        return Err(TelemetryError::InvalidPayload(format!(
            "snapshot ring bad magic {:#x}",
            hdr.magic
        )));
    }
    if hdr.schema_version != SNAPSHOT_SCHEMA_VERSION {
        return Err(TelemetryError::InvalidPayload(format!(
            "snapshot ring schema_version {} != {}",
            hdr.schema_version, SNAPSHOT_SCHEMA_VERSION
        )));
    }
    if hdr.slot_count < 2 {
        return Err(TelemetryError::InvalidPayload(
            "snapshot ring needs >= 2 slots".into(),
        ));
    }
    if (hdr.slot_stride as usize) < SLOT_HEADER_BYTES + RECORD_HEAD_BYTES {
        return Err(TelemetryError::InvalidPayload(
            "snapshot ring slot_stride too small for a frame head".into(),
        ));
    }
    let need = (hdr.slot_count as usize)
        .checked_mul(hdr.slot_stride as usize)
        .and_then(|s| s.checked_add(RING_HEADER_BYTES))
        .ok_or_else(|| TelemetryError::InvalidPayload("snapshot ring size overflow".into()))?;
    if need > map_len {
        return Err(TelemetryError::InvalidPayload(format!(
            "snapshot ring claims {} bytes, mapping is {}",
            need, map_len
        )));
    }
    Ok((hdr.slot_count, hdr.slot_stride))
}

/// Run a blocking reader loop on the calling (dedicated std) thread: poll the
/// attached ring, parse each fresh frame, and hand each `Snapshot` to `sink`.
/// `sink` returns `false` to stop the loop (e.g. the pipeline receiver closed).
/// Returns when `sink` asks to stop or `stop` is set. The blocking shm polling
/// lives here, OFF the tokio workers (guardrail #8); the sink applies natural
/// backpressure (a `blocking_send` into the pipeline channel).
pub fn run_reader<A, F>(
    mut ring: A,
    mut sink: F,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    idle_poll: std::time::Duration,
) where
    A: SnapshotRingAttach,
    F: FnMut(Snapshot) -> bool,
{
    let mut buf: Vec<u8> = Vec::with_capacity(RECORD_HEAD_BYTES);
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        match ring.next_frame(&mut buf) {
            Ok(true) => match parse_slot(&buf) {
                Ok(snap) => {
                    if !sink(snap) {
                        return; // pipeline receiver gone / asked to stop
                    }
                }
                Err(e) => {
                    // A frame that passed the seqlock but fails content
                    // validation is a forged/corrupt publisher — count via log,
                    // never crash the reader (shm trust boundary).
                    tracing::warn!(error = %e, "snapshot ring frame rejected by parse_slot");
                }
            },
            Ok(false) => std::thread::sleep(idle_poll),
            Err(e) => {
                tracing::error!(error = %e, "snapshot ring reader stopping");
                return;
            }
        }
    }
}

/// Parse a raw ring-slot byte buffer into a safe `Snapshot`. This is the trust
/// boundary: it validates the schema version, that the buffer holds at least the
/// fixed head, and that `entity_count`/`occluder_count` are within the schema maxima
/// AND within the bytes actually delivered, before reading any indexed data. A torn,
/// short, or forged frame returns `InvalidPayload`; it never indexes out of bounds
/// and never panics.
pub fn parse_slot(bytes: &[u8]) -> Result<Snapshot, TelemetryError> {
    if bytes.len() < RECORD_HEAD_BYTES {
        return Err(TelemetryError::InvalidPayload(format!(
            "snapshot slot too short: {} < {} (head)",
            bytes.len(),
            RECORD_HEAD_BYTES
        )));
    }

    // SAFETY: we verified `bytes` is at least `RECORD_HEAD_BYTES`. `HkSnapshotRecord`
    // is `#[repr(C)]`, all-POD (no padding-sensitive invariants, no Drop, every bit
    // pattern is a valid value of every field's type), so reading it unaligned from
    // the (possibly unaligned) shm buffer via `read_unaligned` is sound. We copy out
    // of the mapping immediately; we never hold a reference into shared memory while
    // a peer could mutate it.
    let head: HkSnapshotRecord =
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const HkSnapshotRecord) };

    if head.schema_version != SNAPSHOT_SCHEMA_VERSION {
        return Err(TelemetryError::InvalidPayload(format!(
            "snapshot schema_version {} not supported; expected {}",
            head.schema_version, SNAPSHOT_SCHEMA_VERSION
        )));
    }

    let entity_count = head.entity_count as usize;
    if entity_count > SNAP_MAX_ENTITIES {
        return Err(TelemetryError::InvalidPayload(format!(
            "snapshot entity_count {} exceeds max {}",
            entity_count, SNAP_MAX_ENTITIES
        )));
    }

    // Occluder trailer: occluder_count entries of OCCLUDER_BYTES must fit in the bytes
    // delivered after the fixed head. Reject an overrun rather than reading past the
    // mapping (shm trust boundary; covered by torn_snapshot_frame_no_panic).
    let occluder_count = head.occluder_count as usize;
    let trailer_bytes = bytes.len() - RECORD_HEAD_BYTES;
    let needed = occluder_count
        .checked_mul(OCCLUDER_BYTES)
        .ok_or_else(|| TelemetryError::InvalidPayload("occluder_count overflow".to_string()))?;
    if needed > trailer_bytes {
        return Err(TelemetryError::InvalidPayload(format!(
            "snapshot occluder trailer {} needs {} bytes, only {} present",
            occluder_count, needed, trailer_bytes
        )));
    }

    let mut occluders = Vec::with_capacity(occluder_count);
    for i in 0..occluder_count {
        let off = RECORD_HEAD_BYTES + i * OCCLUDER_BYTES;
        // SAFETY: bounds verified above (off + OCCLUDER_BYTES <= bytes.len()); POD.
        let vol: HkOccluderVolume =
            unsafe { core::ptr::read_unaligned(bytes[off..].as_ptr() as *const HkOccluderVolume) };
        occluders.push(vol);
    }

    Snapshot::from_record(&head, entity_count, occluders)
}

/// Test bit `idx` of a per-entity bitset word array. Out-of-range indices read as
/// clear (defensive; callers iterate only `0..entity_count`).
pub fn bit_set(words: &[u32; SNAP_BITSET_WORDS], idx: usize) -> bool {
    let w = idx / 32;
    let b = idx % 32;
    if w >= SNAP_BITSET_WORDS {
        return false;
    }
    (words[w] >> b) & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_size_is_frozen() {
        assert_eq!(core::mem::size_of::<HkSnapshotRecord>(), 10400);
        assert_eq!(core::mem::size_of::<HkEntityState>(), 40);
        assert_eq!(core::mem::size_of::<HkVec3>(), 12);
        assert_eq!(core::mem::size_of::<HkOccluderVolume>(), 40);
    }

    /// A short buffer (fewer bytes than the fixed head) is rejected, never read.
    #[test]
    fn short_slot_is_invalid_payload() {
        let buf = vec![0u8; RECORD_HEAD_BYTES - 1];
        let err = parse_slot(&buf).expect_err("short slot rejected");
        match err {
            TelemetryError::InvalidPayload(_) => {}
            other => panic!("expected InvalidPayload, got {other:?}"),
        }
    }

    /// A head with a bad schema version is rejected.
    #[test]
    fn wrong_schema_version_is_invalid_payload() {
        let mut buf = vec![0u8; RECORD_HEAD_BYTES];
        // schema_version is the first u32.
        buf[0..4].copy_from_slice(&999u32.to_ne_bytes());
        assert!(matches!(
            parse_slot(&buf),
            Err(TelemetryError::InvalidPayload(_))
        ));
    }

    /// An entity_count beyond the maximum is rejected before any indexed read.
    #[test]
    fn overlarge_entity_count_is_invalid_payload() {
        let mut buf = vec![0u8; RECORD_HEAD_BYTES];
        buf[0..4].copy_from_slice(&SNAPSHOT_SCHEMA_VERSION.to_ne_bytes());
        buf[4..8].copy_from_slice(&(SNAP_MAX_ENTITIES as u32 + 1).to_ne_bytes());
        assert!(matches!(
            parse_slot(&buf),
            Err(TelemetryError::InvalidPayload(_))
        ));
    }

    /// An occluder_count whose trailer would overrun the delivered bytes is rejected.
    #[test]
    fn occluder_overrun_is_invalid_payload() {
        let mut buf = vec![0u8; RECORD_HEAD_BYTES]; // no trailer bytes at all
        buf[0..4].copy_from_slice(&SNAPSHOT_SCHEMA_VERSION.to_ne_bytes());
        // occluder_count lives at the field offset; claim 3 with zero trailer present.
        let off = occluder_count_offset();
        buf[off..off + 4].copy_from_slice(&3u32.to_ne_bytes());
        assert!(matches!(
            parse_slot(&buf),
            Err(TelemetryError::InvalidPayload(_))
        ));
    }

    /// A well-formed minimal frame (0 entities, 0 occluders) parses cleanly.
    #[test]
    fn empty_valid_frame_parses() {
        let mut buf = vec![0u8; RECORD_HEAD_BYTES];
        buf[0..4].copy_from_slice(&SNAPSHOT_SCHEMA_VERSION.to_ne_bytes());
        // entity_count = 0, occluder_count = 0 (already zero).
        let snap = parse_slot(&buf).expect("valid empty frame parses");
        assert_eq!(snap.entities.len(), 0);
        assert_eq!(snap.occluders.len(), 0);
    }

    /// Byte offset of `occluder_count` within `HkSnapshotRecord`, computed from the
    /// frozen layout audit (see snapshot_schema.h). Used only by the overrun test.
    fn occluder_count_offset() -> usize {
        // schema_version 0, entity_count 4, tick 8, mono_ns 16, local_player_id 24,
        // cam_origin 32, cam_forward 44, cam_up 56, cam_fov_rad 68,
        // visibility_bits 72 (32B) -> ends 104, audiopath_bits 104 (32B) -> ends 136,
        // occluder_count at 136.
        136
    }

    #[test]
    fn bitset_indexing() {
        let mut words = [0u32; SNAP_BITSET_WORDS];
        words[1] = 1 << 5; // entity 37 (32 + 5)
        assert!(bit_set(&words, 37));
        assert!(!bit_set(&words, 36));
        assert!(!bit_set(&words, 9999)); // out of range -> clear, no panic
    }
}
