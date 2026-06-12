//! Role: POSIX `shm_open` + `mmap` backend for the authoritative snapshot ring
//! (Linux/macOS game hosts). Owns the only platform syscalls in the snapshot
//! domain (guardrail #1, isolated in `backends/`). Maps the Horkos-owned ring
//! (`HkSnapshotRingHeader` + seqlock slots, defined in `snapshot_schema.h`)
//! read-only and implements `SnapshotRingAttach::next_frame` by seqlock-reading
//! the newest published, untorn slot. The seqlock + bounds logic is shared,
//! platform-independent code in `ipc`; only the mapping lifecycle is here.
//!
//! Target platforms: server (HK_PLATFORM_LINUX / HK_PLATFORM_MACOS).
//!
//! Guardrails: #8 — `thiserror` via `TelemetryError`; no `unwrap()` outside
//! tests; the mapping is read-only (`PROT_READ`), so a compromised producer
//! cannot trick the consumer into writing; `munmap` on Drop, no leak.

use std::ffi::CString;
use std::os::raw::c_void;
use std::sync::atomic::Ordering;

use crate::error::TelemetryError;
use crate::snapshot::ipc::{
    read_ring_header, seqlock_read_slot, validate_ring_geometry, SnapshotRingAttach,
};

/// POSIX shared-memory attach handle for the snapshot ring. Holds the live
/// read-only mapping and the consumer's last-consumed generation.
#[derive(Debug)]
pub struct PosixRingAttach {
    base: *mut c_void,
    len: usize,
    slot_count: u32,
    slot_stride: u32,
    last_seq: u64,
}

// SAFETY: the mapping is read-only (`PROT_READ`) and owned solely by this
// handle; moving it to the dedicated reader thread is sound (no aliasing, no
// interior mutability of the Rust value). The raw pointer addresses a process
// mapping that outlives nothing the borrow checker tracks; `Drop` munmaps it.
unsafe impl Send for PosixRingAttach {}

impl SnapshotRingAttach for PosixRingAttach {
    fn attach(name: &str) -> Result<Self, TelemetryError> {
        let cname = CString::new(name)
            .map_err(|_| TelemetryError::InvalidPayload("shm name has interior NUL".into()))?;

        // 1. Open the named shm object read-only. The producer (game server)
        //    created it; telemetry never creates or writes it.
        let fd = unsafe { libc::shm_open(cname.as_ptr(), libc::O_RDONLY, 0) };
        if fd < 0 {
            return Err(TelemetryError::InvalidPayload(format!(
                "shm_open('{name}') failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        // From here, any early return must close `fd`.
        let result = (|| {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut st) } != 0 {
                return Err(TelemetryError::InvalidPayload(format!(
                    "fstat shm failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let len = st.st_size as usize;
            if len < crate::snapshot::ipc::RING_HEADER_BYTES {
                return Err(TelemetryError::InvalidPayload(format!(
                    "shm object {len} bytes smaller than ring header"
                )));
            }
            // 2. Map read-only, shared (so producer writes are visible).
            let base = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };
            if base == libc::MAP_FAILED {
                return Err(TelemetryError::InvalidPayload(format!(
                    "mmap shm failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // 3. Validate the ring geometry before trusting any slot offset.
            let hdr = unsafe { read_ring_header(base as *const u8) };
            match validate_ring_geometry(&hdr, len) {
                Ok((slot_count, slot_stride)) => Ok(PosixRingAttach {
                    base,
                    len,
                    slot_count,
                    slot_stride,
                    // Start from the current write_seq so we read only frames
                    // published AFTER attach (no stale backlog replay).
                    last_seq: hdr.write_seq,
                }),
                Err(e) => {
                    unsafe { libc::munmap(base, len) };
                    Err(e)
                }
            }
        })();
        // The mapping survives the fd (POSIX); close it either way.
        unsafe { libc::close(fd) };
        result
    }

    fn next_frame(&mut self, buf: &mut Vec<u8>) -> Result<bool, TelemetryError> {
        let hdr = unsafe { read_ring_header(self.base as *const u8) };
        // Re-validate write_seq monotonicity defensively; a header whose magic
        // changed under us (producer crashed / remapped) fails closed.
        if hdr.magic != crate::snapshot::ipc::SNAP_RING_MAGIC {
            return Err(TelemetryError::InvalidPayload(
                "snapshot ring header vanished".into(),
            ));
        }
        let cur = hdr.write_seq;
        if cur <= self.last_seq {
            return Ok(false); // no new frame
        }
        // Pick the next generation to read; if the producer lapped us (we fell
        // behind by >= slot_count), skip ahead to the oldest still-live slot.
        let mut gen = self.last_seq + 1;
        if cur - gen >= u64::from(self.slot_count) {
            gen = cur - u64::from(self.slot_count) + 1;
        }
        let slot = ((gen - 1) % u64::from(self.slot_count)) as u32;
        let ok = unsafe {
            seqlock_read_slot(
                self.base as *const u8,
                self.len,
                self.slot_count,
                self.slot_stride,
                slot,
                buf,
            )?
        };
        // Advance past `gen` whether it was clean or torn. The publish protocol
        // bumps `write_seq` only AFTER a slot's sequence goes even, so reaching
        // a torn (odd / changed-mid-copy) slot at `gen <= write_seq` means the
        // producer lapped and overwrote that generation — the frame is lost, not
        // in-progress. Skipping it lets the reader recover to the next frame;
        // NOT advancing would wedge forever on a permanently-stale slot.
        self.last_seq = gen;
        Ok(ok)
    }
}

impl Drop for PosixRingAttach {
    fn drop(&mut self) {
        if !self.base.is_null() {
            unsafe { libc::munmap(self.base, self.len) };
        }
    }
}

// Keep the unused-import lint quiet on platforms where `Ordering` is only used
// transitively; the explicit reference documents the seqlock memory model.
const _: Ordering = Ordering::Acquire;
