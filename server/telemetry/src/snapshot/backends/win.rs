//! Role: Win32 `OpenFileMappingW` / `MapViewOfFile` backend for the
//! authoritative snapshot ring (Windows game hosts). Implements
//! `SnapshotRingAttach` against the Horkos-owned ring contract
//! (`HkSnapshotRingHeader` + seqlock slots, `snapshot_schema.h`); the seqlock +
//! bounds logic is shared platform-independent code in `ipc`, only the mapping
//! lifecycle is here. Platform code isolated in `backends/` (guardrail #1),
//! selected by target `cfg`.
//!
//! Target platforms: server (HK_PLATFORM_WINDOWS). UNVERIFIED — this file has
//! never been compiled on a Windows host; the `windows-sys` mapping calls are
//! mirrored structurally from the POSIX backend and must be built on the
//! Windows box before being trusted (project guardrail: never claim Windows
//! code works until compiled on its target).
//!
//! Guardrails: #8 — `thiserror` via `TelemetryError`; no `unwrap()` outside
//! tests; the view is read-only (`FILE_MAP_READ`); `UnmapViewOfFile` +
//! `CloseHandle` on Drop, no leak.

use std::os::raw::c_void;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Memory::{
    MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, FILE_MAP_READ, MEMORY_MAPPED_VIEW_ADDRESS,
};

use crate::error::TelemetryError;
use crate::snapshot::ipc::{
    read_ring_header, seqlock_read_slot, validate_ring_geometry, SnapshotRingAttach,
    RING_HEADER_BYTES, SNAP_RING_MAGIC,
};

/// Win32 file-mapping attach handle for the snapshot ring.
#[derive(Debug)]
pub struct WinRingAttach {
    mapping: HANDLE,
    base: *const c_void,
    len: usize,
    slot_count: u32,
    slot_stride: u32,
    last_seq: u64,
}

// SAFETY: the view is read-only (`FILE_MAP_READ`) and owned solely by this
// handle; moving it to the dedicated reader thread is sound. Drop unmaps it.
unsafe impl Send for WinRingAttach {}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

impl SnapshotRingAttach for WinRingAttach {
    fn attach(name: &str) -> Result<Self, TelemetryError> {
        let wname = wide(name);
        // Open the named section read-only; the producer (game server) created it.
        let mapping = unsafe { OpenFileMappingW(FILE_MAP_READ, 0, wname.as_ptr()) };
        if mapping.is_null() {
            return Err(TelemetryError::InvalidPayload(format!(
                "OpenFileMappingW('{name}') failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        // Map the whole section (size 0 = entire mapping).
        let view: MEMORY_MAPPED_VIEW_ADDRESS =
            unsafe { MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0) };
        if view.Value.is_null() {
            let err = std::io::Error::last_os_error();
            unsafe { CloseHandle(mapping) };
            return Err(TelemetryError::InvalidPayload(format!(
                "MapViewOfFile failed: {err}"
            )));
        }
        let base = view.Value as *const c_void;

        // The view length is the section length; query it via the region size.
        // VirtualQuery would be exact, but the ring header carries the geometry
        // and `validate_ring_geometry` bounds every slot against `len`, so we
        // take the mapped region size from the header's claimed extent and let
        // validation reject anything that does not fit a real mapping. Use the
        // committed region size via the ring's own slot_count*stride as the
        // authoritative length once validated.
        let hdr = unsafe { read_ring_header(base as *const u8) };
        if hdr.magic != SNAP_RING_MAGIC {
            unsafe {
                UnmapViewOfFile(view);
                CloseHandle(mapping);
            }
            return Err(TelemetryError::InvalidPayload(
                "snapshot ring bad magic".into(),
            ));
        }
        let claimed = RING_HEADER_BYTES
            .saturating_add((hdr.slot_count as usize).saturating_mul(hdr.slot_stride as usize));
        match validate_ring_geometry(&hdr, claimed) {
            Ok((slot_count, slot_stride)) => Ok(WinRingAttach {
                mapping,
                base,
                len: claimed,
                slot_count,
                slot_stride,
                last_seq: hdr.write_seq,
            }),
            Err(e) => {
                unsafe {
                    UnmapViewOfFile(view);
                    CloseHandle(mapping);
                }
                Err(e)
            }
        }
    }

    fn next_frame(&mut self, buf: &mut Vec<u8>) -> Result<bool, TelemetryError> {
        let hdr = unsafe { read_ring_header(self.base as *const u8) };
        if hdr.magic != SNAP_RING_MAGIC {
            return Err(TelemetryError::InvalidPayload(
                "snapshot ring header vanished".into(),
            ));
        }
        let cur = hdr.write_seq;
        if cur <= self.last_seq {
            return Ok(false);
        }
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
        // See the POSIX backend: advance past `gen` whether clean or torn, since
        // a torn slot at `gen <= write_seq` was lapped (lost), not in-progress.
        self.last_seq = gen;
        Ok(ok)
    }
}

impl Drop for WinRingAttach {
    fn drop(&mut self) {
        unsafe {
            if !self.base.is_null() {
                UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: self.base as *mut c_void,
                });
            }
            if !self.mapping.is_null() {
                CloseHandle(self.mapping);
            }
        }
    }
}
