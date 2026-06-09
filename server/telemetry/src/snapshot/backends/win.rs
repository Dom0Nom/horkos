//! src/snapshot/backends/win.rs
//!
//! Role: Win32 `CreateFileMappingW` / `MapViewOfFile` backend for attaching the game
//! server's authoritative snapshot ring (Windows game hosts). Implements
//! `SnapshotRingAttach`. Platform code isolated in a `backends/` folder (guardrail #1)
//! and selected by target `cfg`.
//!
//! Target platforms: server (HK_PLATFORM_WINDOWS).
//!
//! Guardrails: #8 — `thiserror` via `TelemetryError`; no `unwrap()` outside tests.

use crate::error::TelemetryError;
use crate::snapshot::ipc::SnapshotRingAttach;

/// Win32 file-mapping attach handle for the snapshot ring.
///
/// HK-UNCERTAIN(ipc-contract): the live ring protocol is NOT specified (impl-plan
/// UNCERTAINTY flag #1). As on POSIX, the `OpenFileMappingW`/`MapViewOfFile` body is
/// deliberately NOT written until the per-title game-server integration contract (the
/// named-section name, slot stride, and frame-ready sequencing) is fixed with the
/// user. The struct, the `attach` signature, and the shared `ipc::parse_slot` byte
/// parse are the stable surface. Do NOT guess the section name or view geometry here.
#[derive(Debug)]
pub struct WinRingAttach {
    _name: String,
}

impl SnapshotRingAttach for WinRingAttach {
    fn attach(name: &str) -> Result<Self, TelemetryError> {
        // HK-UNCERTAIN(ipc-contract): real impl =
        //   1. OpenFileMappingW(FILE_MAP_READ, FALSE, wide(name)) -> hMapping
        //      (read-only: telemetry never writes the game server's ring)
        //   2. MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0) -> base
        //   3. on Drop: UnmapViewOfFile(base); CloseHandle(hMapping)
        // The slot stride and the producer's frame-ready sequencing are part of the
        // unspecified contract. The reader thread hands each completed slot's bytes to
        // `ipc::parse_slot`. Surfacing a clear error keeps a mis-integration loud in
        // dev rather than silently mis-parsing a partial mapping.
        Err(TelemetryError::InvalidPayload(format!(
            "snapshot shm attach (Win32) not implemented: ring IPC contract for '{name}' \
             is unspecified (HK-UNCERTAIN: requires per-title game-server integration)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_is_unimplemented_but_does_not_panic() {
        assert!(WinRingAttach::attach("hk_snap_ring").is_err());
    }
}
