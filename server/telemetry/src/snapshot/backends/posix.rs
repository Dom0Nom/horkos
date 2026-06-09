//! src/snapshot/backends/posix.rs
//!
//! Role: POSIX `shm_open` + `mmap` backend for attaching the game server's
//! authoritative snapshot ring (Linux/macOS game hosts). Implements
//! `SnapshotRingAttach`. This is platform code, correctly isolated in a `backends/`
//! folder (guardrail #1) and selected by target `cfg`.
//!
//! Target platforms: server (HK_PLATFORM_LINUX / HK_PLATFORM_MACOS).
//!
//! Guardrails: #8 — `thiserror` via `TelemetryError`; no `unwrap()` outside tests.

use crate::error::TelemetryError;
use crate::snapshot::ipc::SnapshotRingAttach;

/// POSIX shared-memory attach handle for the snapshot ring.
///
/// HK-UNCERTAIN(ipc-contract): the live ring protocol is NOT specified (impl-plan
/// UNCERTAINTY flag #1: whether the engine publishes server-side visibility/audio/RNG
/// at all, the slot count, and the publish/sequence handshake by which the game
/// server signals a completed frame). Until that integration contract is fixed with
/// the user, the `shm_open`/`mmap`/`munmap` calls are deliberately NOT written: a
/// half-guessed mapping that reads a torn frame or a wrong slot stride is worse than
/// an unimplemented one. The struct, the `attach` signature, and the byte-view parse
/// (`ipc::parse_slot`) are the stable surface; the mapping body lands when the
/// per-title contract is known. Do NOT guess `mmap` flags / ring geometry here.
#[derive(Debug)]
pub struct PosixRingAttach {
    _name: String,
}

impl SnapshotRingAttach for PosixRingAttach {
    fn attach(name: &str) -> Result<Self, TelemetryError> {
        // HK-UNCERTAIN(ipc-contract): real impl =
        //   1. shm_open(name, O_RDONLY, 0) -> fd  (read-only: telemetry never writes
        //      the game server's ring)
        //   2. fstat to learn the mapped size (must be >= ring-slot count * slot stride)
        //   3. mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0) -> base
        //   4. close(fd) (the mapping survives the fd)
        //   5. on Drop: munmap(base, size)
        // The slot stride and the producer's frame-ready sequencing (so we read a
        // STABLE slot, not one mid-write) are part of the unspecified contract. The
        // reader thread then hands each completed slot's bytes to `ipc::parse_slot`.
        // We surface a clear unimplemented error rather than a partial mapping so a
        // mis-integration fails loudly in dev, never silently mis-parses.
        Err(TelemetryError::InvalidPayload(format!(
            "snapshot shm attach (POSIX) not implemented: ring IPC contract for '{name}' \
             is unspecified (HK-UNCERTAIN: requires per-title game-server integration)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_is_unimplemented_but_does_not_panic() {
        // Fail-closed: returns an error, never panics, until the IPC contract lands.
        assert!(PosixRingAttach::attach("hk_snap_ring").is_err());
    }
}
