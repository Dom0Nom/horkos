//! src/snapshot/backends/mod.rs
//!
//! Role: platform backend selection for the snapshot shared-memory ring attach. This
//! is the ONLY place in the behavioral-gamestate domain that touches an OS API
//! (guardrail #1); the two implementations are selected by target `cfg` keyed to the
//! workspace's platform, never by raw `_WIN32`/`__linux__`. Compiled only under the
//! `gamestate-ipc-shm` feature — with the feature off, analyzers run purely from
//! file-backed fixtures/replays and CI needs no game-server peer.
//!
//! Target platforms: server (POSIX shm on Linux/macOS game hosts; Win32 file mapping
//! on Windows game hosts).
//!
//! Guardrails: #8 — `thiserror` via `TelemetryError`; no `unwrap()` outside tests.

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod posix;

#[cfg(target_os = "windows")]
pub mod win;

/// Re-export the platform default attach type under one name so the reader is
/// platform-agnostic (guardrail #1 — the consumer never names a platform type).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use posix::PosixRingAttach as DefaultRingAttach;

#[cfg(target_os = "windows")]
pub use win::WinRingAttach as DefaultRingAttach;
