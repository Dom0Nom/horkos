//! src/schema.rs
//!
//! Role: The HTTP/JSON per-tick telemetry ingest contract (`TickPayload`). This
//! is an INDEPENDENT wire plane from the C99 kernel-event schema in
//! `sdk/include/horkos/event_schema.h` — it is a serde JSON struct (no
//! `#[repr(C)]`, not byte-compatible with any C struct) carrying gameplay
//! signal (player id, tick, aim deltas, input bitmask), not the kernel
//! process/image/handle records.
//!
//! Target platforms: server.
//!
//! Versioning: `SCHEMA_VERSION` is the tick-stream version, intentionally
//! decoupled from `HK_EVENT_SCHEMA_VERSION`. Every field addition bumps it; no
//! field renames; deprecated fields stay reserved.

use serde::{Deserialize, Serialize};

/// Version of the per-tick JSON ingest contract (distinct from the kernel
/// event schema's `HK_EVENT_SCHEMA_VERSION`). Bump on every additive change.
pub const SCHEMA_VERSION: u32 = 1;

/// One tick of player state. Fixed serialised shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TickPayload {
    /// Schema version of this payload.
    pub schema_version: u32,

    /// Server-assigned player identifier.
    pub player_id: u64,

    /// Monotonic tick counter from the client.
    pub tick: u64,

    /// Aim delta on the X axis since the previous tick.
    pub aim_delta_x: f32,

    /// Aim delta on the Y axis since the previous tick.
    pub aim_delta_y: f32,

    /// Bitmask of input flags (movement, fire, jump, ...).
    pub input_state: u32,

    /// Server-side wall clock at receipt, in nanoseconds since UNIX epoch.
    /// Set by the server; clients send `0`.
    #[serde(default)]
    pub server_received_ts: u64,
}
