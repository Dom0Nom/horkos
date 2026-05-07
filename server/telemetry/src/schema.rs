//! src/schema.rs
//!
//! Role: Per-tick telemetry payload schema mirrored from the Phase 1 C99
//! header `sdk/include/horkos/event_schema.h`. Field names and sizes MUST
//! match the C side; the contract test in this crate diffs them.
//!
//! Target platforms: server.
//!
//! Versioning: every field addition bumps `schema_version`. No field renames.
//! Deprecated fields stay as reserved padding.

use serde::{Deserialize, Serialize};

/// Schema version, mirrored from `sdk/include/horkos/event_schema.h`.
/// Bump in lockstep with the C header on every additive field change.
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
