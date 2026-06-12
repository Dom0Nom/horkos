//! Role: Server-side ingest contract for the anti-analysis-environment report
//! sub-payload (catalog signals 194 — dynamic-instrumentation/DBI residency, and
//! 197 — memory-editor/debugger host fingerprint ONLY). Serde mirror of the
//! usermode POD field names in
//! `ac/include/horkos/anti_analysis/anti_analysis_signals.h`
//! (`aa_instrumentation` + `aa_host_tools`). This is the INDEPENDENT periodic
//! JSON plane (NOT byte-compatible with the C struct — the same separation
//! `schema.rs` documents for `TickPayload`); it rides the `TickPayload` HTTP
//! plane as an OPTIONAL sub-payload (see `schema.rs::TickPayload::anti_analysis`),
//! NOT the C99 kernel-event ring in `event_schema.h`/`ioctl.h`.
//!
//! The other anti-analysis catalog signals (190-193, 195, 196, 198) ride their
//! own domains' planes (selfcheck/timing/eBPF/daemon) and are NOT mirrored here.
//!
//! FEATURES/EVIDENCE ONLY — there is deliberately no verdict field. ALL scoring
//! (combined-signal confidence for 194, severity tiering for 197, the JIT/RE-tool
//! allowlists) is server-side; the client ships the raw observable counts/flags
//! plus a locally-derived tier the server may override. The validation here is
//! purely structural: it range-checks the two tiers against their enum range and
//! rejects an out-of-range tier; missing fields are tolerated per the
//! optional-sub-payload precedent (each scalar is `#[serde(default)]`, so a
//! client that omits a field yields a zero the server reads as "not observed",
//! never a fabricated positive).
//!
//! Target platforms: server.
//!
//! Guardrail #8: pure validation, no blocking, `thiserror` error type, NO
//! `unwrap()`/`expect()` outside `#[cfg(test)]`. A malformed payload (out-of-range
//! tier) yields a typed `AntiAnalysisError`, never a panic.

use serde::{Deserialize, Serialize};

/// Anti-analysis report schema version. Bump on every additive change; independent
/// of the tick-stream `SCHEMA_VERSION` and the kernel `HK_EVENT_SCHEMA_VERSION`.
pub const ANTI_ANALYSIS_SCHEMA_VERSION: u32 = 1;

/// Highest valid signal-194 confidence tier (`HK_AA_INSTR_TIER_HIGH`).
pub const HK_AA_INSTR_TIER_MAX: u32 = 2;
/// Highest valid signal-197 severity tier (`HK_AA_HOST_TIER_HANDLE_OPEN`).
pub const HK_AA_HOST_TIER_MAX: u32 = 3;

/// Typed validation error for the anti-analysis sub-payload.
#[derive(Debug, thiserror::Error)]
pub enum AntiAnalysisError {
    /// A tier field is outside its enum's valid range.
    #[error("{field} tier {value} out of range (0..={max})")]
    TierOutOfRange {
        field: &'static str,
        value: u32,
        max: u32,
    },
}

impl From<AntiAnalysisError> for crate::error::TelemetryError {
    fn from(e: AntiAnalysisError) -> Self {
        crate::error::TelemetryError::AntiAnalysis(e.to_string())
    }
}

/// Signal 194 — dynamic-instrumentation (Frida/DBI) residency fingerprint.
/// Mirrors `aa_instrumentation`. `jit_module_present` is FP context the server
/// allowlists; the client's `confidence_tier` is advisory (server may override).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AaInstrumentation {
    /// Thread starts in anon-RX mappings not backed by any module.
    #[serde(default)]
    pub unbacked_rx_threads: u32,
    /// Loaded modules exporting a framework symbol name.
    #[serde(default)]
    pub runtime_export_match: u32,
    /// 1 if the framework's default control port is listening in the process tree.
    #[serde(default)]
    pub control_port_listener: u32,
    /// 1 if a known-JIT module is loaded (FP context, not scored client-side).
    #[serde(default)]
    pub jit_module_present: u32,
    /// Client-derived tier: 0=none, 1=info(single), 2=high(combined).
    #[serde(default)]
    pub confidence_tier: u32,
    #[serde(default)]
    pub reserved: u32,
}

/// Signal 197 — memory-editor/debugger host fingerprint (Windows). Mirrors
/// `aa_host_tools`. The client's `severity_tier` is advisory (server may override
/// using the kernel whitelist / Ob handle records + the RE-tool allowlist).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AaHostTools {
    /// Known debugger top-level window classes (x64dbg/Olly/etc.).
    #[serde(default)]
    pub debugger_window_classes: u32,
    /// Known editor device/symlink names present (CE/ReClass).
    #[serde(default)]
    pub known_device_objects: u32,
    /// Editor-helper drivers loaded (e.g. DBK64).
    #[serde(default)]
    pub suspicious_drivers: u32,
    /// 1 if a loaded driver matched the kernel whitelist known-bad set.
    #[serde(default)]
    pub byovd_driver_match: u32,
    /// 1 if the kernel Ob records show an editor opened a handle to the game.
    #[serde(default)]
    pub opened_handle_to_game: u32,
    /// Client-derived tier: 0=none, 1=info, 2=tool-present, 3=handle-open.
    #[serde(default)]
    pub severity_tier: u32,
}

/// The 194+197 report sub-payload. Slim by design — carries only these two
/// sub-structs plus the `sensors_ok` bitmask (mirrors `anti_analysis_report`). A
/// clear `sensors_ok` bit means the sampler did NOT run on the client; the server
/// reads the zeroed sub-struct as "not collected", never "clean".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AntiAnalysisPayload {
    /// Sub-payload schema version; must equal `ANTI_ANALYSIS_SCHEMA_VERSION`.
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub instr: AaInstrumentation,
    #[serde(default)]
    pub host: AaHostTools,
    /// `HK_AA_OK_*` bitmask: which samplers ran on this platform.
    #[serde(default)]
    pub sensors_ok: u32,
}

impl AntiAnalysisPayload {
    /// Validate the sub-payload's range invariants. Returns a typed error on any
    /// violation (never panics). Safe to call from async context (pure). Missing
    /// scalar fields are tolerated (they deserialize to zero per the optional-
    /// sub-payload precedent); only an out-of-range tier is rejected.
    pub fn validate(&self) -> Result<(), AntiAnalysisError> {
        if self.instr.confidence_tier > HK_AA_INSTR_TIER_MAX {
            return Err(AntiAnalysisError::TierOutOfRange {
                field: "instr.confidence_tier",
                value: self.instr.confidence_tier,
                max: HK_AA_INSTR_TIER_MAX,
            });
        }
        if self.host.severity_tier > HK_AA_HOST_TIER_MAX {
            return Err(AntiAnalysisError::TierOutOfRange {
                field: "host.severity_tier",
                value: self.host.severity_tier,
                max: HK_AA_HOST_TIER_MAX,
            });
        }
        Ok(())
    }
}
