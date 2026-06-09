//! src/timing.rs
//!
//! Role: Server-side ingest contract for the timing & execution-trace side-channel
//! report (timing-side-channels domain, catalog signals 154/155/156/157/159/161/162).
//! Serde mirror of the usermode `timing_report` field names in
//! `ac/include/horkos/timing/timing_signals.h`. Exposes `POST /api/timing`. This is the
//! INDEPENDENT per-tick/periodic JSON plane (NOT byte-compatible with the C struct —
//! same separation `schema.rs` documents for `TickPayload`); histograms arrive as
//! fixed-length arrays and are length-validated on deserialize rather than indexed
//! blindly.
//!
//! FEATURES/EVIDENCE ONLY — there is deliberately no verdict field. ALL scoring (skew
//! thresholds, modality shifts, cadence signatures, VM-context tagging) is server-side
//! in the ban-engine; the client ships raw vectors/histograms/scalars only. Both 155
//! (APERF/MPERF skew) and 162 (CPUID fan) are VM-context TAGS correlated with the
//! hypervisor-present bit — never an autonomous ban (VBS/HVCI/WSL2/Hyper-V fan the
//! same way).
//!
//! Target platforms: server.
//!
//! Guardrail #8: fully async-compatible (pure validation, no blocking), `thiserror`
//! error type, NO `unwrap()`/`expect()` outside `#[cfg(test)]`. A malformed report
//! (wrong histogram length, out-of-range pct/ppm, NaN) yields a typed
//! `TelemetryError::Timing`, never a panic.
//!
//! Phase 2 stub parity: validate the schema version + field ranges, record a span,
//! drop on the floor (mirrors `telemetry::ingest`). The model scoring lands in a /tdd
//! phase.

use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::TelemetryError;

/// Timing-report schema version. Bump on every additive change; independent of the
/// tick-stream `SCHEMA_VERSION` and the kernel `HK_EVENT_SCHEMA_VERSION`.
pub const TIMING_SCHEMA_VERSION: u32 = 1;

/// Fixed histogram bucket count — mirrors `HK_TIMING_HIST_BUCKETS` (159 dispatch
/// latency, 161 inter-arrival). Lengths are validated on deserialize.
pub const HK_TIMING_HIST_BUCKETS: usize = 32;
/// Fixed CPUID leaf-fan width — mirrors `HK_TIMING_CPUID_LEAVES` (162).
pub const HK_TIMING_CPUID_LEAVES: usize = 16;

/// `sensors_ok` bits — mirror of `hk::timing::SensorOk`. A clear bit means the sampler
/// did NOT run cleanly on the client; the server must read a zeroed sub-struct as
/// "not collected", never "clean".
pub const HK_TIMING_OK_VEH: u32 = 1 << 0;
pub const HK_TIMING_OK_WATCHDOG: u32 = 1 << 1;
pub const HK_TIMING_OK_CLOCK: u32 = 1 << 2;
pub const HK_TIMING_OK_EXC: u32 = 1 << 3;
pub const HK_TIMING_OK_GUARD: u32 = 1 << 4;
pub const HK_TIMING_OK_CPUID: u32 = 1 << 5;
pub const HK_TIMING_OK_KERNEL: u32 = 1 << 6;

/// Signal 154 — VEH fault-resolver attribution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct VehAttrib {
    pub foreign_resolver: u32,
    pub resolver_signed: u32,
    pub dr6_stepbit: u32,
    pub dr7_local_enable: u32,
    pub resolver_image_base: u64,
}

/// Signal 156 — sibling-thread RDTSCP watchdog deltas + core ids.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Watchdog {
    pub in_section_tsc_delta: u64,
    pub watchdog_tsc_delta: u64,
    pub aux_core_in: u32,
    pub aux_core_watch: u32,
    pub ctx_switch_seen: u32,
    pub divergence_pct: u32,
}

/// Signal 157 — KUSER_SHARED_DATA vs API clock consistency.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ClockConsistency {
    pub shared_interrupt_dt: u64,
    pub shared_system_dt: u64,
    pub api_tick_dt: u64,
    pub api_qpc_dt: u64,
    pub ratio_drift_ppm: u32,
    pub wine_vm_ctx: u32,
}

/// Signal 159 — INT3-decoy dispatch-latency histogram.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExcLatency {
    pub hist: Vec<u32>,
    pub baseline_modes: u32,
    pub live_modes: u32,
}

/// Signal 161 — guard-fault inter-arrival cadence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardCadence {
    pub inter_arrival: Vec<u32>,
    pub fault_count: u32,
    pub uniform_cadence: u32,
    pub eflags_tf_or_dr6: u32,
}

/// Signal 162 — CPUID leaf-fan latency vector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CpuidFan {
    pub leaf_latency: Vec<u32>,
    pub leaf_id: Vec<u32>,
    pub flat_baseline_cycles: u32,
}

/// Signal 155 — kernel APERF/MPERF-vs-RDTSC effective-frequency skew (folded from the
/// driver ring). VM-context tag — server correlates with `hv_present_bit`, never bans.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct KernelSummary {
    pub aperf_mperf_eff_mhz: u32,
    pub rdtsc_nominal_mhz: u32,
    pub skew_pct: u32,
    pub hv_present_bit: u32,
}

/// One per-tick/periodic timing report for a player. Mirrors `timing_report`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimingReport {
    /// Envelope schema version; must equal `TIMING_SCHEMA_VERSION`.
    pub schema_version: u32,
    /// Server-assigned player identifier.
    pub player_id: u64,
    pub veh: VehAttrib,
    pub watchdog: Watchdog,
    pub clock: ClockConsistency,
    pub exc: ExcLatency,
    pub guard: GuardCadence,
    pub cpuid: CpuidFan,
    pub kern: KernelSummary,
    /// `HK_TIMING_OK_*` bitmask: which samplers ran cleanly this report.
    pub sensors_ok: u32,
}

impl TimingReport {
    /// Validate the report's structural + range invariants. Returns a typed error on
    /// any violation (never panics). Called from the ingest handler; safe to call from
    /// async context (pure).
    pub fn validate(&self) -> Result<(), TelemetryError> {
        if self.schema_version != TIMING_SCHEMA_VERSION {
            return Err(TelemetryError::Timing(format!(
                "timing schema_version {} not supported; expected {}",
                self.schema_version, TIMING_SCHEMA_VERSION
            )));
        }
        // Fixed-length histograms: validate length so a malformed client cannot smuggle
        // an over/under-length vector past a later indexer.
        if self.exc.hist.len() != HK_TIMING_HIST_BUCKETS {
            return Err(TelemetryError::Timing(format!(
                "exc.hist length {} != {}",
                self.exc.hist.len(),
                HK_TIMING_HIST_BUCKETS
            )));
        }
        if self.guard.inter_arrival.len() != HK_TIMING_HIST_BUCKETS {
            return Err(TelemetryError::Timing(format!(
                "guard.inter_arrival length {} != {}",
                self.guard.inter_arrival.len(),
                HK_TIMING_HIST_BUCKETS
            )));
        }
        if self.cpuid.leaf_latency.len() != HK_TIMING_CPUID_LEAVES
            || self.cpuid.leaf_id.len() != HK_TIMING_CPUID_LEAVES
        {
            return Err(TelemetryError::Timing(format!(
                "cpuid leaf vectors must be {} (got latency={}, id={})",
                HK_TIMING_CPUID_LEAVES,
                self.cpuid.leaf_latency.len(),
                self.cpuid.leaf_id.len()
            )));
        }
        // Range-bound the derived percentages/ppm the client computes so a poisoned
        // value cannot smear server-side bucketing. The client clamps these (see
        // timing_logic.cpp); reject anything outside the clamp range as malformed.
        if self.watchdog.divergence_pct > 1000 {
            return Err(TelemetryError::Timing(format!(
                "watchdog.divergence_pct {} out of range (0..=1000)",
                self.watchdog.divergence_pct
            )));
        }
        if self.clock.ratio_drift_ppm > 1_000_000 {
            return Err(TelemetryError::Timing(format!(
                "clock.ratio_drift_ppm {} out of range (0..=1_000_000)",
                self.clock.ratio_drift_ppm
            )));
        }
        if self.kern.skew_pct > 100 {
            return Err(TelemetryError::Timing(format!(
                "kern.skew_pct {} out of range (0..=100)",
                self.kern.skew_pct
            )));
        }
        Ok(())
    }
}

/// Mounts `POST /api/timing`.
pub fn router() -> Router {
    Router::new().route("/api/timing", post(ingest))
}

#[tracing::instrument(skip_all, fields(player_id, sensors_ok))]
async fn ingest(
    Json(report): Json<TimingReport>,
) -> Result<axum::http::StatusCode, TelemetryError> {
    report.validate()?;

    tracing::Span::current()
        .record("player_id", report.player_id)
        .record("sensors_ok", report.sensors_ok);

    tracing::trace!(
        sensors_ok = report.sensors_ok,
        kern_skew = report.kern.skew_pct,
        "timing report accepted"
    );

    // Phase 2 stub: log only, no scoring (mirrors `telemetry::ingest`). The ban-engine
    // model thresholds skew/modality/cadence and folds the VM-context tags later.
    let _ = report;

    Ok(axum::http::StatusCode::ACCEPTED)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> TimingReport {
        TimingReport {
            schema_version: TIMING_SCHEMA_VERSION,
            player_id: 0xC0FFEE,
            veh: VehAttrib::default(),
            watchdog: Watchdog {
                divergence_pct: 12,
                ..Default::default()
            },
            clock: ClockConsistency {
                ratio_drift_ppm: 5000,
                ..Default::default()
            },
            exc: ExcLatency {
                hist: vec![0u32; HK_TIMING_HIST_BUCKETS],
                baseline_modes: 1,
                live_modes: 2,
            },
            guard: GuardCadence {
                inter_arrival: vec![0u32; HK_TIMING_HIST_BUCKETS],
                fault_count: 40,
                uniform_cadence: 1,
                eflags_tf_or_dr6: 1,
            },
            cpuid: CpuidFan {
                leaf_latency: vec![40u32; HK_TIMING_CPUID_LEAVES],
                leaf_id: vec![1u32; HK_TIMING_CPUID_LEAVES],
                flat_baseline_cycles: 40,
            },
            kern: KernelSummary {
                aperf_mperf_eff_mhz: 3200,
                rdtsc_nominal_mhz: 3000,
                skew_pct: 6,
                hv_present_bit: 1,
            },
            sensors_ok: HK_TIMING_OK_WATCHDOG | HK_TIMING_OK_CPUID | HK_TIMING_OK_KERNEL,
        }
    }

    #[test]
    fn round_trip_and_validate() {
        let r = sample_report();
        let json = serde_json::to_value(&r).expect("serialize");
        let back: TimingReport = serde_json::from_value(json).expect("deserialize");
        assert_eq!(r, back);
        assert!(back.validate().is_ok());
    }

    #[test]
    fn wrong_hist_length_is_rejected() {
        let mut r = sample_report();
        r.exc.hist = vec![0u32; HK_TIMING_HIST_BUCKETS - 1];
        let err = r.validate().expect_err("must reject short hist");
        match err {
            TelemetryError::Timing(_) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn wrong_cpuid_length_is_rejected() {
        let mut r = sample_report();
        r.cpuid.leaf_id = vec![0u32; HK_TIMING_CPUID_LEAVES + 1];
        assert!(r.validate().is_err());
    }

    #[test]
    fn out_of_range_divergence_is_rejected() {
        let mut r = sample_report();
        r.watchdog.divergence_pct = 1001;
        assert!(r.validate().is_err());
    }

    #[test]
    fn out_of_range_ppm_is_rejected() {
        let mut r = sample_report();
        r.clock.ratio_drift_ppm = 1_000_001;
        assert!(r.validate().is_err());
    }

    #[test]
    fn out_of_range_skew_is_rejected() {
        let mut r = sample_report();
        r.kern.skew_pct = 101;
        assert!(r.validate().is_err());
    }

    #[test]
    fn wrong_schema_version_is_rejected() {
        let mut r = sample_report();
        r.schema_version = TIMING_SCHEMA_VERSION + 1;
        assert!(r.validate().is_err());
    }

    #[test]
    fn schema_version_pinned() {
        // Guards against an accidental bump without updating the C mirror.
        assert_eq!(TIMING_SCHEMA_VERSION, 1);
    }
}
