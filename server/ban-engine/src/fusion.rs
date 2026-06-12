//! Role: deterministic cross-signal fusion — the ONLY place a verdict is
//! formed. Consumes the per-session `SuspicionEvent`s the telemetry analyzers
//! emit (signals 172-180) plus the arrival-cadence observation (signal 186)
//! and produces a `FusionOutcome`. Pure function, no I/O, no `.await`.
//!
//! Policy invariants (catalog FP gate, ARCHITECTURE principle #1):
//!   - NO single signal bans: `Verdict::Ban` structurally requires at least
//!     `min_corroborating_signals` DISTINCT signal ids at Moderate tier or
//!     above, in addition to the score threshold. This is the fusion-side
//!     enforcement of `telemetry::analyzers::STANDALONE_BANNABLE == false`.
//!   - Fail closed on garbage, fail OPEN on nothing: a non-finite z-score or
//!     an under-sampled event is SKIPPED (recorded with a reason, so the
//!     audit record carries the exculpatory evidence) rather than failing the
//!     whole call — one buggy analyzer must not blind the other eight.
//!   - All thresholds/weights are conservative hand-set priors pending the
//!     signed-rule bundle (guardrail #14; same posture as `loader_inject.rs`).
//!     `FusionParams` is shaped like `CadenceParams` (struct + `validate()`)
//!     so it is already the signed-bundle deserialization target.
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — `thiserror` via `BanEngineError`; no `unwrap()` outside
//! tests; total over adversarial input.

use serde::Serialize;
use telemetry::analyzers::SuspicionEvent;

use crate::arrival_cadence::CadenceObservation;
use crate::error::BanEngineError;

/// Catalog signal id for the arrival-cadence (lag-switch) observation fused
/// alongside the gamestate analyzers.
pub const SIGNAL_ARRIVAL_CADENCE: u16 = 186;

/// Fusion thresholds and weights. Conservative hand-set priors (guardrail #14):
/// the live values arrive as a SIGNED rule through `crate::bundle`; these
/// defaults preserve the catalog FP posture for the scaffold's own tests.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct FusionParams {
    /// z-score tier floors. Events below `z_weak` are ignored (recorded as
    /// skipped). Tiers are load-bearing: analyzers do not uniformly gate on a
    /// z threshold before emitting (e.g. occlusion-preaim emits any
    /// negative-tail z once its recurrence floor is met).
    pub z_weak: f64,
    pub z_moderate: f64,
    pub z_strong: f64,
    /// Per-tier score weights (mirrors the `loader_inject` integer-units style).
    pub w_weak: u32,
    pub w_moderate: u32,
    pub w_strong: u32,
    /// Weight of a flagged arrival-cadence observation (Moderate tier).
    pub w_cadence: u32,
    /// Recurrence floor: events with fewer qualifying samples are skipped.
    pub min_samples: u32,
    /// Score at/above which the verdict is at least `Review`.
    pub review_threshold: u32,
    /// Score at/above which a ban is CONSIDERED (corroboration still required).
    pub ban_threshold: u32,
    /// Distinct signal ids at Moderate+ tier required before `Ban` is possible.
    /// MUST be >= 2 — the structural no-single-signal gate.
    pub min_corroborating_signals: u32,
}

impl Default for FusionParams {
    fn default() -> Self {
        FusionParams {
            z_weak: 2.5,
            z_moderate: 3.0,
            z_strong: 4.0,
            w_weak: 10,
            w_moderate: 25,
            w_strong: 40,
            w_cadence: 25,
            min_samples: 3,
            review_threshold: 40,
            ban_threshold: 70,
            min_corroborating_signals: 2,
        }
    }
}

impl FusionParams {
    pub fn validate(&self) -> Result<(), BanEngineError> {
        let finite_ordered = self.z_weak.is_finite()
            && self.z_moderate.is_finite()
            && self.z_strong.is_finite()
            && self.z_weak > 0.0
            && self.z_weak <= self.z_moderate
            && self.z_moderate <= self.z_strong;
        if !finite_ordered {
            return Err(BanEngineError::InvalidFusionParams(
                "z tiers must be finite, positive, and ordered weak <= moderate <= strong",
            ));
        }
        if self.w_weak > self.w_moderate || self.w_moderate > self.w_strong {
            return Err(BanEngineError::InvalidFusionParams(
                "tier weights must be ordered weak <= moderate <= strong",
            ));
        }
        if self.review_threshold == 0 || self.review_threshold > self.ban_threshold {
            return Err(BanEngineError::InvalidFusionParams(
                "thresholds must satisfy 0 < review <= ban",
            ));
        }
        // The structural no-single-signal gate: a params bundle that lowers this
        // below 2 would let one signal ban — rejected regardless of source.
        if self.min_corroborating_signals < 2 {
            return Err(BanEngineError::InvalidFusionParams(
                "min_corroborating_signals must be >= 2 (no single signal bans)",
            ));
        }
        Ok(())
    }
}

/// Strength tier an event landed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Tier {
    Weak,
    Moderate,
    Strong,
}

/// Session verdict, ordered: `Clean < Review < Ban`. The pipeline latches the
/// per-session verdict to the maximum ever reached (no auto-downgrade).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Verdict {
    Clean,
    Review,
    Ban,
}

/// One event that contributed to the score (inculpatory evidence).
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Contribution {
    pub signal_id: u16,
    pub zscore: f64,
    pub sample_count: u32,
    pub window_ticks: u64,
    pub tier: Tier,
    pub weight: u32,
}

/// One event that was NOT counted, and why (exculpatory evidence — audit
/// records must show what was rejected, not only what convicted).
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct SkippedEvent {
    pub signal_id: u16,
    pub zscore: f64,
    pub sample_count: u32,
    pub reason: &'static str,
}

/// The full fusion result for one scoring pass.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FusionOutcome {
    pub verdict: Verdict,
    pub score: u32,
    pub contributions: Vec<Contribution>,
    pub skipped: Vec<SkippedEvent>,
    pub cadence: Option<CadenceObservation>,
}

/// Fuse one scoring pass. Pure; the caller owns latching and persistence.
pub fn fuse(
    events: &[SuspicionEvent],
    cadence: Option<CadenceObservation>,
    params: &FusionParams,
) -> Result<FusionOutcome, BanEngineError> {
    params.validate()?;

    let mut contributions: Vec<Contribution> = Vec::new();
    let mut skipped: Vec<SkippedEvent> = Vec::new();

    for ev in events {
        let reason = if !ev.zscore.is_finite() {
            Some("non-finite zscore")
        } else if ev.sample_count < params.min_samples {
            Some("below sample floor")
        } else if ev.zscore < params.z_weak {
            Some("below weak tier")
        } else {
            None
        };
        if let Some(reason) = reason {
            skipped.push(SkippedEvent {
                signal_id: ev.signal_id,
                zscore: ev.zscore,
                sample_count: ev.sample_count,
                reason,
            });
            continue;
        }

        let (tier, weight) = if ev.zscore >= params.z_strong {
            (Tier::Strong, params.w_strong)
        } else if ev.zscore >= params.z_moderate {
            (Tier::Moderate, params.w_moderate)
        } else {
            (Tier::Weak, params.w_weak)
        };

        let c = Contribution {
            signal_id: ev.signal_id,
            zscore: ev.zscore,
            sample_count: ev.sample_count,
            window_ticks: ev.window_ticks,
            tier,
            weight,
        };
        // Defensive dedupe: the registry yields at most one event per analyzer,
        // but a duplicated signal id must never double-count toward the
        // corroboration gate — keep the strongest.
        match contributions
            .iter_mut()
            .find(|e| e.signal_id == c.signal_id)
        {
            Some(existing) => {
                if c.weight > existing.weight
                    || (c.weight == existing.weight && c.zscore > existing.zscore)
                {
                    *existing = c;
                }
            }
            None => contributions.push(c),
        }
    }

    if let Some(obs) = &cadence {
        if obs.flagged {
            contributions.push(Contribution {
                signal_id: SIGNAL_ARRIVAL_CADENCE,
                zscore: f64::from(obs.conserved_repeats),
                sample_count: obs.conserved_repeats,
                window_ticks: 0,
                tier: Tier::Moderate,
                weight: params.w_cadence,
            });
        }
    }

    let score: u32 = contributions
        .iter()
        .fold(0u32, |acc, c| acc.saturating_add(c.weight));
    let corroborating = contributions
        .iter()
        .filter(|c| c.tier >= Tier::Moderate)
        .count() as u32;

    let verdict =
        if score >= params.ban_threshold && corroborating >= params.min_corroborating_signals {
            Verdict::Ban
        } else if score >= params.review_threshold {
            Verdict::Review
        } else {
            Verdict::Clean
        };

    Ok(FusionOutcome {
        verdict,
        score,
        contributions,
        skipped,
        cadence,
    })
}
