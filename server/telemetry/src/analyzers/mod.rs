//! Role: analyzer trait + pipeline registry for the behavioral-gamestate-knowledge
//! domain (catalog signals 172-180). Each analyzer replays the authoritative snapshot
//! stream against the client-reported `TickPayload` and proves the player acted on
//! information they could not legitimately have. Every analyzer is read-only and
//! emits a `SuspicionEvent` (player, signal, z-score, sample/window counts) for FUSION
//! by `ban-engine` — analyzers NEVER ban, and per the catalog FP policy NO single
//! game-state signal may stand alone (encoded as the `STANDALONE_BANNABLE` invariant
//! below, always false for this domain).
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — `thiserror` via `TelemetryError`; no `unwrap()` outside tests;
//! `feed` returns `Result` so a degenerate tick is an error, not a panic. #14 — the
//! Phase-2/3 scoring here is the DETERMINISTIC statistical gate (z-score/p95/FFT/
//! correlation in `crate::stats`); ML fusion is a later phase.

use crate::error::TelemetryError;
use crate::schema::TickPayload;
use crate::snapshot::Snapshot;

pub mod attention_budget;
pub mod dynamic_occluder;
pub mod flick_precog;
pub mod occlusion_preaim;
pub mod peek_latency;
pub mod positional_prior;
pub mod recoil_rng_corr;
pub mod refresh_aliasing;
pub mod vision_cone;

/// Catalog signal id for a game-state analyzer (172..=180).
pub type SignalId = u16;

/// POLICY INVARIANT (catalog FP gate): no single game-state-knowledge signal may
/// auto-ban. `SuspicionEvent`s are fused by `ban-engine`; this constant documents and
/// pins the invariant so a future caller cannot wire a standalone ban off one signal.
pub const STANDALONE_BANNABLE: bool = false;

/// A read-only suspicion finding handed to `ban-engine` for fusion. Carries the
/// statistical strength (`zscore`) and the support (`sample_count`, `window_ticks`)
/// so the fusion layer can weight it; it is NEVER a verdict.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SuspicionEvent {
    pub player_id: u64,
    pub signal_id: SignalId,
    /// Population z-score of the accumulated tell (higher = more anomalous).
    pub zscore: f64,
    /// Number of qualifying engagements/events that fed the score.
    pub sample_count: u32,
    /// Span of ticks the score was accumulated over.
    pub window_ticks: u64,
}

/// The analyzer contract. `feed` ingests one paired (client tick, authoritative
/// snapshot); `score` reports a `SuspicionEvent` once the analyzer's recurrence and
/// significance thresholds are met, else `None`.
pub trait Analyzer: Send {
    /// Catalog signal id (172..=180).
    fn id(&self) -> SignalId;
    /// Ingest one paired tick + authoritative snapshot. Returns an error on a
    /// malformed pairing (e.g. a tick whose features cannot be reconciled with the
    /// snapshot); never panics.
    fn feed(&mut self, tick: &TickPayload, snap: &Snapshot) -> Result<(), TelemetryError>;
    /// Current suspicion verdict, or `None` until threshold + recurrence are met.
    fn score(&self) -> Option<SuspicionEvent>;
}

/// The registered set of game-state analyzers for one player session. Owns a boxed
/// analyzer per signal and fans each fed tick out to all of them. The HTTP ingest
/// path (`lib.rs`) constructs one registry per tracked session; `drain_suspicions`
/// collects the events to forward to `ban-engine`.
///
/// Lifecycle: construct one `AnalyzerRegistry` per player session and discard it
/// when the session ends. Never reuse an instance across matches — analyzers
/// accumulate per-session state (latency series, EWMA estimators, burst windows)
/// that is only meaningful within a single continuous session.
pub struct AnalyzerRegistry {
    player_id: u64,
    analyzers: Vec<Box<dyn Analyzer>>,
}

impl AnalyzerRegistry {
    /// Build the full domain registry (signals 172-180) for one player.
    pub fn new(player_id: u64) -> Self {
        let analyzers: Vec<Box<dyn Analyzer>> = vec![
            Box::new(occlusion_preaim::OcclusionPreaim::new(player_id)),
            Box::new(flick_precog::FlickPrecog::new(player_id)),
            Box::new(vision_cone::VisionCone::new(player_id)),
            Box::new(attention_budget::AttentionBudget::new(player_id)),
            Box::new(dynamic_occluder::DynamicOccluder::new(player_id)),
            Box::new(peek_latency::PeekLatency::new(player_id)),
            Box::new(recoil_rng_corr::RecoilRngCorr::new(player_id)),
            Box::new(positional_prior::PositionalPrior::new(player_id)),
            Box::new(refresh_aliasing::RefreshAliasing::new(player_id)),
        ];
        AnalyzerRegistry {
            player_id,
            analyzers,
        }
    }

    pub fn player_id(&self) -> u64 {
        self.player_id
    }

    /// Fan one paired (tick, snapshot) out to every analyzer. All analyzers are
    /// fed regardless of individual errors so their tick state stays in sync.
    /// Returns the first error encountered, or `Ok(())` if all succeeded.
    pub fn feed(&mut self, tick: &TickPayload, snap: &Snapshot) -> Result<(), TelemetryError> {
        let mut first_err: Option<TelemetryError> = None;
        for a in self.analyzers.iter_mut() {
            if let Err(e) = a.feed(tick, snap) {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        match first_err {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }

    /// Collect every analyzer's current `SuspicionEvent` (those past threshold).
    pub fn collect_suspicions(&self) -> Vec<SuspicionEvent> {
        self.analyzers.iter().filter_map(|a| a.score()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::fixtures::base_snapshot;

    #[test]
    fn registry_has_all_nine_signals() {
        let reg = AnalyzerRegistry::new(42);
        let mut ids: Vec<SignalId> = reg.analyzers.iter().map(|a| a.id()).collect();
        ids.sort_unstable();
        assert_eq!(ids, (172..=180).collect::<Vec<_>>());
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn standalone_ban_is_disallowed() {
        // Policy invariant: no single game-state signal auto-bans.
        assert!(!STANDALONE_BANNABLE);
    }

    #[test]
    fn empty_session_emits_no_suspicions() {
        let mut reg = AnalyzerRegistry::new(7);
        let snap = base_snapshot(0, 0);
        let tick = TickPayload::default();
        reg.feed(&tick, &snap).expect("feed clean tick");
        assert!(
            reg.collect_suspicions().is_empty(),
            "clean tick -> no suspicion"
        );
    }
}
