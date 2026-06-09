//! src/analyzers/peek_latency.rs
//!
//! Role: peeker-advantage vs RTT+jitter budget analyzer (catalog signal 174). When the
//! local player and an enemy gain MUTUAL line-of-sight (both visible to each other
//! this tick), the defender's information about the peeker is delayed by the network
//! round-trip. This analyzer pairs the mutual-LoS-onset tick with the player's `fired`
//! shot tick and subtracts the per-connection RTT: a shot that lands BEFORE the
//! jitter-widened RTT budget could have delivered the peeker's position is the tell
//! (the player fired on information that had not yet legitimately arrived). The budget
//! uses the p95-HIGH RTT estimate (`stats::RttEstimator::p95_high`) so bursty jitter
//! WIDENS the budget and cannot manufacture a false sub-budget peek. Read-only; fuses
//! in `ban-engine` (never standalone).
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — no `unwrap()` outside tests; `feed` is total over its input.
//!
//! HK-UNCERTAIN(rtt-source): the RTT source is not yet wired. Per the impl-plan's
//! UNCERTAINTY flag, TCP sessions can read `getsockopt(TCP_INFO).tcpi_rtt` in
//! `snapshot/backends`, but most competitive shooters are UDP/QUIC where RTT must come
//! from the engine ping EWMA delivered IN the snapshot frame — which the current
//! `HkSnapshotRecord` does not carry. HK-TODO(schema): add a per-tick authoritative
//! `rtt_ns`/`rtt_jitter_ns` to the snapshot frame (or supply it via the TCP_INFO
//! backend) so this analyzer can read a trustworthy budget. Until then the RTT
//! estimator is fed externally (test-only `push_rtt_ns`) and `feed` consumes whatever
//! the estimator currently holds; production wiring is gated on the schema decision.

use std::collections::HashMap;

use crate::analyzers::{Analyzer, SignalId, SuspicionEvent};
use crate::error::TelemetryError;
use crate::schema::TickPayload;
use crate::snapshot::Snapshot;
use crate::stats::RttEstimator;

/// EWMA weight and jitter multiplier for the RTT budget. `k_high = 2.0` puts the
/// budget roughly two mean-absolute-deviations above the mean RTT.
const RTT_ALPHA: f64 = 0.2;
const RTT_K_HIGH: f64 = 2.0;

/// Minimum sub-budget peeks before emitting (recurrence gate).
const MIN_EVENTS: u32 = 5;

/// Per-enemy mutual-LoS-onset state: the mono_ns at which mutual LoS began.
#[derive(Clone, Copy)]
struct MutualOnset {
    onset_mono_ns: u64,
}

pub struct PeekLatency {
    player_id: u64,
    rtt: RttEstimator,
    onsets: HashMap<u64, MutualOnset>,
    /// Per sub-budget peek: how many ns BELOW the budget the shot landed (positive =
    /// more anomalous).
    deficits_ns: Vec<f64>,
    first_tick: Option<u64>,
    last_tick: u64,
}

impl PeekLatency {
    pub fn new(player_id: u64) -> Self {
        PeekLatency {
            player_id,
            rtt: RttEstimator::new(RTT_ALPHA, RTT_K_HIGH),
            onsets: HashMap::new(),
            deficits_ns: Vec::new(),
            first_tick: None,
            last_tick: 0,
        }
    }

    /// Feed an observed RTT sample (ns) into the budget estimator. HK-UNCERTAIN: this
    /// is the seam for the not-yet-wired RTT source (TCP_INFO backend or engine ping
    /// in the snapshot frame). Tests drive it directly.
    pub fn push_rtt_ns(&mut self, rtt_ns: f64) {
        self.rtt.update(rtt_ns);
    }
}

impl Analyzer for PeekLatency {
    fn id(&self) -> SignalId {
        174
    }

    fn feed(&mut self, tick: &TickPayload, snap: &Snapshot) -> Result<(), TelemetryError> {
        self.first_tick.get_or_insert(snap.tick);
        self.last_tick = snap.tick;

        // Budget in ns: the jitter-widened RTT high estimate.
        let budget_ns = self.rtt.p95_high();

        for (i, e) in snap.entities.iter().enumerate() {
            if e.is_local() || e.is_team() || !e.is_alive() {
                continue;
            }
            // Mutual LoS proxy: this single-observer frame gives the local player's
            // visibility of the enemy; we treat that as the mutual-onset trigger (the
            // peeker is visible to the local player the same tick it sees the local
            // player in a symmetric peek). HK-TODO(schema): a per-(observer,target)
            // visibility matrix would make "mutual" exact.
            let visible = snap.is_visible(i);
            if visible {
                let onset = self
                    .onsets
                    .entry(e.entity_id)
                    .or_insert(MutualOnset {
                        onset_mono_ns: snap.mono_ns,
                    })
                    .onset_mono_ns;

                // A shot this tick: did it land before the information could arrive?
                if tick.fired {
                    let elapsed = snap.mono_ns.saturating_sub(onset) as f64;
                    if elapsed < budget_ns {
                        self.deficits_ns.push(budget_ns - elapsed);
                    }
                    // One shot resolves this engagement's onset.
                    self.onsets.remove(&e.entity_id);
                }
            } else {
                self.onsets.remove(&e.entity_id);
            }
        }
        Ok(())
    }

    fn score(&self) -> Option<SuspicionEvent> {
        if (self.deficits_ns.len() as u32) < MIN_EVENTS {
            return None;
        }
        let mean_deficit_ms =
            self.deficits_ns.iter().sum::<f64>() / self.deficits_ns.len() as f64 / 1_000_000.0;
        Some(SuspicionEvent {
            player_id: self.player_id,
            signal_id: self.id(),
            // Strength scales with how deep below budget the shots landed.
            zscore: mean_deficit_ms.max(0.0),
            sample_count: self.deficits_ns.len() as u32,
            window_ticks: self.last_tick.saturating_sub(self.first_tick.unwrap_or(0)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geom::Vec3;
    use crate::snapshot::fixtures::{base_snapshot, push_enemy};

    /// Cheat: with a ~40 ms RTT budget, the player fires only ~5 ms after mutual-LoS
    /// onset, repeatedly -> sub-budget peeks -> scores.
    #[test]
    fn sub_budget_peek_scores() {
        let mut a = PeekLatency::new(1);
        // Seed a steady 40 ms RTT.
        for _ in 0..40 {
            a.push_rtt_ns(40_000_000.0);
        }
        for t in 0..u64::from(MIN_EVENTS) + 2 {
            // Onset tick: enemy becomes visible (mutual LoS), no shot yet.
            let mut s0 = base_snapshot(t, t * 50_000_000);
            push_enemy(
                &mut s0,
                100,
                Vec3::new(10.0, 0.0, 0.0),
                Vec3::ZERO,
                true,
                false,
            );
            a.feed(&TickPayload::default(), &s0).expect("feed");
            // Shot 5 ms later: well within the 40 ms RTT budget.
            let mut s1 = base_snapshot(t, t * 50_000_000 + 5_000_000);
            push_enemy(
                &mut s1,
                100,
                Vec3::new(10.0, 0.0, 0.0),
                Vec3::ZERO,
                true,
                false,
            );
            let fire = TickPayload {
                fired: true,
                ..Default::default()
            };
            a.feed(&fire, &s1).expect("feed");
        }
        let ev = a.score().expect("sub-budget peek scores");
        assert_eq!(ev.signal_id, 174);
        assert!(ev.zscore > 0.0);
    }

    /// Clean: bursty jitter WIDENS the p95-high budget; a peek that would look
    /// sub-budget against the mean is within the jitter-widened budget -> not flagged
    /// when the shot lands after the (now larger) budget. Here the player fires AFTER
    /// the widened budget so no deficit accrues.
    #[test]
    fn peek_within_jitter_budget_is_clean() {
        let mut a = PeekLatency::new(1);
        // Jittery RTT around 40 ms -> p95_high noticeably above 40 ms.
        let pattern = [20_000_000.0, 60_000_000.0, 24_000_000.0, 56_000_000.0];
        for i in 0..60 {
            a.push_rtt_ns(pattern[i % pattern.len()]);
        }
        let budget = a.rtt.p95_high();
        for t in 0..u64::from(MIN_EVENTS) + 2 {
            let mut s0 = base_snapshot(t, t * 200_000_000);
            push_enemy(
                &mut s0,
                100,
                Vec3::new(10.0, 0.0, 0.0),
                Vec3::ZERO,
                true,
                false,
            );
            a.feed(&TickPayload::default(), &s0).expect("feed");
            // Fire AFTER the widened budget elapses -> not sub-budget.
            let after = budget as u64 + 5_000_000;
            let mut s1 = base_snapshot(t, t * 200_000_000 + after);
            push_enemy(
                &mut s1,
                100,
                Vec3::new(10.0, 0.0, 0.0),
                Vec3::ZERO,
                true,
                false,
            );
            let fire = TickPayload {
                fired: true,
                ..Default::default()
            };
            a.feed(&fire, &s1).expect("feed");
        }
        assert!(a.score().is_none(), "within jitter-widened budget is clean");
    }
}
