//! Role: positional-prior beelining (entropy-collapsed pathing) analyzer (catalog
//! signal 176). Logs the local player's authoritative position/velocity and measures
//! how directly they path toward a SERVER-RANDOM objective/spawn (gated on the
//! `objective_seed` actually being randomized this match — a fixed-meta spawn is NOT
//! scoreable). Two collapsing signals: low heading-change entropy (the path is a
//! straight beeline, not a human's exploratory route) and low divergence from the
//! optimal navmesh A* route to the random objective. A player who beelines to a
//! location they could only know from a map/radar cheat reading the random seed is the
//! tell. Weak prior — never standalone (`STANDALONE_BANNABLE`); the lowest-FP-weight
//! signal in the domain. Read-only; fuses in `ban-engine`.
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — no `unwrap()` outside tests; `feed` is total over its input.
//!
//! HK-UNCERTAIN(navmesh): A*/navmesh ownership is unresolved (impl-plan UNCERTAINTY
//! flag #2). If the engine supplies the optimal route, divergence is cheap to compute;
//! if telemetry must run A* itself it needs the navmesh blob + a pathfinder
//! dependency. Until that decision is made, the A*-divergence term is NOT computed —
//! only the heading-entropy / beeline-straightness term (which needs only the logged
//! authoritative transforms) is active. HK-TODO(schema): an authoritative
//! `objective_pos` + a route/navmesh handle in the snapshot frame would enable the
//! divergence term. Do NOT guess a navmesh format here.

use crate::analyzers::{Analyzer, SignalId, SuspicionEvent};
use crate::error::TelemetryError;
use crate::geom::{angular_error, Vec3};
use crate::schema::TickPayload;
use crate::snapshot::Snapshot;

/// Heading-change-entropy ceiling below which the path is a suspicious beeline. A
/// human's route has higher heading entropy (course corrections, exploration).
const ENTROPY_BEELINE_CEILING: f64 = 0.30;

/// Minimum logged path samples before the entropy is meaningful.
const MIN_SAMPLES: usize = 16;

/// Number of distinct beeline-to-random-objective runs needed before emitting.
const MIN_RUNS: u32 = 3;

pub struct PositionalPrior {
    player_id: u64,
    /// Successive local-player velocity headings (unit) for entropy.
    headings: Vec<Vec3>,
    /// Whether the objective seed was randomized this match (gate).
    seed_randomized: bool,
    /// Completed beeline runs (one per low-entropy path segment to a random objective).
    beeline_runs: u32,
    /// Lowest entropy observed in a scoreable run (strength proxy).
    min_entropy: f64,
    first_tick: Option<u64>,
    last_tick: u64,
}

impl PositionalPrior {
    pub fn new(player_id: u64) -> Self {
        PositionalPrior {
            player_id,
            headings: Vec::new(),
            seed_randomized: false,
            beeline_runs: 0,
            min_entropy: 1.0,
            first_tick: None,
            last_tick: 0,
        }
    }

    /// Normalized heading-change entropy of the logged path, in [0, 1]. Quantizes the
    /// per-step heading change into bins and computes the normalized Shannon entropy:
    /// a straight beeline (all changes ~0) collapses to ~0; an exploratory path
    /// spreads across bins toward 1.
    fn heading_entropy(&self) -> f64 {
        if self.headings.len() < 2 {
            return 1.0;
        }
        const BINS: usize = 8;
        let mut hist = [0u32; BINS];
        let mut total = 0u32;
        for w in self.headings.windows(2) {
            let change = angular_error(w[0], Vec3::ZERO, w[1]).unwrap_or(0.0);
            // Map [0, PI] -> bin.
            let frac = (change / std::f32::consts::PI).clamp(0.0, 0.999);
            let bin = (frac * BINS as f32) as usize;
            hist[bin] += 1;
            total += 1;
        }
        if total == 0 {
            return 1.0;
        }
        let mut h = 0.0;
        for &c in hist.iter() {
            if c == 0 {
                continue;
            }
            let p = c as f64 / total as f64;
            h -= p * p.ln();
        }
        // Normalize by ln(BINS) so the result is in [0, 1].
        h / (BINS as f64).ln()
    }
}

impl Analyzer for PositionalPrior {
    fn id(&self) -> SignalId {
        176
    }

    fn feed(&mut self, _tick: &TickPayload, snap: &Snapshot) -> Result<(), TelemetryError> {
        self.first_tick.get_or_insert(snap.tick);
        self.last_tick = snap.tick;

        // Gate: only a match with a RANDOMIZED objective seed is scoreable (a fixed
        // meta spawn that a player legitimately memorizes must not trip).
        if snap.objective_seed != 0 {
            self.seed_randomized = true;
        }

        // Log the local player's authoritative heading.
        if let Some(idx) = snap.index_of(snap.local_player_id) {
            if let Some(e) = snap.entities.get(idx) {
                let h = e.velocity.normalized();
                if h != Vec3::ZERO {
                    self.headings.push(h);
                }
            }
        }

        // When we have enough path, evaluate the run and reset the window.
        if self.headings.len() >= MIN_SAMPLES {
            let entropy = self.heading_entropy();
            if self.seed_randomized && entropy < ENTROPY_BEELINE_CEILING {
                self.beeline_runs += 1;
                self.min_entropy = self.min_entropy.min(entropy);
            }
            self.headings.clear();
        }
        Ok(())
    }

    fn score(&self) -> Option<SuspicionEvent> {
        if self.beeline_runs < MIN_RUNS {
            return None;
        }
        Some(SuspicionEvent {
            player_id: self.player_id,
            signal_id: self.id(),
            // Lower entropy => stronger; map to a positive strength.
            zscore: (ENTROPY_BEELINE_CEILING - self.min_entropy).max(0.0),
            sample_count: self.beeline_runs,
            window_ticks: self.last_tick.saturating_sub(self.first_tick.unwrap_or(0)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::fixtures::base_snapshot;

    fn local_moving(tick: u64, heading: Vec3, seed: u64) -> Snapshot {
        let mut s = base_snapshot(tick, tick * 1_000_000);
        s.objective_seed = seed;
        s.local_player_id = 1;
        s.entities.push(crate::snapshot::EntityState {
            entity_id: 1,
            position: Vec3::new(tick as f32, 0.0, 0.0),
            velocity: heading,
            flags: crate::snapshot::ipc::ENT_ALIVE | crate::snapshot::ipc::ENT_LOCAL,
        });
        s.visibility.push(false);
        s.audiopath.push(false);
        s
    }

    /// Cheat: dead-straight beeline (constant heading) toward a random objective across
    /// several runs -> entropy collapses -> scores.
    #[test]
    fn beeline_to_random_objective_scores() {
        let mut a = PositionalPrior::new(1);
        for run in 0..MIN_RUNS + 1 {
            for k in 0..MIN_SAMPLES + 1 {
                let t = (run as u64) * 100 + k as u64;
                // Constant heading -> zero heading-change entropy.
                let s = local_moving(t, Vec3::new(1.0, 0.0, 0.0), 0xABCDEF);
                a.feed(&TickPayload::default(), &s).expect("feed");
            }
        }
        let ev = a.score().expect("beeline to random objective scores");
        assert_eq!(ev.signal_id, 176);
        assert!(ev.zscore >= 0.0);
        assert!(ev.sample_count >= MIN_RUNS);
    }

    /// Clean: the SAME straight beeline but the objective seed is fixed (== 0) ->
    /// not a random objective -> not scoreable.
    #[test]
    fn beeline_to_fixed_meta_spawn_is_clean() {
        let mut a = PositionalPrior::new(1);
        for run in 0..MIN_RUNS + 1 {
            for k in 0..MIN_SAMPLES + 1 {
                let t = (run as u64) * 100 + k as u64;
                let s = local_moving(t, Vec3::new(1.0, 0.0, 0.0), 0); // fixed seed
                a.feed(&TickPayload::default(), &s).expect("feed");
            }
        }
        assert!(a.score().is_none(), "fixed-meta-spawn beeline is clean");
    }

    /// Clean: an exploratory (high heading-entropy) path to a random objective does not
    /// collapse -> no beeline run -> no score. A real exploratory route has VARIED turn
    /// magnitudes (small corrections, sharp reversals, gentle arcs), which spread the
    /// heading-change histogram across bins; a uniform zig-zag of one fixed turn angle
    /// would not (it is as low-entropy as a beeline), so the headings below are chosen
    /// to span a range of turn magnitudes.
    #[test]
    fn exploratory_path_is_clean() {
        use std::f32::consts::PI;
        let mut a = PositionalPrior::new(1);
        // Cumulative heading angles whose successive differences vary widely:
        // +18deg, +90deg, -126deg, +54deg, +162deg, -36deg ... so the turn-magnitude
        // histogram is spread, not concentrated in one bin.
        let turn_steps_deg = [18.0_f32, 90.0, -126.0, 54.0, 162.0, -36.0, 108.0];
        for run in 0..MIN_RUNS + 1 {
            let mut angle_deg = 0.0_f32;
            for k in 0..MIN_SAMPLES + 1 {
                let t = (run as u64) * 100 + k as u64;
                angle_deg += turn_steps_deg[k % turn_steps_deg.len()];
                let rad = angle_deg * PI / 180.0;
                let h = Vec3::new(rad.cos(), rad.sin(), 0.0);
                let s = local_moving(t, h, 0xABCDEF);
                a.feed(&TickPayload::default(), &s).expect("feed");
            }
        }
        assert!(a.score().is_none(), "exploratory path is clean");
    }
}
