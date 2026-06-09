//! src/analyzers/recoil_rng_corr.rs
//!
//! Role: recoil/spread-RNG compensation under zero-feedback analyzer (catalog signal
//! 180). During ticks where the player is FIRING but has NO line-of-sight to any enemy
//! and NO tracer feedback, it correlates the player's integrated counter-motion
//! (`aim_delta_*`) against the authoritative per-shot recoil vector
//! (`snap.recoil_rng_vec`). The discriminator is correlation to the per-shot RANDOM
//! component — the learnable MEAN recoil pattern (supplied as a signed weapon curve)
//! is subtracted from both streams first (`stats::corr_random_component`), so a
//! skilled player who has memorized the mean pattern correlates ~0 while a cheat
//! reading the RNG correlates high. Requires statistical significance over many
//! shots. Read-only; fuses in `ban-engine` (never standalone).
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — no `unwrap()` outside tests; `feed` is total over its input. The
//! learnable recoil mean is SIGNED rule data (rides `ban-engine::bundle`), so it is
//! injected as a closure here, never hardcoded (mirrors `aim_kinematics`).

use crate::analyzers::{Analyzer, SignalId, SuspicionEvent};
use crate::error::TelemetryError;
use crate::schema::TickPayload;
use crate::snapshot::Snapshot;
use crate::stats::corr_random_component;

/// Minimum no-feedback firing samples before a correlation is significant.
const MIN_SHOTS: u32 = 12;

/// Correlation magnitude above which the random-component tracking is the tell.
const CORR_THRESHOLD: f64 = 0.6;

/// Signature of the signed, learnable mean-recoil curve: `(weapon_id, shot_index) ->
/// expected recoil X/Y mean`. Injected so no recoil data is hardcoded.
pub type RecoilMeanFn = dyn Fn(u32, u32) -> (f32, f32) + Send;

pub struct RecoilRngCorr {
    player_id: u64,
    /// Player counter-motion samples (x, y) during no-feedback firing ticks.
    applied_x: Vec<f64>,
    applied_y: Vec<f64>,
    /// Authoritative recoil samples (x, y) the same ticks.
    recoil_x: Vec<f64>,
    recoil_y: Vec<f64>,
    /// Learnable mean per the same ticks.
    mean_x: Vec<f64>,
    mean_y: Vec<f64>,
    /// Injected signed mean-recoil curve. Defaults to zero-mean (pure RNG) when the
    /// signed bundle has not supplied one (then any correlation IS to the full recoil,
    /// a weaker but still server-only signal).
    mean_fn: Box<RecoilMeanFn>,
    first_tick: Option<u64>,
    last_tick: u64,
}

impl RecoilRngCorr {
    pub fn new(player_id: u64) -> Self {
        Self::with_mean_curve(player_id, Box::new(|_w, _s| (0.0, 0.0)))
    }

    /// Construct with an injected signed mean-recoil curve.
    pub fn with_mean_curve(player_id: u64, mean_fn: Box<RecoilMeanFn>) -> Self {
        RecoilRngCorr {
            player_id,
            applied_x: Vec::new(),
            applied_y: Vec::new(),
            recoil_x: Vec::new(),
            recoil_y: Vec::new(),
            mean_x: Vec::new(),
            mean_y: Vec::new(),
            mean_fn,
            first_tick: None,
            last_tick: 0,
        }
    }
}

impl Analyzer for RecoilRngCorr {
    fn id(&self) -> SignalId {
        180
    }

    fn feed(&mut self, tick: &TickPayload, snap: &Snapshot) -> Result<(), TelemetryError> {
        self.first_tick.get_or_insert(snap.tick);
        self.last_tick = snap.tick;

        // Only firing ticks count.
        if !tick.fire_active && !tick.fired {
            return Ok(());
        }
        // Zero-feedback gate: no enemy visible (no tracer/visual recoil feedback the
        // player could be reacting to). If any enemy is visible this tick, skip it.
        let any_visible = (0..snap.entities.len()).any(|i| snap.is_visible(i));
        if any_visible {
            return Ok(());
        }

        let (mx, my) = (self.mean_fn)(tick.weapon_id, tick.shot_index);
        self.applied_x.push(tick.aim_delta_x as f64);
        self.applied_y.push(tick.aim_delta_y as f64);
        self.recoil_x.push(snap.recoil_rng_vec.x as f64);
        self.recoil_y.push(snap.recoil_rng_vec.y as f64);
        self.mean_x.push(mx as f64);
        self.mean_y.push(my as f64);
        Ok(())
    }

    fn score(&self) -> Option<SuspicionEvent> {
        if (self.applied_x.len() as u32) < MIN_SHOTS {
            return None;
        }
        let cx = corr_random_component(&self.applied_x, &self.recoil_x, &self.mean_x);
        let cy = corr_random_component(&self.applied_y, &self.recoil_y, &self.mean_y);
        // Take the stronger axis; a cheat compensating the RNG correlates on both, but
        // either axis crossing threshold is the tell.
        let best = match (cx, cy) {
            (Some(a), Some(b)) => a.abs().max(b.abs()),
            (Some(a), None) => a.abs(),
            (None, Some(b)) => b.abs(),
            (None, None) => return None,
        };
        if best < CORR_THRESHOLD {
            return None;
        }
        Some(SuspicionEvent {
            player_id: self.player_id,
            signal_id: self.id(),
            zscore: best,
            sample_count: self.applied_x.len() as u32,
            window_ticks: self.last_tick.saturating_sub(self.first_tick.unwrap_or(0)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geom::Vec3;
    use crate::snapshot::fixtures::base_snapshot;

    fn firing_tick(idx: u32, applied_x: f32) -> TickPayload {
        TickPayload {
            fire_active: true,
            weapon_id: 1,
            shot_index: idx,
            aim_delta_x: applied_x,
            ..Default::default()
        }
    }

    /// Cheat: the player's counter-motion tracks the authoritative RANDOM recoil
    /// component (mean subtracted) with no visible enemy -> high correlation -> scores.
    #[test]
    fn rng_component_correlation_scores() {
        let mean_curve = |_w: u32, s: u32| (0.01 * (s as f32 + 1.0), 0.0);
        let mut a = RecoilRngCorr::with_mean_curve(1, Box::new(mean_curve));
        let rng = [
            0.3f32, -0.4, 0.5, -0.2, 0.4, -0.3, 0.35, -0.25, 0.45, -0.15, 0.2, -0.5, 0.1, -0.35,
        ];
        for (i, &r) in rng.iter().enumerate() {
            let mean = 0.01 * (i as f32 + 1.0);
            let mut s = base_snapshot(i as u64, i as u64 * 1_000_000);
            s.recoil_rng_vec = Vec3::new(mean + r, 0.0, 0.0);
            // Cheat counter-motion = -(mean + rng): perfectly cancels incl. the RNG.
            a.feed(&firing_tick(i as u32, -(mean + r)), &s)
                .expect("feed");
        }
        let ev = a.score().expect("RNG-correlated compensation scores");
        assert_eq!(ev.signal_id, 180);
        assert!(ev.zscore >= CORR_THRESHOLD);
    }

    /// Clean: a skilled player matches only the learnable MEAN recoil pattern and
    /// ignores the RNG -> ~0 correlation to the random component -> no score.
    #[test]
    fn mean_pattern_only_is_clean() {
        let mean_curve = |_w: u32, s: u32| (0.01 * (s as f32 + 1.0), 0.0);
        let mut a = RecoilRngCorr::with_mean_curve(1, Box::new(mean_curve));
        let rng = [
            0.3f32, -0.4, 0.5, -0.2, 0.4, -0.3, 0.35, -0.25, 0.45, -0.15, 0.2, -0.5, 0.1, -0.35,
        ];
        for (i, &r) in rng.iter().enumerate() {
            let mean = 0.01 * (i as f32 + 1.0);
            let mut s = base_snapshot(i as u64, i as u64 * 1_000_000);
            s.recoil_rng_vec = Vec3::new(mean + r, 0.0, 0.0);
            // Human compensates only the MEAN: applied = -mean (no RNG knowledge).
            a.feed(&firing_tick(i as u32, -mean), &s).expect("feed");
        }
        assert!(a.score().is_none(), "mean-only compensation is clean");
    }

    /// Clean: an enemy is VISIBLE while firing -> tracer/visual feedback could explain
    /// the compensation -> the tick is excluded from the zero-feedback correlation.
    #[test]
    fn visible_enemy_excludes_ticks() {
        let mean_curve = |_w: u32, s: u32| (0.01 * (s as f32 + 1.0), 0.0);
        let mut a = RecoilRngCorr::with_mean_curve(1, Box::new(mean_curve));
        for i in 0..20u32 {
            let mut s = base_snapshot(i as u64, i as u64 * 1_000_000);
            s.recoil_rng_vec = Vec3::new(0.5, 0.0, 0.0);
            s.entities.push(crate::snapshot::EntityState {
                entity_id: 100,
                position: Vec3::new(10.0, 0.0, 0.0),
                velocity: Vec3::ZERO,
                flags: crate::snapshot::ipc::ENT_ALIVE,
            });
            s.visibility.push(true); // visible -> excluded
            s.audiopath.push(false);
            a.feed(&firing_tick(i, -0.5), &s).expect("feed");
        }
        assert!(
            a.score().is_none(),
            "visible-enemy firing ticks are excluded"
        );
    }
}
