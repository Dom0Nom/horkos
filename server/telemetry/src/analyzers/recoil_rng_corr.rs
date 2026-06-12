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
