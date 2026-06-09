//! src/analyzers/attention_budget.rs
//!
//! Role: multi-target attention-impossibility analyzer (catalog signal 179). Over a
//! sliding tick window it counts the DISTINCT occluded enemies that each independently
//! drew a correct corrective reaction from the player; it subtracts any enemy a
//! teammate had line-of-sight on (callout-explainable) and any with an authoritative
//! audio path. A residual count of simultaneously-tracked occluded+silent+uncalled
//! enemies above the human attention budget, occurring REPEATEDLY, is the tell — a
//! human cannot correctly track more than a few unseen actors at once. Read-only;
//! fuses in `ban-engine` (never standalone).
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — no `unwrap()` outside tests; `feed` is total over its input.

use std::collections::HashSet;

use crate::analyzers::{Analyzer, SignalId, SuspicionEvent};
use crate::error::TelemetryError;
use crate::geom::{aim_from_yaw_pitch, angular_error, view_basis};
use crate::schema::TickPayload;
use crate::snapshot::Snapshot;

/// Aim error (rad) below which the player is considered to be "tracking" an enemy
/// this tick (a near-lock).
const TRACK_LOCK_RAD: f32 = 0.05;

/// Sliding window length (ticks) over which simultaneous tracking is counted.
const WINDOW_TICKS: u64 = 16;

/// Human attention budget: the maximum distinct occluded+silent+uncalled enemies a
/// human can correctly track at once. Above this is the impossibility.
const ATTENTION_BUDGET: usize = 2;

/// How many windows must exceed the budget before emitting (recurrence gate).
const MIN_OVERBUDGET_WINDOWS: u32 = 4;

pub struct AttentionBudget {
    player_id: u64,
    /// Enemies tracked while occluded+silent+uncalled within the current window.
    window_tracked: HashSet<u64>,
    window_start: u64,
    /// Count of windows whose residual tracked-count exceeded the budget.
    overbudget_windows: u32,
    /// Max residual count seen in any over-budget window (strength proxy).
    max_residual: usize,
    first_tick: Option<u64>,
    last_tick: u64,
}

impl AttentionBudget {
    pub fn new(player_id: u64) -> Self {
        AttentionBudget {
            player_id,
            window_tracked: HashSet::new(),
            window_start: 0,
            overbudget_windows: 0,
            max_residual: 0,
            first_tick: None,
            last_tick: 0,
        }
    }

    fn close_window(&mut self) {
        let residual = self.window_tracked.len();
        if residual > ATTENTION_BUDGET {
            self.overbudget_windows += 1;
            self.max_residual = self.max_residual.max(residual);
        }
        self.window_tracked.clear();
    }
}

impl Analyzer for AttentionBudget {
    fn id(&self) -> SignalId {
        179
    }

    fn feed(&mut self, tick: &TickPayload, snap: &Snapshot) -> Result<(), TelemetryError> {
        if self.first_tick.is_none() {
            self.first_tick = Some(snap.tick);
            self.window_start = snap.tick;
        }
        self.last_tick = snap.tick;

        // Roll the sliding window.
        if snap.tick.saturating_sub(self.window_start) >= WINDOW_TICKS {
            self.close_window();
            self.window_start = snap.tick;
        }

        let basis = view_basis(snap.cam_forward, snap.cam_up);
        let aim = basis.map(|(f, u)| aim_from_yaw_pitch(f, u, tick.aim_delta_x, tick.aim_delta_y));

        for (i, e) in snap.entities.iter().enumerate() {
            if e.is_local() || e.is_team() || !e.is_alive() {
                continue;
            }
            // Only occluded + silent + uncalled enemies count toward the budget.
            if snap.is_visible(i) || snap.has_audio_path(i) || snap.teammate_has_los(i) {
                continue;
            }
            if let Some(a) = aim {
                if let Some(err) = angular_error(a, snap.cam_origin, e.position) {
                    if err <= TRACK_LOCK_RAD {
                        self.window_tracked.insert(e.entity_id);
                    }
                }
            }
        }
        Ok(())
    }

    fn score(&self) -> Option<SuspicionEvent> {
        if self.overbudget_windows < MIN_OVERBUDGET_WINDOWS {
            return None;
        }
        // Strength scales with how far over the budget the worst window ran.
        let z = (self.max_residual.saturating_sub(ATTENTION_BUDGET)) as f64
            + self.overbudget_windows as f64;
        Some(SuspicionEvent {
            player_id: self.player_id,
            signal_id: self.id(),
            zscore: z,
            sample_count: self.overbudget_windows,
            window_ticks: self.last_tick.saturating_sub(self.first_tick.unwrap_or(0)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geom::Vec3;
    use crate::snapshot::fixtures::base_snapshot;

    fn aim_at(target: Vec3, origin: Vec3) -> TickPayload {
        let d = target - origin;
        TickPayload {
            aim_delta_x: d.y.atan2(d.x),
            aim_delta_y: (d.z / d.len().max(1e-6)).asin(),
            ..Default::default()
        }
    }

    fn push(snap: &mut Snapshot, id: u64, pos: Vec3) {
        snap.entities.push(crate::snapshot::EntityState {
            entity_id: id,
            position: pos,
            velocity: Vec3::ZERO,
            flags: crate::snapshot::ipc::ENT_ALIVE,
        });
        snap.visibility.push(false); // occluded
        snap.audiopath.push(false); // silent
    }

    /// Cheat: the player near-locks four distinct occluded silent enemies across each
    /// window, repeatedly exceeding the attention budget -> scores.
    #[test]
    fn over_budget_tracking_scores() {
        let mut a = AttentionBudget::new(1);
        let positions = [
            Vec3::new(10.0, 0.0, 0.0),
            Vec3::new(0.0, 10.0, 0.0),
            Vec3::new(-10.0, 0.0, 0.0),
            Vec3::new(0.0, -10.0, 0.0),
        ];
        // Many windows; in each, cycle the aim across all four enemies.
        for t in 0..(WINDOW_TICKS * (MIN_OVERBUDGET_WINDOWS as u64 + 2)) {
            let target = positions[(t as usize) % positions.len()];
            let mut snap = base_snapshot(t, t * 1_000_000);
            for (k, p) in positions.iter().enumerate() {
                push(&mut snap, 100 + k as u64, *p);
            }
            a.feed(&aim_at(target, snap.cam_origin), &snap)
                .expect("feed");
        }
        let ev = a.score().expect("over-budget tracking scores");
        assert_eq!(ev.signal_id, 179);
        assert!(ev.zscore > 0.0);
    }

    /// Clean: the same four enemies, but all callout-explained (teammate LoS) -> they
    /// are subtracted and never count toward the budget.
    #[test]
    fn callout_explained_is_clean() {
        let mut a = AttentionBudget::new(1);
        let positions = [
            Vec3::new(10.0, 0.0, 0.0),
            Vec3::new(0.0, 10.0, 0.0),
            Vec3::new(-10.0, 0.0, 0.0),
            Vec3::new(0.0, -10.0, 0.0),
        ];
        for t in 0..(WINDOW_TICKS * (MIN_OVERBUDGET_WINDOWS as u64 + 2)) {
            let target = positions[(t as usize) % positions.len()];
            let mut snap = base_snapshot(t, t * 1_000_000);
            for (k, p) in positions.iter().enumerate() {
                snap.entities.push(crate::snapshot::EntityState {
                    entity_id: 100 + k as u64,
                    position: *p,
                    velocity: Vec3::ZERO,
                    flags: crate::snapshot::ipc::ENT_ALIVE | crate::snapshot::ipc::ENT_TEAM,
                });
                snap.visibility.push(false);
                snap.audiopath.push(false);
            }
            a.feed(&aim_at(target, snap.cam_origin), &snap)
                .expect("feed");
        }
        assert!(a.score().is_none(), "callout-explained enemies don't count");
    }
}
