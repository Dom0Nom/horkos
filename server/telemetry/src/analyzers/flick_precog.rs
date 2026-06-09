//! src/analyzers/flick_precog.rs
//!
//! Role: flick-endpoint precognition / pre-LoS aim seeding analyzer (catalog signal
//! 177). At the tick an enemy transitions occluded->visible (line-of-sight onset), it
//! compares the player's aim error to (a) the enemy's LAST-VISIBLE position vs (b) the
//! enemy's LIVE (occluded-updated) position. A systematically SMALLER error to the
//! LIVE position — which the honest client could not know — is the tell: the aim was
//! seeded to where the enemy actually is, not where it was last seen. FP gate: the
//! enemy must have MOVED while occluded (so a memorized angle cannot explain the
//! lock), and the discriminator is population-normalized over many engagements. Reuses
//! 172's integrated-aim + visibility-transition machinery. Read-only; fuses in
//! `ban-engine` (never standalone).
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — no `unwrap()` outside tests; `feed` is total over its input.

use std::collections::HashMap;

use crate::analyzers::{Analyzer, SignalId, SuspicionEvent};
use crate::error::TelemetryError;
use crate::geom::{aim_from_yaw_pitch, angular_error, view_basis, Vec3};
use crate::schema::TickPayload;
use crate::snapshot::Snapshot;

/// Minimum distance (world units) an enemy must have moved while occluded for the
/// engagement to be scoreable — below this a memorized angle explains the lock.
const MIN_OCCLUDED_MOVE: f32 = 1.0;

/// Minimum qualifying LoS-onset engagements before emitting.
const MIN_ENGAGEMENTS: u32 = 8;

/// Per-enemy occluded-tracking state: the position where it was last seen and whether
/// it has been continuously occluded since.
#[derive(Clone, Copy)]
struct LastSeen {
    pos: Vec3,
    occluded_since_seen: bool,
}

pub struct FlickPrecog {
    player_id: u64,
    last_seen: HashMap<u64, LastSeen>,
    /// Per engagement: error_to_last_seen - error_to_live (rad). Positive means the
    /// aim was closer to the LIVE position than to the last-seen one (the tell).
    advantage: Vec<f64>,
    first_tick: Option<u64>,
    last_tick: u64,
}

impl FlickPrecog {
    pub fn new(player_id: u64) -> Self {
        FlickPrecog {
            player_id,
            last_seen: HashMap::new(),
            advantage: Vec::new(),
            first_tick: None,
            last_tick: 0,
        }
    }
}

impl Analyzer for FlickPrecog {
    fn id(&self) -> SignalId {
        177
    }

    fn feed(&mut self, tick: &TickPayload, snap: &Snapshot) -> Result<(), TelemetryError> {
        self.first_tick.get_or_insert(snap.tick);
        self.last_tick = snap.tick;

        let basis = view_basis(snap.cam_forward, snap.cam_up);

        for (i, e) in snap.entities.iter().enumerate() {
            if e.is_local() || e.is_team() || !e.is_alive() {
                continue;
            }
            let visible = snap.is_visible(i);
            let prior = self.last_seen.get(&e.entity_id).copied();

            // Detect occluded->visible onset: was occluded since last seen, now visible.
            if visible {
                if let (Some(prev), Some((fwd, up))) = (prior, basis) {
                    if prev.occluded_since_seen {
                        let moved = (e.position - prev.pos).len();
                        if moved >= MIN_OCCLUDED_MOVE {
                            let aim =
                                aim_from_yaw_pitch(fwd, up, tick.aim_delta_x, tick.aim_delta_y);
                            let err_last = angular_error(aim, snap.cam_origin, prev.pos);
                            let err_live = angular_error(aim, snap.cam_origin, e.position);
                            if let (Some(el), Some(ev)) = (err_last, err_live) {
                                // advantage > 0 => aim hugged the LIVE (unknowable) pos.
                                self.advantage.push((el - ev) as f64);
                            }
                        }
                    }
                }
                // Refresh last-seen at the live position; no longer occluded.
                self.last_seen.insert(
                    e.entity_id,
                    LastSeen {
                        pos: e.position,
                        occluded_since_seen: false,
                    },
                );
            } else {
                // Occluded this tick: mark continuously-occluded if we had seen it.
                self.last_seen
                    .entry(e.entity_id)
                    .and_modify(|ls| ls.occluded_since_seen = true);
            }
        }
        Ok(())
    }

    fn score(&self) -> Option<SuspicionEvent> {
        if (self.advantage.len() as u32) < MIN_ENGAGEMENTS {
            return None;
        }
        // The honest expectation is mean advantage ~0 (aim is, if anything, biased
        // toward the last-seen position). A persistent positive mean is the tell. We
        // report a z-like strength via the sample mean over its standard error.
        let n = self.advantage.len() as f64;
        let mean = self.advantage.iter().sum::<f64>() / n;
        if mean <= 0.0 {
            return None;
        }
        let var = self
            .advantage
            .iter()
            .map(|x| (x - mean) * (x - mean))
            .sum::<f64>()
            / n;
        let std = var.max(0.0).sqrt();
        // Standard error of the mean; guard a zero-variance (all-equal) sample.
        let sem = if std > 0.0 {
            std / n.sqrt()
        } else {
            f64::MIN_POSITIVE
        };
        let z = mean / sem;
        Some(SuspicionEvent {
            player_id: self.player_id,
            signal_id: self.id(),
            zscore: z,
            sample_count: self.advantage.len() as u32,
            window_ticks: self.last_tick.saturating_sub(self.first_tick.unwrap_or(0)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::fixtures::{base_snapshot, push_enemy};

    fn aim_at(target: Vec3, origin: Vec3) -> TickPayload {
        // Encode the aim as yaw/pitch from the base forward (+X) toward `target`.
        // For the fixtures the camera forward is +X and up +Z; compute the yaw to the
        // target in the XY plane and pitch toward +Z.
        let d = target - origin;
        let yaw = d.y.atan2(d.x);
        let pitch = (d.z / d.len().max(1e-6)).asin();
        TickPayload {
            aim_delta_x: yaw,
            aim_delta_y: pitch,
            ..Default::default()
        }
    }

    /// Cheat: at LoS onset the aim hugs the LIVE position of an enemy that moved while
    /// occluded -> persistent positive advantage -> scores.
    #[test]
    fn precog_to_live_position_scores() {
        let mut a = FlickPrecog::new(1);
        let mut t = 0u64;
        for _ in 0..MIN_ENGAGEMENTS + 2 {
            // Tick A: enemy visible at last-seen position, establish last_seen.
            let mut s0 = base_snapshot(t, t * 1_000_000);
            push_enemy(
                &mut s0,
                100,
                Vec3::new(10.0, 0.0, 0.0),
                Vec3::ZERO,
                true,
                false,
            );
            a.feed(&TickPayload::default(), &s0).expect("feed");
            t += 1;

            // Tick B: enemy occluded, moves far away.
            let mut s1 = base_snapshot(t, t * 1_000_000);
            push_enemy(
                &mut s1,
                100,
                Vec3::new(10.0, 8.0, 0.0),
                Vec3::ZERO,
                false,
                false,
            );
            a.feed(&TickPayload::default(), &s1).expect("feed");
            t += 1;

            // Tick C: LoS onset; aim hugs the LIVE (moved) position, not last-seen.
            let mut s2 = base_snapshot(t, t * 1_000_000);
            let live = Vec3::new(10.0, 8.0, 0.0);
            push_enemy(&mut s2, 100, live, Vec3::ZERO, true, false);
            a.feed(&aim_at(live, s2.cam_origin), &s2).expect("feed");
            t += 1;
        }
        let ev = a.score().expect("precog to live pos scores");
        assert_eq!(ev.signal_id, 177);
        assert!(ev.zscore > 0.0);
    }

    /// Clean: aim seeded to the LAST-SEEN (memorized) position; advantage is negative
    /// (closer to last-seen than live) -> no score.
    #[test]
    fn aim_to_last_seen_is_clean() {
        let mut a = FlickPrecog::new(1);
        let mut t = 0u64;
        for _ in 0..MIN_ENGAGEMENTS + 2 {
            let last_seen = Vec3::new(10.0, 0.0, 0.0);
            let mut s0 = base_snapshot(t, t * 1_000_000);
            push_enemy(&mut s0, 100, last_seen, Vec3::ZERO, true, false);
            a.feed(&TickPayload::default(), &s0).expect("feed");
            t += 1;

            let mut s1 = base_snapshot(t, t * 1_000_000);
            push_enemy(
                &mut s1,
                100,
                Vec3::new(10.0, 8.0, 0.0),
                Vec3::ZERO,
                false,
                false,
            );
            a.feed(&TickPayload::default(), &s1).expect("feed");
            t += 1;

            let mut s2 = base_snapshot(t, t * 1_000_000);
            let live = Vec3::new(10.0, 8.0, 0.0);
            push_enemy(&mut s2, 100, live, Vec3::ZERO, true, false);
            // Aim at the OLD position (memorized angle).
            a.feed(&aim_at(last_seen, s2.cam_origin), &s2)
                .expect("feed");
            t += 1;
        }
        assert!(a.score().is_none(), "memorized-angle aim is clean");
    }
}
