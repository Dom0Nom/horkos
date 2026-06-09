//! src/analyzers/vision_cone.rs
//!
//! Role: vision-cone knowledge-leakage analyzer (catalog signal 173). Detects a player
//! reacting to an enemy that is OUTSIDE the authoritative view frustum
//! (`geom::frustum_contains` false), with NO authoritative audio path and NO teammate
//! line-of-sight (callout-explainable) — i.e. an enemy the honest client's screen
//! never rendered and no legitimate cue revealed. The reaction onset is the `mono_ns`
//! of the first corrective turn toward that enemy minus the tick it first existed
//! off-frustum; a reaction below the human visual/audio floor onto an off-frustum
//! silent enemy is the tell. Accumulated over a session and population-normalized.
//! Read-only; fuses in `ban-engine` (never standalone).
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — no `unwrap()` outside tests; `feed` is total over its input.

use std::collections::HashMap;

use crate::analyzers::{Analyzer, SignalId, SuspicionEvent};
use crate::error::TelemetryError;
use crate::geom::{aim_from_yaw_pitch, angular_error, frustum_contains, view_basis};
use crate::schema::TickPayload;
use crate::snapshot::Snapshot;
use crate::stats::{zscore, Baseline};

/// Angular movement (rad) of the aim toward an enemy that counts as a "corrective
/// turn" onset this tick.
const TURN_ONSET_RAD: f32 = 0.05;

/// Human reaction floor (ms): an onset faster than this onto an off-frustum, silent,
/// un-called enemy is below any legitimate stimulus-response and is the tell.
const VISUAL_FLOOR_MS: f64 = 120.0;

/// Minimum qualifying off-frustum reactions before emitting.
const MIN_EVENTS: u32 = 6;

/// Honest-population baseline of off-frustum-reaction latency (ms). Honest players
/// simply do not react to off-frustum silent enemies, so observed honest "reactions"
/// (coincidental turns) cluster well above the floor.
const REACTION_BASELINE: Baseline = Baseline {
    mean: 300.0,
    stddev: 80.0,
};

#[derive(Clone, Copy)]
struct OffFrustumSince {
    /// mono_ns at which the enemy first became off-frustum+silent+uncalled.
    onset_mono_ns: u64,
    /// Aim error to the enemy at that onset (to detect a later corrective turn).
    onset_err: f32,
}

pub struct VisionCone {
    player_id: u64,
    pending: HashMap<u64, OffFrustumSince>,
    /// Reaction latencies (ms) onto off-frustum silent enemies.
    latencies: Vec<f64>,
    first_tick: Option<u64>,
    last_tick: u64,
}

impl VisionCone {
    pub fn new(player_id: u64) -> Self {
        VisionCone {
            player_id,
            pending: HashMap::new(),
            latencies: Vec::new(),
            first_tick: None,
            last_tick: 0,
        }
    }
}

impl Analyzer for VisionCone {
    fn id(&self) -> SignalId {
        173
    }

    fn feed(&mut self, tick: &TickPayload, snap: &Snapshot) -> Result<(), TelemetryError> {
        self.first_tick.get_or_insert(snap.tick);
        self.last_tick = snap.tick;

        let basis = view_basis(snap.cam_forward, snap.cam_up);
        let aim = basis.map(|(f, u)| aim_from_yaw_pitch(f, u, tick.aim_delta_x, tick.aim_delta_y));

        for (i, e) in snap.entities.iter().enumerate() {
            if e.is_local() || e.is_team() || !e.is_alive() {
                continue;
            }
            let off_frustum = !frustum_contains(
                snap.cam_origin,
                snap.cam_forward,
                snap.cam_fov_rad,
                e.position,
            );
            let silent = !snap.has_audio_path(i);
            let uncalled = !snap.teammate_has_los(i);
            let qualifies = off_frustum && silent && uncalled;

            let err_now = aim
                .and_then(|a| angular_error(a, snap.cam_origin, e.position))
                .unwrap_or(std::f32::consts::PI);

            if qualifies {
                match self.pending.get(&e.entity_id).copied() {
                    None => {
                        self.pending.insert(
                            e.entity_id,
                            OffFrustumSince {
                                onset_mono_ns: snap.mono_ns,
                                onset_err: err_now,
                            },
                        );
                    }
                    Some(since) => {
                        // A corrective turn toward this off-frustum enemy: error
                        // shrank by at least the onset threshold since it appeared.
                        if since.onset_err - err_now >= TURN_ONSET_RAD {
                            let dt_ms = snap.mono_ns.saturating_sub(since.onset_mono_ns) as f64
                                / 1_000_000.0;
                            self.latencies.push(dt_ms);
                            self.pending.remove(&e.entity_id);
                        }
                    }
                }
            } else {
                // Enemy is now legitimately knowable (in frustum / audible / called):
                // stop tracking it as an off-frustum stimulus.
                self.pending.remove(&e.entity_id);
            }
        }
        Ok(())
    }

    fn score(&self) -> Option<SuspicionEvent> {
        // Count only sub-floor reactions; those are the anomalous ones.
        let sub_floor: Vec<f64> = self
            .latencies
            .iter()
            .copied()
            .filter(|&ms| ms < VISUAL_FLOOR_MS)
            .collect();
        if (sub_floor.len() as u32) < MIN_EVENTS {
            return None;
        }
        let mean = sub_floor.iter().sum::<f64>() / sub_floor.len() as f64;
        // Faster-than-floor reaction = strongly NEGATIVE z vs the honest baseline.
        let z = zscore(mean, REACTION_BASELINE)?;
        if z >= 0.0 {
            return None;
        }
        Some(SuspicionEvent {
            player_id: self.player_id,
            signal_id: self.id(),
            zscore: -z,
            sample_count: sub_floor.len() as u32,
            window_ticks: self.last_tick.saturating_sub(self.first_tick.unwrap_or(0)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geom::Vec3;
    use crate::snapshot::fixtures::{base_snapshot, push_enemy};

    fn aim_at(target: Vec3, origin: Vec3) -> TickPayload {
        let d = target - origin;
        let yaw = d.y.atan2(d.x);
        let pitch = (d.z / d.len().max(1e-6)).asin();
        TickPayload {
            aim_delta_x: yaw,
            aim_delta_y: pitch,
            ..Default::default()
        }
    }

    /// Cheat: instant turn onto an off-frustum, silent, uncalled enemy -> sub-floor
    /// latency repeated -> scores.
    #[test]
    fn offfrustum_fast_reaction_scores() {
        let mut a = VisionCone::new(1);
        let mut t = 0u64;
        for _ in 0..MIN_EVENTS + 2 {
            // Enemy directly BEHIND (off the +X frustum), silent.
            let behind = Vec3::new(-10.0, 0.0, 0.0);
            // Onset tick: not yet turned (aim still forward).
            let mut s0 = base_snapshot(t, t * 1_000_000);
            push_enemy(&mut s0, 100, behind, Vec3::ZERO, false, false);
            a.feed(&TickPayload::default(), &s0).expect("feed");
            t += 1;
            // 20 ms later: snapped aim onto the off-frustum enemy.
            let mut s1 = base_snapshot(t, t * 1_000_000 + 20_000_000);
            push_enemy(&mut s1, 100, behind, Vec3::ZERO, false, false);
            a.feed(&aim_at(behind, s1.cam_origin), &s1).expect("feed");
            t += 1;
        }
        let ev = a.score().expect("sub-floor off-frustum reaction scores");
        assert_eq!(ev.signal_id, 173);
        assert!(ev.zscore > 0.0);
    }

    /// Clean: the enemy has an authoritative audio path -> not an off-frustum
    /// knowledge leak -> never counted.
    #[test]
    fn offfrustum_with_audio_is_clean() {
        let mut a = VisionCone::new(1);
        let mut t = 0u64;
        for _ in 0..MIN_EVENTS + 2 {
            let behind = Vec3::new(-10.0, 0.0, 0.0);
            let mut s0 = base_snapshot(t, t * 1_000_000);
            push_enemy(&mut s0, 100, behind, Vec3::ZERO, false, true); // audible
            a.feed(&TickPayload::default(), &s0).expect("feed");
            t += 1;
            let mut s1 = base_snapshot(t, t * 1_000_000 + 20_000_000);
            push_enemy(&mut s1, 100, behind, Vec3::ZERO, false, true);
            a.feed(&aim_at(behind, s1.cam_origin), &s1).expect("feed");
            t += 1;
        }
        assert!(
            a.score().is_none(),
            "audible enemy is legitimately knowable"
        );
    }

    /// Clean: a teammate has LoS (callout-explainable) -> excluded.
    #[test]
    fn offfrustum_with_teammate_los_is_clean() {
        let mut a = VisionCone::new(1);
        for t in 0..u64::from(MIN_EVENTS) + 2 {
            let behind = Vec3::new(-10.0, 0.0, 0.0);
            let mut s0 = base_snapshot(t, t * 1_000_000);
            // Mark the enemy as TEAM-flagged so teammate_has_los() returns true;
            // (the fixture's team flag stands in for a teammate sightline).
            s0.entities.push(crate::snapshot::EntityState {
                entity_id: 100,
                position: behind,
                velocity: Vec3::ZERO,
                flags: crate::snapshot::ipc::ENT_ALIVE | crate::snapshot::ipc::ENT_TEAM,
            });
            s0.visibility.push(false);
            s0.audiopath.push(false);
            a.feed(&aim_at(behind, s0.cam_origin), &s0).expect("feed");
        }
        assert!(
            a.score().is_none(),
            "team/callout-explained enemy is excluded"
        );
    }
}
