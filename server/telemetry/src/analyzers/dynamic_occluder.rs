//! src/analyzers/dynamic_occluder.rs
//!
//! Role: through-smoke / particle-volume tracking-continuity analyzer (catalog signal
//! 175). For an enemy whose line-of-sight from the local view origin is pierced by an
//! ACTIVE dynamic occluder volume (`geom::segment_intersects_aabb` against the smoke
//! AABB while it is within its `[born, expire)` window), it compares the player's aim
//! tracking-error variance INSIDE the volume against the variance just before/after.
//! A human loses the target in smoke (variance spikes); a wallhack tracks through it
//! (variance stays low). FP gate (catalog): score only when the target CHANGED
//! velocity/direction inside the volume (so a memorized straight path cannot explain
//! the lock) AND there is no authoritative audio path. The emitted strength is the
//! pre/post-to-intra variance ratio over many smoke events. Read-only; fuses in
//! `ban-engine` (never standalone).
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — no `unwrap()` outside tests; `feed` is total over its input.

use std::collections::HashMap;

use crate::analyzers::{Analyzer, SignalId, SuspicionEvent};
use crate::error::TelemetryError;
use crate::geom::{aim_from_yaw_pitch, angular_error, segment_intersects_aabb, view_basis, Vec3};
use crate::schema::TickPayload;
use crate::snapshot::Snapshot;

/// Minimum direction change (radians of velocity heading) inside the smoke for the
/// event to be scoreable (defeats the memorized-straight-path FP).
const MIN_DIR_CHANGE_RAD: f32 = 0.20;

/// Minimum smoke events before emitting.
const MIN_EVENTS: u32 = 4;

/// Per-enemy in-progress smoke-tracking event.
struct SmokeEvent {
    /// Aim errors (rad) sampled while LoS was pierced by the smoke volume.
    intra_errors: Vec<f32>,
    /// Aim errors just before the enemy entered smoke (continuity baseline).
    pre_errors: Vec<f32>,
    /// Velocity heading at smoke entry, to measure direction change inside.
    entry_heading: Option<Vec3>,
    /// Whether the heading changed enough inside the volume.
    dir_changed: bool,
    /// Whether an audio path existed at any point during the event (disqualifies).
    had_audio: bool,
}

pub struct DynamicOccluder {
    player_id: u64,
    events: HashMap<u64, SmokeEvent>,
    /// Per completed scoreable event: pre-variance / intra-variance ratio. A high
    /// ratio (calm tracking inside vs noisy outside is inverted: a CHEAT keeps intra
    /// LOW so pre/intra is HIGH) is the tell.
    ratios: Vec<f64>,
    /// Recent aim errors per enemy for the pre-smoke continuity baseline.
    recent: HashMap<u64, Vec<f32>>,
    first_tick: Option<u64>,
    last_tick: u64,
}

impl DynamicOccluder {
    pub fn new(player_id: u64) -> Self {
        DynamicOccluder {
            player_id,
            events: HashMap::new(),
            ratios: Vec::new(),
            recent: HashMap::new(),
            first_tick: None,
            last_tick: 0,
        }
    }
}

fn variance(xs: &[f32]) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let n = xs.len() as f64;
    let mean = xs.iter().map(|&x| x as f64).sum::<f64>() / n;
    xs.iter().map(|&x| (x as f64 - mean).powi(2)).sum::<f64>() / n
}

impl Analyzer for DynamicOccluder {
    fn id(&self) -> SignalId {
        175
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
            let err = match aim.and_then(|a| angular_error(a, snap.cam_origin, e.position)) {
                Some(x) => x,
                None => continue,
            };

            // Does any ACTIVE smoke volume pierce the LoS to this enemy?
            let in_smoke = snap.occluders.iter().any(|o| {
                o.active_at(snap.tick)
                    && segment_intersects_aabb(snap.cam_origin, e.position, o.aabb)
            });

            if in_smoke {
                let ev = self
                    .events
                    .entry(e.entity_id)
                    .or_insert_with(|| SmokeEvent {
                        intra_errors: Vec::new(),
                        pre_errors: self.recent.get(&e.entity_id).cloned().unwrap_or_default(),
                        entry_heading: Some(e.velocity.normalized()),
                        dir_changed: false,
                        had_audio: false,
                    });
                ev.intra_errors.push(err);
                if snap.has_audio_path(i) {
                    ev.had_audio = true;
                }
                if let Some(entry) = ev.entry_heading {
                    let cur = e.velocity.normalized();
                    if let Some(dh) = angular_error(entry, Vec3::ZERO, cur) {
                        if dh >= MIN_DIR_CHANGE_RAD {
                            ev.dir_changed = true;
                        }
                    }
                }
            } else {
                // Leaving smoke (or never in it): finalize any pending event.
                if let Some(ev) = self.events.remove(&e.entity_id) {
                    let intra = variance(&ev.intra_errors);
                    let pre = variance(&ev.pre_errors);
                    // Scoreable only if the target maneuvered inside AND was silent.
                    if ev.dir_changed && !ev.had_audio && ev.intra_errors.len() >= 2 {
                        // Cheat: intra variance ~0 (tracked through), pre variance > 0.
                        let ratio = if intra > 0.0 {
                            pre / intra
                        } else if pre > 0.0 {
                            // Perfect intra-smoke lock with prior movement: maximal.
                            1_000.0
                        } else {
                            0.0
                        };
                        self.ratios.push(ratio);
                    }
                }
                // Maintain the rolling pre-smoke continuity baseline (last few ticks).
                let rec = self.recent.entry(e.entity_id).or_default();
                rec.push(err);
                if rec.len() > 6 {
                    rec.remove(0);
                }
            }
        }
        Ok(())
    }

    fn score(&self) -> Option<SuspicionEvent> {
        // Count events whose continuity ratio indicates through-smoke tracking
        // (pre variance materially exceeds intra variance).
        let strong: Vec<f64> = self.ratios.iter().copied().filter(|&r| r >= 4.0).collect();
        if (strong.len() as u32) < MIN_EVENTS {
            return None;
        }
        let mean_ratio = strong.iter().sum::<f64>() / strong.len() as f64;
        Some(SuspicionEvent {
            player_id: self.player_id,
            signal_id: self.id(),
            zscore: mean_ratio.ln().max(0.0),
            sample_count: strong.len() as u32,
            window_ticks: self.last_tick.saturating_sub(self.first_tick.unwrap_or(0)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geom::Aabb;
    use crate::snapshot::fixtures::base_snapshot;
    use crate::snapshot::OccluderVolume;

    fn aim_at(target: Vec3, origin: Vec3) -> TickPayload {
        let d = target - origin;
        TickPayload {
            aim_delta_x: d.y.atan2(d.x),
            aim_delta_y: (d.z / d.len().max(1e-6)).asin(),
            ..Default::default()
        }
    }

    fn smoke() -> OccluderVolume {
        OccluderVolume {
            aabb: Aabb {
                min: Vec3::new(2.0, -3.0, -3.0),
                max: Vec3::new(4.0, 3.0, 3.0),
            },
            born_tick: 0,
            expire_tick: 10_000,
        }
    }

    fn push_enemy_full(snap: &mut Snapshot, id: u64, pos: Vec3, vel: Vec3, audio: bool) {
        snap.entities.push(crate::snapshot::EntityState {
            entity_id: id,
            position: pos,
            velocity: vel,
            flags: crate::snapshot::ipc::ENT_ALIVE,
        });
        snap.visibility.push(false);
        snap.audiopath.push(audio);
    }

    /// Cheat: target maneuvers (changes heading) inside the smoke yet the aim tracks it
    /// with ~zero error variance -> high pre/intra ratio across many events -> scores.
    #[test]
    fn through_smoke_lock_scores() {
        let mut a = DynamicOccluder::new(1);
        let mut t = 0u64;
        for _ in 0..MIN_EVENTS + 2 {
            // Pre-smoke: enemy in the open, player has some natural tracking jitter.
            for k in 0..4 {
                let mut s = base_snapshot(t, t * 1_000_000);
                let pos = Vec3::new(8.0, k as f32 * 0.5, 0.0);
                push_enemy_full(&mut s, 100, pos, Vec3::new(0.0, 1.0, 0.0), false);
                // Aim slightly off (jitter) so pre-variance is nonzero.
                let jitter = Vec3::new(8.0, k as f32 * 0.5 + 0.4, 0.0);
                a.feed(&aim_at(jitter, s.cam_origin), &s).expect("feed");
                t += 1;
            }
            // Inside smoke: enemy turns (heading change), aim locks perfectly.
            let headings = [
                Vec3::new(0.0, 1.0, 0.0),
                Vec3::new(1.0, 0.5, 0.0),
                Vec3::new(1.0, -0.5, 0.0),
            ];
            for h in headings {
                let mut s = base_snapshot(t, t * 1_000_000);
                s.occluders.push(smoke());
                // Enemy on the far side of the smoke box.
                let pos = Vec3::new(6.0, 0.0, 0.0);
                push_enemy_full(&mut s, 100, pos, h, false);
                a.feed(&aim_at(pos, s.cam_origin), &s).expect("feed"); // perfect lock
                t += 1;
            }
            // Post-smoke: finalize the event.
            let mut s = base_snapshot(t, t * 1_000_000);
            let pos = Vec3::new(8.0, 0.0, 0.0);
            push_enemy_full(&mut s, 100, pos, Vec3::new(1.0, 0.0, 0.0), false);
            a.feed(&aim_at(pos, s.cam_origin), &s).expect("feed");
            t += 1;
        }
        let ev = a.score().expect("through-smoke maneuvering lock scores");
        assert_eq!(ev.signal_id, 175);
        assert!(ev.zscore > 0.0);
    }

    /// Clean: the target moves STRAIGHT through the smoke (no heading change) -> a
    /// memorized path explains a lock -> not scoreable.
    #[test]
    fn straight_path_through_smoke_is_clean() {
        let mut a = DynamicOccluder::new(1);
        let mut t = 0u64;
        for _ in 0..MIN_EVENTS + 2 {
            for _k in 0..3 {
                let mut s = base_snapshot(t, t * 1_000_000);
                s.occluders.push(smoke());
                let pos = Vec3::new(6.0, 0.0, 0.0);
                // Constant heading: no direction change inside smoke.
                push_enemy_full(&mut s, 100, pos, Vec3::new(0.0, 1.0, 0.0), false);
                a.feed(&aim_at(pos, s.cam_origin), &s).expect("feed");
                t += 1;
            }
            let mut s = base_snapshot(t, t * 1_000_000);
            push_enemy_full(
                &mut s,
                100,
                Vec3::new(8.0, 0.0, 0.0),
                Vec3::new(0.0, 1.0, 0.0),
                false,
            );
            a.feed(&TickPayload::default(), &s).expect("feed");
            t += 1;
        }
        assert!(a.score().is_none(), "straight memorized path is clean");
    }
}
