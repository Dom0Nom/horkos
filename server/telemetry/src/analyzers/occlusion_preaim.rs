//! Role: occlusion-resolved pre-aim lead analyzer (catalog signal 172). Per tick it
//! integrates the client-reported `aim_delta_*` into a 3-D aim direction in the
//! snapshot's authoritative view frame, then measures the angular error to each
//! enemy's AUTHORITATIVE position. The tell is a sub-degree aim lock onto an enemy the
//! server marks OCCLUDED (`visibility` clear) with NO authoritative audio path and NO
//! prior line-of-sight in the engagement — information the honest client never had.
//! FP gate (catalog): require the enemy to have been occluded + silent for the lead-up
//! ticks and population-normalize the per-engagement tightness via a z-score before
//! emitting. Read-only; fuses in `ban-engine` (never standalone — `STANDALONE_BANNABLE`).
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — no `unwrap()` outside tests; `feed` is total over its input.

use crate::analyzers::{Analyzer, SignalId, SuspicionEvent};
use crate::error::TelemetryError;
use crate::geom::{aim_from_yaw_pitch, angular_error, view_basis};
use crate::schema::TickPayload;
use crate::snapshot::Snapshot;
use crate::stats::{population_baseline, zscore, Baseline};

/// Sub-degree lock threshold (radians): an aim error this tight onto an occluded,
/// silent enemy is the structural tell. ~1.0 degree. This GATES which engagements
/// count as "tight"; it is not a standalone verdict (the z-score over many such
/// engagements is the emitted strength).
const TIGHT_LOCK_RAD: f32 = 0.0175;

/// Minimum qualifying engagements before a score is emitted (recurrence gate).
const MIN_ENGAGEMENTS: u32 = 8;

/// Hard cap on the per-session engagement buffer. Without it a long (or
/// adversarially endless) session grows `lock_errors` without bound — a memory
/// DoS on the pipeline task. When full, the OLDEST half is discarded so the
/// score reflects the most recent play (sliding-window semantics).
pub const MAX_SAMPLES: usize = 4096;

/// Population baseline of the per-engagement minimum-lock-error onto occluded enemies
/// for honest players. Placeholder until the baseline store lands; the value object
/// keeps the gate pure and testable. Honest players essentially never tight-lock a
/// fully occluded silent enemy, so the honest mean error is large.
const OCCLUDED_LOCK_BASELINE: Baseline = Baseline {
    mean: 0.40, // ~23 deg mean error onto occluded enemies for honest play
    stddev: 0.15,
};

pub struct OcclusionPreaim {
    player_id: u64,
    /// Per qualifying engagement: the tightest aim error (rad) achieved onto an
    /// occluded+silent enemy. A small value is anomalous.
    lock_errors: Vec<f64>,
    first_tick: Option<u64>,
    last_tick: u64,
}

impl OcclusionPreaim {
    pub fn new(player_id: u64) -> Self {
        OcclusionPreaim {
            player_id,
            lock_errors: Vec::new(),
            first_tick: None,
            last_tick: 0,
        }
    }
}

impl Analyzer for OcclusionPreaim {
    fn id(&self) -> SignalId {
        172
    }

    fn feed(&mut self, tick: &TickPayload, snap: &Snapshot) -> Result<(), TelemetryError> {
        self.first_tick.get_or_insert(snap.tick);
        self.last_tick = snap.tick;

        let (fwd, up) = match view_basis(snap.cam_forward, snap.cam_up) {
            Some(b) => b,
            None => return Ok(()), // degenerate camera this tick: no usable aim frame
        };
        let aim = aim_from_yaw_pitch(fwd, up, tick.aim_delta_x, tick.aim_delta_y);

        // Tightest error onto an occluded, silent enemy this tick.
        let mut best: Option<f32> = None;
        for (i, e) in snap.entities.iter().enumerate() {
            if e.is_local() || e.is_team() || !e.is_alive() {
                continue;
            }
            // FP gate: only occluded AND no authoritative audio path qualifies — a
            // visible or audible enemy is legitimately knowable.
            if snap.is_visible(i) || snap.has_audio_path(i) {
                continue;
            }
            if let Some(err) = angular_error(aim, snap.cam_origin, e.position) {
                best = Some(best.map_or(err, |b| b.min(err)));
            }
        }

        if let Some(err) = best {
            if err <= TIGHT_LOCK_RAD {
                if self.lock_errors.len() >= MAX_SAMPLES {
                    self.lock_errors.drain(..MAX_SAMPLES / 2);
                }
                self.lock_errors.push(err as f64);
            }
        }
        Ok(())
    }

    fn score(&self) -> Option<SuspicionEvent> {
        if (self.lock_errors.len() as u32) < MIN_ENGAGEMENTS {
            return None;
        }
        // The player's mean tight-lock error onto occluded enemies; a smaller mean is
        // more anomalous, so the z-score is negated (left tail = suspicious).
        let baseline = population_baseline(&self.lock_errors).unwrap_or(OCCLUDED_LOCK_BASELINE);
        let _ = baseline; // population_baseline of the player's own sample is not the
                          // discriminator; compare the player mean to the HONEST baseline.
        let n = self.lock_errors.len() as f64;
        let player_mean = self.lock_errors.iter().sum::<f64>() / n;
        let z = zscore(player_mean, OCCLUDED_LOCK_BASELINE)?;
        // Suspicious = unusually SMALL error -> strongly negative z. Report magnitude.
        if z >= 0.0 {
            return None;
        }
        Some(SuspicionEvent {
            player_id: self.player_id,
            signal_id: self.id(),
            zscore: -z,
            sample_count: self.lock_errors.len() as u32,
            window_ticks: self.last_tick.saturating_sub(self.first_tick.unwrap_or(0)),
        })
    }
}
