//! src/aim_kinematics.rs
//!
//! Role: Server-side aim-kinematics feature extractor + event segmenters for
//! catalog signals 166 (flick onset-to-target curvature), 167 (reaction-latency
//! floor vs. visibility-onset), 168 (recoil-compensation phase-lock residual)
//! and 169 (target-switch latency vs. saccade floor). Consumes a window of
//! `telemetry::schema::TickPayload` (the per-tick JSON aim-feature block the
//! client ships) and emits typed model features. The client ships RAW features
//! only; ALL thresholds, human-floor comparisons, distribution fits and verdicts
//! live HERE (and in the ort/ONNX scoring path that consumes these features) —
//! never on the client (catalog mandate: 166/167/168/169 are population/
//! distributional, server-side).
//!
//! Phase-2 scope (this file): typed feature structs + the segmentation entry
//! points as PURE functions over a `&[TickPayload]` window, so they unit-test on
//! the host with no model. The ort session and the human-floor/distribution
//! models are later work (mirrors how `telemetry::ort_linked_marker` keeps `ort`
//! wired without loading a model). No verdict is produced here.
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — no `unwrap()`/`expect()` outside `#[cfg(test)]`; `thiserror`
//! for error types (none needed yet — the segmenters are total over their
//! input and return empty on a degenerate window rather than erroring). #14 —
//! the DECISION logic (segmentation thresholds, saccade/reaction floors, recoil
//! curves) is deferred to /tdd + the signed-rule/model path; this scaffolds the
//! feature contract and the structural segmentation only.

use telemetry::schema::TickPayload;

/// Nanoseconds-per-second, for ns->ms conversions in the feature math.
const NS_PER_MS: f32 = 1_000_000.0;

/// Minimum angular separation (radians) a target-switch must span before it is
/// scored. Small-gap spray-transfer between close enemies is a real skill and is
/// excluded (catalog FP gate 169). Conservative placeholder; the authoritative
/// floor is a signed-rule/model parameter in /tdd, NOT a hard client/Phase-2
/// constant that convicts. Used here only to mark a candidate as "scoreable".
const MIN_SWITCH_ANG_SEP_RAD: f32 = 0.20;

/// 166 — flick onset-to-target curvature features for one segmented flick.
/// The model compares these against a human-floor; this struct is the feature
/// vector, not a verdict.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FlickFeatures {
    /// Peak angular distance past the target over the residual-to-target at
    /// settle (dimensionless overshoot ratio). 0 = no overshoot.
    pub overshoot_ratio: f32,
    /// Time from flick onset to settle (ms).
    pub settle_ms: f32,
    /// Minimum (most negative) jerk over the flick — the deceleration signature
    /// a bot's instantaneous correction drives toward an unnatural extreme.
    pub jerk_min: f32,
}

/// 167 — reaction-latency-floor features for one occluded->visible target event.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReactionFeatures {
    /// Reaction time: first-corrective-impulse ts minus visibility-onset ts (ms).
    pub rt_ms: f32,
    /// Whether the impulse was a genuine new-direction change toward the
    /// newly-visible target (a continuation of prior tracking is excluded from
    /// the reaction-time CDF — guards the pre-aim/prediction FP).
    pub is_direction_change: bool,
}

/// 168 — recoil-compensation phase-lock residual features over a burst.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RecoilResidual {
    /// Variance of the applied-vs-expected recoil residual over the burst.
    pub resid_var: f32,
    /// Cross-correlation lag between the recoil step and the applied
    /// compensation (ms). A script can be zero-lag; a human cannot.
    pub xcorr_lag_ms: f32,
}

/// 169 — target-switch latency features for one switch event.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SwitchFeatures {
    /// Time from switch onset to re-lock on the new target (ms).
    pub switch_latency_ms: f32,
    /// Straightness of the transit path (1.0 = perfectly straight; a bot's
    /// instantaneous transfer trends toward 1.0).
    pub transit_straightness: f32,
    /// Angular separation between the two targets (rad).
    pub ang_sep_rad: f32,
}

/// 166 — segment flick events from a tick window and emit their curvature
/// features. Pure function over the window; no model, no verdict.
///
/// A flick is a high-velocity view excursion that approaches a target and
/// settles. This Phase-2 body extracts the structural segmentation only: it
/// finds local angular-velocity peaks where the view is closing on the nearest
/// target, then folds overshoot/settle/jerk over each segment. The human-floor
/// model that SCORES the features is /tdd + ort work.
pub fn segment_flicks(ticks: &[TickPayload]) -> Vec<FlickFeatures> {
    let mut out = Vec::new();
    if ticks.len() < 3 {
        return out;
    }

    // Walk interior ticks; a flick onset is a local angular-velocity maximum
    // while distance-to-target is decreasing (the view is closing on a target).
    let mut i = 1;
    while i + 1 < ticks.len() {
        let prev = &ticks[i - 1];
        let cur = &ticks[i];
        let next = &ticks[i + 1];

        let is_vel_peak = cur.ang_vel > prev.ang_vel && cur.ang_vel >= next.ang_vel;
        let closing = cur.dist_to_nearest_target_rad <= prev.dist_to_nearest_target_rad;

        if is_vel_peak && closing && cur.ang_vel > 0.0 {
            out.push(fold_flick(&ticks[i - 1..]));
            // Skip past the settle region we just folded to avoid double-counting
            // the same flick; advance to the first tick whose velocity fell back
            // below the onset (settle), bounded by the window.
            let onset_vel = cur.ang_vel;
            let mut j = i + 1;
            while j + 1 < ticks.len() && ticks[j].ang_vel > onset_vel * 0.5 {
                j += 1;
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    out
}

/// Fold one flick segment (starting just before onset) into its features.
/// `seg` is the window from the tick before onset to the end of the window;
/// the settle point is the first local distance minimum after onset.
fn fold_flick(seg: &[TickPayload]) -> FlickFeatures {
    // Settle = first tick where distance-to-target stops decreasing (local min).
    // Overshoot = how far past that minimum the view swung before returning,
    // expressed relative to the residual at settle.
    let mut settle_idx = seg.len().saturating_sub(1);
    for k in 1..seg.len() {
        if seg[k].dist_to_nearest_target_rad > seg[k - 1].dist_to_nearest_target_rad {
            settle_idx = k - 1;
            break;
        }
    }

    let residual_at_settle = seg
        .get(settle_idx)
        .map(|t| t.dist_to_nearest_target_rad)
        .unwrap_or(0.0)
        .abs();

    // Peak excursion past settle within the remaining window (overshoot lobe).
    let mut max_past = 0.0_f32;
    for t in seg.iter().skip(settle_idx + 1) {
        let past = (residual_at_settle - t.dist_to_nearest_target_rad).abs();
        if past > max_past {
            max_past = past;
        }
    }
    let overshoot_ratio = if residual_at_settle > f32::EPSILON {
        max_past / residual_at_settle
    } else {
        // No residual at settle — overshoot is undefined; report 0 rather than
        // a division blowup (degenerate-window safety, not a fabricated signal).
        0.0
    };

    // Settle time: ticks carry no own dt in this block, so settle_ms is derived
    // from the newest-HID timestamps when present, else left 0 (the model treats
    // 0 as "unknown" and falls back to the per-player tick rate prior).
    let settle_ms = ts_delta_ms(
        seg.first().map(|t| t.hid_newest_ts_ns).unwrap_or(0),
        seg.get(settle_idx).map(|t| t.hid_newest_ts_ns).unwrap_or(0),
    );

    let jerk_min = seg
        .iter()
        .map(|t| t.ang_jerk)
        .fold(0.0_f32, |acc, j| if j < acc { j } else { acc });

    FlickFeatures {
        overshoot_ratio,
        settle_ms,
        jerk_min,
    }
}

/// 167 — extract reaction-latency features for every tick that records a
/// visibility-onset/first-impulse pair. A continuation of prior tracking
/// (`impulse_is_direction_change == false`) is INCLUDED in the output with its
/// flag set false so the caller (CDF builder) can exclude it; this function does
/// not itself convict, it labels.
pub fn segment_reactions(ticks: &[TickPayload]) -> Vec<ReactionFeatures> {
    let mut out = Vec::new();
    for t in ticks {
        // Only ticks carrying a real onset+impulse pair are reaction events.
        if t.target_vis_onset_ts_ns == 0 || t.first_impulse_ts_ns == 0 {
            continue;
        }
        out.push(ReactionFeatures {
            rt_ms: ts_delta_ms(t.target_vis_onset_ts_ns, t.first_impulse_ts_ns),
            is_direction_change: t.impulse_is_direction_change,
        });
    }
    out
}

/// 168 — recoil-residual features over the full-auto bursts in the window.
///
/// The applied compensation is `applied_angle_dy` during `fire_active`; the
/// EXPECTED inverse-recoil step per shot comes from the SIGNED weapon recoil
/// curve, which rides the existing signed-rule plumbing (`bundle.rs`) and is
/// supplied by the caller as `recoil_step_for(weapon_id, shot_index)`. Phase-2
/// keeps the residual math but takes the curve as an injected closure so no
/// recoil data is hardcoded here (it is signed rule data, not a constant).
pub fn segment_recoil_bursts<F>(ticks: &[TickPayload], recoil_step_for: F) -> Vec<RecoilResidual>
where
    F: Fn(u32, u32) -> f32,
{
    let mut out = Vec::new();
    let mut burst: Vec<f32> = Vec::new(); // per-shot residuals for the active burst
    let mut burst_weapon: u32 = 0;

    let flush = |burst: &mut Vec<f32>, out: &mut Vec<RecoilResidual>| {
        if burst.len() >= 2 {
            out.push(RecoilResidual {
                resid_var: variance(burst),
                // xcorr lag needs the timestamped applied stream vs the curve;
                // not derivable from per-shot residual magnitude alone. Left 0
                // (model treats 0 as "lag unknown") until the timestamped
                // cross-correlation lands in /tdd. HK-TODO(schema): a per-shot
                // applied-impulse timestamp would let this compute a real lag.
                xcorr_lag_ms: 0.0,
            });
        }
        burst.clear();
    };

    for t in ticks {
        if t.fire_active {
            if !burst.is_empty() && t.weapon_id != burst_weapon {
                flush(&mut burst, &mut out);
            }
            burst_weapon = t.weapon_id;
            let expected = recoil_step_for(t.weapon_id, t.shot_index);
            // residual = applied - (-recoil_step): perfect inverse -> ~0.
            let residual = t.applied_angle_dy - (-expected);
            burst.push(residual);
        } else if !burst.is_empty() {
            flush(&mut burst, &mut out);
        }
    }
    flush(&mut burst, &mut out);
    out
}

/// 169 — segment target-switch events and emit their latency/transit features.
/// Only switches whose angular separation exceeds `MIN_SWITCH_ANG_SEP_RAD` are
/// emitted as scoreable — small-gap spray-transfers are excluded (catalog FP
/// gate). `ang_sep` is taken from the candidate offsets when the switch tick
/// records them; otherwise the largest available candidate offset is used as a
/// conservative lower bound on the gap.
pub fn segment_switches(ticks: &[TickPayload]) -> Vec<SwitchFeatures> {
    let mut out = Vec::new();
    let mut onset_ts: Option<u64> = None;

    for (idx, t) in ticks.iter().enumerate() {
        if !t.switch_event_flag {
            continue;
        }
        let ang_sep = t
            .candidate_target_offsets
            .iter()
            .copied()
            .map(f32::abs)
            .fold(0.0_f32, f32::max);

        // Below the saccade-relevant gap: skill spray-transfer, not scoreable.
        if ang_sep < MIN_SWITCH_ANG_SEP_RAD {
            onset_ts = Some(t.first_impulse_ts_ns);
            continue;
        }

        let switch_latency_ms = match onset_ts {
            Some(start) if start != 0 && t.fire_ts_ns != 0 => ts_delta_ms(start, t.fire_ts_ns),
            _ => 0.0, // no usable onset/lock pair this window: lag unknown
        };

        // Transit straightness is the path-integral straightness across the
        // switch; per-tick angular geometry to reconstruct the path is not in
        // this fixed block, so report the structural placeholder 0.0 (model
        // treats 0 as "unknown"). HK-TODO(schema): a per-tick view-vector sample
        // stream would let this reconstruct transit straightness.
        let transit_straightness = 0.0;

        out.push(SwitchFeatures {
            switch_latency_ms,
            transit_straightness,
            ang_sep_rad: ang_sep,
        });

        let _ = idx;
        onset_ts = Some(t.first_impulse_ts_ns);
    }
    out
}

/// Signed ns delta between two timestamps, in ms. Returns 0 if either side is 0
/// (unknown) or if `to < from` (clock went backwards / out-of-order window) —
/// the model treats 0 as "unknown" rather than a fabricated negative latency.
fn ts_delta_ms(from_ns: u64, to_ns: u64) -> f32 {
    if from_ns == 0 || to_ns == 0 || to_ns < from_ns {
        return 0.0;
    }
    (to_ns - from_ns) as f32 / NS_PER_MS
}

/// Population variance of a residual sample. Returns 0 for fewer than two
/// samples (no spread defined).
fn variance(xs: &[f32]) -> f32 {
    if xs.len() < 2 {
        return 0.0;
    }
    let n = xs.len() as f32;
    let mean = xs.iter().sum::<f32>() / n;
    xs.iter().map(|x| (x - mean) * (x - mean)).sum::<f32>() / n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> TickPayload {
        TickPayload {
            schema_version: telemetry::schema::SCHEMA_VERSION,
            ..Default::default()
        }
    }

    #[test]
    fn flick_segments_a_ballistic_then_corrective_profile() {
        // Distance closes fast then overshoots and settles; velocity peaks mid.
        let mut ticks = Vec::new();
        let dists = [1.0_f32, 0.6, 0.2, 0.0, 0.05, 0.0];
        let vels = [0.5_f32, 4.0, 5.0, 1.0, 0.4, 0.1];
        let jerks = [0.0_f32, -2.0, -8.0, 1.0, 0.0, 0.0];
        for k in 0..dists.len() {
            ticks.push(TickPayload {
                dist_to_nearest_target_rad: dists[k],
                ang_vel: vels[k],
                ang_jerk: jerks[k],
                hid_newest_ts_ns: 1_000_000 * (k as u64 + 1),
                ..base()
            });
        }
        let flicks = segment_flicks(&ticks);
        assert!(
            !flicks.is_empty(),
            "a velocity-peak closing flick is segmented"
        );
        assert!(flicks[0].jerk_min <= -8.0 + f32::EPSILON);
    }

    #[test]
    fn flick_monotone_low_jerk_profile_has_no_overshoot() {
        // Smooth monotone close: no velocity peak that then settles -> the
        // low-jerk signature, zero overshoot if segmented at all.
        let mut ticks = Vec::new();
        for k in 0..6 {
            ticks.push(TickPayload {
                dist_to_nearest_target_rad: 1.0 - 0.15 * k as f32,
                ang_vel: 1.0,
                ang_jerk: 0.0,
                ..base()
            });
        }
        let flicks = segment_flicks(&ticks);
        for f in &flicks {
            assert_eq!(f.overshoot_ratio, 0.0);
            assert_eq!(f.jerk_min, 0.0);
        }
    }

    #[test]
    fn reaction_excludes_non_direction_change_via_flag() {
        let direction_change = TickPayload {
            target_vis_onset_ts_ns: 1_000_000,
            first_impulse_ts_ns: 1_000_000 + 180 * 1_000_000, // 180 ms
            impulse_is_direction_change: true,
            ..base()
        };
        let continuation = TickPayload {
            target_vis_onset_ts_ns: 5_000_000,
            first_impulse_ts_ns: 5_000_000 + 40 * 1_000_000, // 40 ms (sub-floor)
            impulse_is_direction_change: false,
            ..base()
        };
        let feats = segment_reactions(&[direction_change, continuation]);
        assert_eq!(feats.len(), 2);
        assert!((feats[0].rt_ms - 180.0).abs() < 0.01);
        assert!(feats[0].is_direction_change);
        // The sub-floor event is flagged as a continuation so the CDF builder
        // excludes it — proving the pre-aim FP guard is representable.
        assert!(!feats[1].is_direction_change);
        let scoreable: Vec<_> = feats.iter().filter(|f| f.is_direction_change).collect();
        assert_eq!(scoreable.len(), 1);
    }

    #[test]
    fn recoil_perfect_inverse_has_near_zero_variance() {
        // Applied compensation exactly inverts the recoil step each shot.
        let curve = |_w: u32, shot: u32| 0.01 * (shot as f32 + 1.0);
        let mut ticks = Vec::new();
        for shot in 0..6u32 {
            ticks.push(TickPayload {
                fire_active: true,
                weapon_id: 1,
                shot_index: shot,
                applied_angle_dy: -(0.01 * (shot as f32 + 1.0)),
                ..base()
            });
        }
        let res = segment_recoil_bursts(&ticks, curve);
        assert_eq!(res.len(), 1);
        assert!(
            res[0].resid_var < 1e-9,
            "perfect inverse -> ~zero residual var"
        );
    }

    #[test]
    fn recoil_noisy_human_stream_has_nonzero_variance() {
        let curve = |_w: u32, shot: u32| 0.01 * (shot as f32 + 1.0);
        let noise = [0.003_f32, -0.004, 0.006, -0.002, 0.005, -0.003];
        let mut ticks = Vec::new();
        for shot in 0..6u32 {
            ticks.push(TickPayload {
                fire_active: true,
                weapon_id: 1,
                shot_index: shot,
                applied_angle_dy: -(0.01 * (shot as f32 + 1.0)) + noise[shot as usize],
                ..base()
            });
        }
        let res = segment_recoil_bursts(&ticks, curve);
        assert_eq!(res.len(), 1);
        assert!(
            res[0].resid_var > 1e-6,
            "human noise -> nonzero residual var"
        );
    }

    #[test]
    fn switch_excludes_small_angular_gap_transfers() {
        // Small-gap transfer: below MIN_SWITCH_ANG_SEP_RAD -> not scored.
        let small = TickPayload {
            switch_event_flag: true,
            candidate_target_offsets: vec![0.05, 0.10],
            first_impulse_ts_ns: 1_000_000,
            fire_ts_ns: 1_000_000 + 30 * 1_000_000,
            ..base()
        };
        assert!(segment_switches(&[small]).is_empty());

        // Large-gap switch: scored.
        let large = TickPayload {
            switch_event_flag: true,
            candidate_target_offsets: vec![0.05, 0.9],
            first_impulse_ts_ns: 1_000_000,
            fire_ts_ns: 1_000_000 + 30 * 1_000_000,
            ..base()
        };
        let feats = segment_switches(&[large]);
        assert_eq!(feats.len(), 1);
        assert!(feats[0].ang_sep_rad >= MIN_SWITCH_ANG_SEP_RAD);
    }

    #[test]
    fn variance_of_single_sample_is_zero() {
        assert_eq!(variance(&[1.0]), 0.0);
        assert_eq!(variance(&[]), 0.0);
    }

    #[test]
    fn ts_delta_handles_out_of_order_and_zero() {
        assert_eq!(ts_delta_ms(0, 100), 0.0);
        assert_eq!(ts_delta_ms(100, 0), 0.0);
        assert_eq!(ts_delta_ms(200, 100), 0.0); // backwards -> 0
        assert!((ts_delta_ms(1_000_000, 3_000_000) - 2.0).abs() < 0.01);
    }
}
