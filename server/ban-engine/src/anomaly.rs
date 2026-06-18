//! Role: server-side behavioral-window extraction and ONNX anomaly scoring for
//! catalog signal 217. Target platform: server. Interfaces: consumes existing
//! `telemetry::schema::TickPayload` windows, reuses the aim segmenters, loads
//! the model selected by `HORKOS_ANOMALY_MODEL`, and emits `SuspicionEvent`s to
//! ban-engine fusion. Missing or invalid optional model evidence emits no signal.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use ort::session::{builder::GraphOptimizationLevel, Session};
use ort::value::Tensor;
use telemetry::analyzers::SuspicionEvent;
use telemetry::schema::TickPayload;

use crate::aim_kinematics::{
    segment_flicks, segment_reactions, segment_switches, FlickFeatures, ReactionFeatures,
    SwitchFeatures,
};

/// Catalog id for the multivariate behavioral reconstruction anomaly.
pub const SIGNAL_BEHAVIOR_ANOMALY: u16 = 217;
/// Fixed input width shared with `server/ml/behavior_features.json`.
pub const BEHAVIOR_FEATURE_DIM: usize = 10;
/// Ordered feature names mirrored from the cross-language training manifest.
pub const BEHAVIOR_FEATURE_NAMES: [&str; BEHAVIOR_FEATURE_DIM] = [
    "mean_overshoot_ratio",
    "mean_settle_ms",
    "mean_abs_jerk",
    "mean_direction_change_rt_ms",
    "min_direction_change_rt_ms",
    "mean_switch_latency_ms",
    "mean_switch_ang_sep_rad",
    "mean_log1p_hid_interval_var_ns",
    "mean_injected_event_fraction",
    "mean_abs_clock_ratio_ppm",
];
/// Minimum compatible raw ticks required for one model observation.
pub const MIN_BEHAVIOR_TICKS: usize = 64;
/// Minimum ticks with usable HID interval data.
pub const MIN_HID_TICKS: usize = 32;
/// Minimum count required independently from every segmented modality.
pub const MIN_BEHAVIOR_EVENTS: u32 = 8;

/// One complete behavioral-window observation ready for ONNX inference.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BehaviorObservation {
    pub features: [f32; BEHAVIOR_FEATURE_DIM],
    pub sample_count: u32,
    pub window_ticks: u64,
}

/// Extract the complete broad behavior vector from a compatible tick suffix.
pub fn behavior_observation(
    ticks: &[TickPayload],
    window_ticks: u64,
) -> Option<BehaviorObservation> {
    let eligible_ticks = schema_v4_suffix(ticks);
    if eligible_ticks.len() < MIN_BEHAVIOR_TICKS {
        return None;
    }
    let flicks = segment_flicks(eligible_ticks);
    let reactions = segment_reactions(eligible_ticks);
    let switches = segment_switches(eligible_ticks);
    aggregate_behavior(eligible_ticks, &flicks, &reactions, &switches, window_ticks)
}

fn schema_v4_suffix(ticks: &[TickPayload]) -> &[TickPayload] {
    let start = ticks
        .iter()
        .rposition(|tick| tick.schema_version < 4)
        .map_or(0, |index| index + 1);
    &ticks[start..]
}

fn aggregate_behavior(
    eligible_ticks: &[TickPayload],
    flicks: &[FlickFeatures],
    reactions: &[ReactionFeatures],
    switches: &[SwitchFeatures],
    window_ticks: u64,
) -> Option<BehaviorObservation> {
    if eligible_ticks.len() < MIN_BEHAVIOR_TICKS {
        return None;
    }

    if flicks.iter().any(|flick| {
        !flick.overshoot_ratio.is_finite()
            || !flick.settle_ms.is_finite()
            || !flick.jerk_min.is_finite()
    }) {
        return None;
    }
    let valid_flicks: Vec<&FlickFeatures> = flicks
        .iter()
        .filter(|flick| flick.settle_ms > 0.0)
        .collect();

    let direction_reactions: Vec<&ReactionFeatures> = reactions
        .iter()
        .filter(|reaction| reaction.is_direction_change)
        .collect();
    if direction_reactions
        .iter()
        .any(|reaction| !reaction.rt_ms.is_finite())
    {
        return None;
    }
    let valid_reactions: Vec<&ReactionFeatures> = direction_reactions
        .into_iter()
        .filter(|reaction| reaction.rt_ms > 0.0)
        .collect();

    if switches
        .iter()
        .any(|switch| !switch.switch_latency_ms.is_finite() || !switch.ang_sep_rad.is_finite())
    {
        return None;
    }
    let valid_switches: Vec<&SwitchFeatures> = switches
        .iter()
        .filter(|switch| switch.switch_latency_ms > 0.0)
        .collect();

    if valid_flicks.len() < MIN_BEHAVIOR_EVENTS as usize
        || valid_reactions.len() < MIN_BEHAVIOR_EVENTS as usize
        || valid_switches.len() < MIN_BEHAVIOR_EVENTS as usize
    {
        return None;
    }

    let hid_ticks: Vec<&TickPayload> = eligible_ticks
        .iter()
        .filter(|tick| tick.hid_report_count >= 2)
        .collect();
    if hid_ticks.len() < MIN_HID_TICKS {
        return None;
    }

    let mean = |sum: f64, count: usize| sum / count as f64;
    let mean_overshoot = mean(
        valid_flicks
            .iter()
            .map(|flick| f64::from(flick.overshoot_ratio))
            .sum(),
        valid_flicks.len(),
    );
    let mean_settle = mean(
        valid_flicks
            .iter()
            .map(|flick| f64::from(flick.settle_ms))
            .sum(),
        valid_flicks.len(),
    );
    let mean_abs_jerk = mean(
        valid_flicks
            .iter()
            .map(|flick| f64::from(flick.jerk_min).abs())
            .sum(),
        valid_flicks.len(),
    );
    let mean_reaction = mean(
        valid_reactions
            .iter()
            .map(|reaction| f64::from(reaction.rt_ms))
            .sum(),
        valid_reactions.len(),
    );
    let min_reaction = valid_reactions
        .iter()
        .map(|reaction| f64::from(reaction.rt_ms))
        .fold(f64::INFINITY, f64::min);
    let mean_switch_latency = mean(
        valid_switches
            .iter()
            .map(|switch| f64::from(switch.switch_latency_ms))
            .sum(),
        valid_switches.len(),
    );
    let mean_switch_separation = mean(
        valid_switches
            .iter()
            .map(|switch| f64::from(switch.ang_sep_rad))
            .sum(),
        valid_switches.len(),
    );
    let mean_log_hid_variance = mean(
        hid_ticks
            .iter()
            .map(|tick| (tick.hid_interval_var_ns as f64).ln_1p())
            .sum(),
        hid_ticks.len(),
    );
    let mean_injected_fraction = mean(
        hid_ticks
            .iter()
            .map(|tick| f64::from(tick.injected_event_fraction_q8) / 256.0)
            .sum(),
        hid_ticks.len(),
    );
    let mean_abs_clock_drift = mean(
        eligible_ticks
            .iter()
            .map(|tick| f64::from(tick.clock_ratio_ppm).abs())
            .sum(),
        eligible_ticks.len(),
    );

    let features = [
        mean_overshoot as f32,
        mean_settle as f32,
        mean_abs_jerk as f32,
        mean_reaction as f32,
        min_reaction as f32,
        mean_switch_latency as f32,
        mean_switch_separation as f32,
        mean_log_hid_variance as f32,
        mean_injected_fraction as f32,
        mean_abs_clock_drift as f32,
    ];
    if !features.iter().all(|value| value.is_finite()) {
        return None;
    }

    let sample_count = [
        valid_flicks.len(),
        valid_reactions.len(),
        valid_switches.len(),
        hid_ticks.len(),
    ]
    .into_iter()
    .min()
    .unwrap_or(0)
    .min(u32::MAX as usize) as u32;

    Some(BehaviorObservation {
        features,
        sample_count,
        window_ticks,
    })
}

/// ONNX scorer for the fusion-scale behavioral anomaly strength.
pub struct AnomalyScorer {
    session: Mutex<Session>,
    input_name: String,
    runtime_error_logged: AtomicBool,
}

impl std::fmt::Debug for AnomalyScorer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnomalyScorer")
            .field("input_name", &self.input_name)
            .finish_non_exhaustive()
    }
}

impl AnomalyScorer {
    /// Load the optional model configured by `HORKOS_ANOMALY_MODEL`.
    pub fn from_env() -> Option<Self> {
        let path = std::env::var_os("HORKOS_ANOMALY_MODEL")?;
        match Self::from_file(std::path::Path::new(&path)) {
            Ok(scorer) => {
                tracing::info!(?path, "behavioral anomaly ONNX model loaded");
                Some(scorer)
            }
            Err(error) => {
                tracing::warn!(
                    ?path,
                    error = %error,
                    "behavioral anomaly model load failed; scoring disabled"
                );
                None
            }
        }
    }

    /// Load a model and verify it accepts the fixed input and returns one scalar.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ort::Error> {
        let session = Session::builder()?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .commit_from_file(path)?;
        let input_name = session
            .inputs
            .first()
            .map(|input| input.name.clone())
            .ok_or_else(|| ort::Error::new("behavioral anomaly model has no inputs"))?;
        let scorer = Self {
            session: Mutex::new(session),
            input_name,
            runtime_error_logged: AtomicBool::new(false),
        };
        scorer
            .try_infer(&[0.0; BEHAVIOR_FEATURE_DIM])
            .ok_or_else(|| ort::Error::new("behavioral anomaly model probe failed"))?;
        Ok(scorer)
    }

    /// Emit signal 217 only when the model strength clears the active fusion floor.
    pub fn score(
        &self,
        player_id: u64,
        observation: &BehaviorObservation,
        decision_floor: f64,
    ) -> Option<SuspicionEvent> {
        if observation.sample_count < MIN_BEHAVIOR_EVENTS
            || !decision_floor.is_finite()
            || decision_floor <= 0.0
        {
            return None;
        }
        let strength = match self.try_infer(&observation.features) {
            Some(strength) => strength,
            None => {
                if self
                    .runtime_error_logged
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    tracing::warn!(
                        "behavioral anomaly inference failed; signal disabled for sample"
                    );
                }
                return None;
            }
        };
        let zscore = f64::from(strength);
        if zscore < decision_floor {
            return None;
        }
        Some(SuspicionEvent {
            player_id,
            signal_id: SIGNAL_BEHAVIOR_ANOMALY,
            zscore,
            sample_count: observation.sample_count,
            window_ticks: observation.window_ticks,
        })
    }

    fn try_infer(&self, features: &[f32; BEHAVIOR_FEATURE_DIM]) -> Option<f32> {
        if !features.iter().all(|value| value.is_finite()) {
            return None;
        }
        let tensor =
            Tensor::from_array((vec![1_i64, BEHAVIOR_FEATURE_DIM as i64], features.to_vec()))
                .ok()?;
        let mut session = self.session.lock().ok()?;
        let outputs = session
            .run(ort::inputs![self.input_name.as_str() => tensor])
            .ok()?;
        if outputs.len() != 1 {
            return None;
        }
        let output = outputs.get("anomaly_strength")?;
        let (_shape, data) = output.try_extract_tensor::<f32>().ok()?;
        if data.len() != 1 {
            return None;
        }
        let strength = data[0];
        strength.is_finite().then_some(strength)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aim_kinematics::{FlickFeatures, ReactionFeatures, SwitchFeatures};
    use telemetry::schema::TickPayload;

    fn eligible_ticks(count: usize, usable_hid: usize) -> Vec<TickPayload> {
        (0..count)
            .map(|index| TickPayload {
                schema_version: 4,
                hid_report_count: u32::from(index < usable_hid) * 2,
                hid_interval_var_ns: 3,
                injected_event_fraction_q8: 64,
                clock_ratio_ppm: -10,
                ..TickPayload::default()
            })
            .collect()
    }

    fn flicks(count: usize) -> Vec<FlickFeatures> {
        vec![
            FlickFeatures {
                overshoot_ratio: 0.2,
                settle_ms: 100.0,
                jerk_min: -7.0,
            };
            count
        ]
    }

    fn reactions(count: usize) -> Vec<ReactionFeatures> {
        vec![
            ReactionFeatures {
                rt_ms: 200.0,
                is_direction_change: true,
            };
            count
        ]
    }

    fn switches(count: usize) -> Vec<SwitchFeatures> {
        vec![
            SwitchFeatures {
                switch_latency_ms: 150.0,
                transit_straightness: 0.0,
                ang_sep_rad: 0.5,
            };
            count
        ]
    }

    #[test]
    fn aggregate_preserves_feature_order_and_transforms() {
        let observation = aggregate_behavior(
            &eligible_ticks(64, 32),
            &flicks(8),
            &reactions(8),
            &switches(8),
            63,
        )
        .unwrap();

        let expected = [
            0.2,
            100.0,
            7.0,
            200.0,
            200.0,
            150.0,
            0.5,
            4.0_f32.ln(),
            0.25,
            10.0,
        ];
        for (actual, expected) in observation.features.iter().zip(expected) {
            assert!((actual - expected).abs() < 1.0e-5, "{actual} != {expected}");
        }
        assert_eq!(observation.sample_count, 8);
        assert_eq!(observation.window_ticks, 63);
    }

    #[test]
    fn compatible_suffix_starts_after_last_legacy_tick() {
        let mut ticks = eligible_ticks(10, 10);
        ticks.push(TickPayload {
            schema_version: 3,
            ..TickPayload::default()
        });
        ticks.extend(eligible_ticks(64, 32));

        let suffix = schema_v4_suffix(&ticks);

        assert_eq!(suffix.len(), 64);
        assert!(suffix.iter().all(|tick| tick.schema_version >= 4));
    }

    #[test]
    fn aggregate_enforces_each_recurrence_floor() {
        assert!(aggregate_behavior(
            &eligible_ticks(63, 32),
            &flicks(8),
            &reactions(8),
            &switches(8),
            63,
        )
        .is_none());
        assert!(aggregate_behavior(
            &eligible_ticks(64, 31),
            &flicks(8),
            &reactions(8),
            &switches(8),
            63,
        )
        .is_none());
        assert!(aggregate_behavior(
            &eligible_ticks(64, 32),
            &flicks(7),
            &reactions(8),
            &switches(8),
            63,
        )
        .is_none());
        assert!(aggregate_behavior(
            &eligible_ticks(64, 32),
            &flicks(8),
            &reactions(7),
            &switches(8),
            63,
        )
        .is_none());
        assert!(aggregate_behavior(
            &eligible_ticks(64, 32),
            &flicks(8),
            &reactions(8),
            &switches(7),
            63,
        )
        .is_none());
    }

    #[test]
    fn aggregate_suppresses_non_finite_segments() {
        let mut invalid_flicks = flicks(8);
        invalid_flicks[0].overshoot_ratio = f32::NAN;

        assert!(aggregate_behavior(
            &eligible_ticks(64, 32),
            &invalid_flicks,
            &reactions(8),
            &switches(8),
            63,
        )
        .is_none());
    }
}
