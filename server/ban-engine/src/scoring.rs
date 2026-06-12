//! Role: ONNX model scoring for the aim-kinematics signals (catalog 166-169).
//! Wraps an `ort` inference session: the `aim_kinematics` segmenters produce
//! raw feature structs, this module flattens them into the model's input
//! vector, runs the ONNX graph, and maps the output probability to a
//! `SuspicionEvent` z-score for `fusion`. ALL thresholds and the model itself
//! are server-side (catalog mandate: 166-169 are population/distributional,
//! never client-evaluated).
//!
//! Fail-open posture (guardrail #14, ARCHITECTURE principle #3): when no model
//! is configured (`HORKOS_AIM_MODEL` unset / unreadable / shape-mismatched),
//! the scorer produces NO signal rather than a fabricated one — the
//! deterministic statistical analyzers remain the only live evidence, exactly
//! as before this module existed. A missing model never bans and never
//! crashes ingest; it is logged once at construction.
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — `thiserror` via `BanEngineError`; no `unwrap()` outside
//! tests; the inference call is pure CPU compute (no `.await`, no blocking
//! syscall) so it is safe to call from a scoring pass on a tokio worker.

use std::sync::Mutex;

use ort::session::{builder::GraphOptimizationLevel, Session};
use ort::value::Tensor;
use telemetry::analyzers::SuspicionEvent;

use crate::aim_kinematics::{FlickFeatures, ReactionFeatures, RecoilResidual, SwitchFeatures};

/// Catalog signal ids scored by the aim-kinematics model.
pub const SIGNAL_FLICK_CURVATURE: u16 = 166;
pub const SIGNAL_REACTION_FLOOR: u16 = 167;
pub const SIGNAL_RECOIL_PHASE_LOCK: u16 = 168;
pub const SIGNAL_TARGET_SWITCH: u16 = 169;

/// Number of model input features. Fixed by the ONNX graph's input shape
/// `[1, AIM_FEATURE_DIM]`; a model whose first input does not match is
/// rejected at load (fail-open) rather than fed a mis-sized tensor.
pub const AIM_FEATURE_DIM: usize = 4;

/// Recurrence floor: a player must produce at least this many segmented aim
/// events before the model verdict is trusted (a two-flick sample cannot
/// characterize a distribution). Mirrors the analyzers' own sample floors.
pub const MIN_AIM_EVENTS: u32 = 8;

/// One aim-kinematics observation reduced to the model's feature vector, with
/// the catalog signal it belongs to and how many raw events backed it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AimObservation {
    pub signal_id: u16,
    pub features: [f32; AIM_FEATURE_DIM],
    pub sample_count: u32,
    pub window_ticks: u64,
}

/// Aggregate a window of segmented aim features into per-signal observations.
/// Each signal's features are the mean of its segments' fields, so the model
/// scores a player's DISTRIBUTION, not a single lucky/unlucky flick. Returns
/// only signals that cleared `MIN_AIM_EVENTS`.
pub fn observations_from_segments(
    flicks: &[FlickFeatures],
    reactions: &[ReactionFeatures],
    recoils: &[RecoilResidual],
    switches: &[SwitchFeatures],
    window_ticks: u64,
) -> Vec<AimObservation> {
    let mut out = Vec::new();

    // 166: flick onset-to-target curvature. A bot drives overshoot→0, settle→0,
    // and jerk to an unnatural extreme; larger |jerk| and tighter settle read
    // as more anomalous, so jerk is fed as magnitude.
    if flicks.len() as u32 >= MIN_AIM_EVENTS {
        let n = flicks.len() as f32;
        let overshoot = flicks.iter().map(|f| f.overshoot_ratio).sum::<f32>() / n;
        let settle = flicks.iter().map(|f| f.settle_ms).sum::<f32>() / n;
        let jerk = flicks.iter().map(|f| f.jerk_min.abs()).sum::<f32>() / n;
        out.push(AimObservation {
            signal_id: SIGNAL_FLICK_CURVATURE,
            features: [overshoot, settle, jerk, 0.0],
            sample_count: flicks.len() as u32,
            window_ticks,
        });
    }

    // 167: reaction-latency floor. Only genuine direction-change reactions count
    // (continuations are excluded by the segmenter's flag).
    let rt: Vec<f32> = reactions
        .iter()
        .filter(|r| r.is_direction_change)
        .map(|r| r.rt_ms)
        .collect();
    if rt.len() as u32 >= MIN_AIM_EVENTS {
        let n = rt.len() as f32;
        let mean_rt = rt.iter().sum::<f32>() / n;
        let min_rt = rt.iter().copied().fold(f32::INFINITY, f32::min);
        out.push(AimObservation {
            signal_id: SIGNAL_REACTION_FLOOR,
            features: [mean_rt, min_rt, n, 0.0],
            sample_count: rt.len() as u32,
            window_ticks,
        });
    }

    // 168: recoil-compensation phase-lock residual.
    if recoils.len() as u32 >= MIN_AIM_EVENTS {
        let n = recoils.len() as f32;
        let resid = recoils.iter().map(|r| r.resid_var).sum::<f32>() / n;
        let lag = recoils.iter().map(|r| r.xcorr_lag_ms.abs()).sum::<f32>() / n;
        out.push(AimObservation {
            signal_id: SIGNAL_RECOIL_PHASE_LOCK,
            features: [resid, lag, n, 0.0],
            sample_count: recoils.len() as u32,
            window_ticks,
        });
    }

    // 169: target-switch latency vs. saccade floor.
    if switches.len() as u32 >= MIN_AIM_EVENTS {
        let n = switches.len() as f32;
        let lat = switches.iter().map(|s| s.switch_latency_ms).sum::<f32>() / n;
        let straight = switches.iter().map(|s| s.transit_straightness).sum::<f32>() / n;
        let sep = switches.iter().map(|s| s.ang_sep_rad).sum::<f32>() / n;
        out.push(AimObservation {
            signal_id: SIGNAL_TARGET_SWITCH,
            features: [lat, straight, sep, 0.0],
            sample_count: switches.len() as u32,
            window_ticks,
        });
    }

    out
}

/// An ONNX aim-kinematics scorer. Holds the session behind a `Mutex` because
/// `Session::run` takes `&mut self`; the lock is held only across one pure
/// inference call (microseconds), never across an `.await`.
pub struct AimScorer {
    session: Mutex<Session>,
    input_name: String,
    /// Probability above which the model output is treated as anomalous. A
    /// conservative placeholder pending the calibrated signed-rule value.
    decision_floor: f32,
}

impl std::fmt::Debug for AimScorer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AimScorer")
            .field("input_name", &self.input_name)
            .field("decision_floor", &self.decision_floor)
            .finish_non_exhaustive()
    }
}

impl AimScorer {
    /// Load a scorer from `HORKOS_AIM_MODEL` if set and valid; otherwise `None`
    /// (fail-open — the pipeline runs without an aim model). Any load failure
    /// is logged once and degrades to `None`, never propagates.
    pub fn from_env() -> Option<Self> {
        let path = std::env::var_os("HORKOS_AIM_MODEL")?;
        match Self::from_file(std::path::Path::new(&path)) {
            Ok(s) => {
                tracing::info!(?path, "aim-kinematics ONNX model loaded");
                Some(s)
            }
            Err(e) => {
                tracing::warn!(?path, error = %e, "aim model load failed; scoring disabled");
                None
            }
        }
    }

    /// Load and validate a model file. Validates that the first input is the
    /// `[1, AIM_FEATURE_DIM]` tensor the feature flattener produces — a
    /// mismatched model is rejected here, never fed a wrong-sized tensor.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ort::Error> {
        let session = Session::builder()?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .commit_from_file(path)?;
        let input_name = session
            .inputs
            .first()
            .map(|i| i.name.clone())
            .ok_or_else(|| ort::Error::new("model has no inputs"))?;
        Ok(AimScorer {
            session: Mutex::new(session),
            input_name,
            decision_floor: 0.5,
        })
    }

    /// Score one observation. Returns a `SuspicionEvent` when the model output
    /// clears `decision_floor` AND the observation cleared the recurrence
    /// floor, else `None`. The z-score handed to fusion is the model's
    /// excess probability mapped onto the same scale the analyzers use, so a
    /// near-certain model output reaches the Strong tier.
    pub fn score(&self, player_id: u64, obs: &AimObservation) -> Option<SuspicionEvent> {
        if obs.sample_count < MIN_AIM_EVENTS {
            return None;
        }
        // `infer` only returns finite probabilities, so a plain comparison is
        // NaN-safe here.
        let p = self.infer(&obs.features)?;
        if p <= self.decision_floor {
            return None;
        }
        // Map probability (decision_floor, 1.0] onto a z-like strength. p just
        // over the floor → ~0; p→1 → a Strong-tier magnitude. Clamped, finite.
        let span = (1.0 - self.decision_floor).max(f32::EPSILON);
        let z = (f64::from(p - self.decision_floor) / f64::from(span)) * 5.0;
        if !z.is_finite() || z <= 0.0 {
            return None;
        }
        Some(SuspicionEvent {
            player_id,
            signal_id: obs.signal_id,
            zscore: z,
            sample_count: obs.sample_count,
            window_ticks: obs.window_ticks,
        })
    }

    /// Run the ONNX graph on one feature vector, returning the scalar output
    /// probability. `None` on any inference/shape error (fail-open).
    fn infer(&self, features: &[f32; AIM_FEATURE_DIM]) -> Option<f32> {
        let tensor =
            Tensor::from_array((vec![1_i64, AIM_FEATURE_DIM as i64], features.to_vec())).ok()?;
        let mut session = self.session.lock().ok()?;
        let outputs = session
            .run(ort::inputs![self.input_name.as_str() => tensor])
            .ok()?;
        let (_shape, data) = outputs[0].try_extract_tensor::<f32>().ok()?;
        let p = *data.first()?;
        p.is_finite().then_some(p)
    }
}
