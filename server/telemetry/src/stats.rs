//! Role: Shared statistical gating for the behavioral-gamestate analyzers (catalog
//! signals 172-180): population-baseline z-score, an EWMA / p95-high RTT estimator
//! (174 widens the peeker budget by jitter so a false sub-budget cannot arise from
//! bursty latency), spectral peak detection over a reaction-latency series (178), and
//! a correlation that isolates the RANDOM recoil component from the learnable mean
//! (180 — the discriminator is correlation to the unlearnable per-shot RNG, not the
//! mean pattern a skilled player learns). No verdict is produced here; these are the
//! FP-gating primitives every analyzer's `score()` consults before emitting a
//! `SuspicionEvent`.
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — no `unwrap()`/`expect()` outside `#[cfg(test)]`; every function is
//! total over its input. A degenerate input (empty series, zero variance, fewer than
//! two samples) returns a defined "no signal" result (`None`/0.0), never a NaN that a
//! downstream gate could misread as an extreme z-score.

use rustfft::{num_complex::Complex, FftPlanner};

/// Population baseline parameters for a z-score gate: the mean and standard deviation
/// of a signal across the honest player population. Supplied by the (later) baseline
/// store; here it is a plain value object so the gate is pure and testable.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Baseline {
    pub mean: f64,
    pub stddev: f64,
}

/// Z-score of `x` against `baseline`. Returns `None` when the baseline has
/// non-positive spread (an unpopulated/degenerate baseline must NOT manufacture an
/// infinite z-score — the gate then treats the signal as "no baseline yet").
pub fn zscore(x: f64, baseline: Baseline) -> Option<f64> {
    // NaN stddev must land in the None branch, same as zero/negative spread.
    let spread_positive = baseline.stddev.partial_cmp(&0.0) == Some(std::cmp::Ordering::Greater);
    if !spread_positive || !x.is_finite() || !baseline.mean.is_finite() {
        return None;
    }
    Some((x - baseline.mean) / baseline.stddev)
}

/// Population mean and standard deviation of a sample (for building a `Baseline` from
/// observed honest-population data). Returns `None` for fewer than two samples.
pub fn population_baseline(xs: &[f64]) -> Option<Baseline> {
    if xs.len() < 2 {
        return None;
    }
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    let var = xs.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / n;
    Some(Baseline {
        mean,
        stddev: var.max(0.0).sqrt(),
    })
}

/// EWMA estimator for an RTT series with a paired upper-tail (p95-high) estimate.
/// 174 must use a JITTER-WIDENED budget so a bursty-but-honest connection never
/// presents a false sub-budget peek: the "budget" is `p95_high`, the EWMA mean plus a
/// multiple of the EWMA mean-absolute-deviation, not the bare mean.
#[derive(Debug, Clone, Copy)]
pub struct RttEstimator {
    alpha: f64,
    /// EWMA of the RTT samples.
    mean: f64,
    /// EWMA of |sample - mean| (mean absolute deviation; jitter proxy).
    mad: f64,
    /// Standard-normal multiplier applied to the MAD for the high estimate.
    k_high: f64,
    initialized: bool,
}

impl RttEstimator {
    /// `alpha` in (0,1] is the EWMA weight on the newest sample; `k_high` scales the
    /// jitter term. Defaults clamp to safe ranges so a misconfigured caller cannot
    /// produce a degenerate (zero/negative) estimator.
    pub fn new(alpha: f64, k_high: f64) -> Self {
        RttEstimator {
            alpha: alpha.clamp(f64::MIN_POSITIVE, 1.0),
            mean: 0.0,
            mad: 0.0,
            k_high: k_high.max(0.0),
            initialized: false,
        }
    }

    pub fn update(&mut self, sample: f64) {
        if !sample.is_finite() {
            return;
        }
        if !self.initialized {
            self.mean = sample;
            self.mad = 0.0;
            self.initialized = true;
            return;
        }
        let dev = (sample - self.mean).abs();
        self.mad = self.alpha * dev + (1.0 - self.alpha) * self.mad;
        self.mean = self.alpha * sample + (1.0 - self.alpha) * self.mean;
    }

    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Jitter-widened upper RTT estimate. Monotonic in the MAD: more jitter => a
    /// larger budget => harder to flag a sub-budget peek (the 174 FP guard).
    pub fn p95_high(&self) -> f64 {
        self.mean + self.k_high * self.mad
    }
}

/// Pearson correlation between two equal-length series. Returns `None` for fewer than
/// two pairs or when either side has zero variance (a flat series has no correlation
/// to report — never report a spurious +/-1).
pub fn pearson(a: &[f64], b: &[f64]) -> Option<f64> {
    if a.len() != b.len() || a.len() < 2 {
        return None;
    }
    let n = a.len() as f64;
    let ma = a.iter().sum::<f64>() / n;
    let mb = b.iter().sum::<f64>() / n;
    let mut cov = 0.0;
    let mut va = 0.0;
    let mut vb = 0.0;
    for (x, y) in a.iter().zip(b.iter()) {
        let dx = x - ma;
        let dy = y - mb;
        cov += dx * dy;
        va += dx * dx;
        vb += dy * dy;
    }
    if va <= 0.0 || vb <= 0.0 {
        return None;
    }
    Some(cov / (va.sqrt() * vb.sqrt()))
}

/// True iff every element of `xs` equals the first (zero variance). Used to detect the
/// degenerate residual stream a mean-only compensator produces.
fn is_flat(xs: &[f64]) -> bool {
    match xs.first() {
        None => true,
        Some(&first) => xs.iter().all(|&x| (x - first).abs() <= f64::EPSILON),
    }
}

/// 180 — correlation of the player's per-shot counter-motion against the RANDOM
/// component of the authoritative recoil, with the LEARNABLE MEAN pattern removed
/// first. `applied` is the player's compensation per shot; `recoil` is the
/// authoritative per-shot recoil; `mean_pattern` is the deterministic (learnable)
/// recoil mean for that weapon at that shot index. We subtract the mean from BOTH
/// the recoil (leaving only the unlearnable RNG residual) and the applied motion
/// (removing the part a skilled human can pre-learn), then correlate the residuals.
/// A skilled player matching only the mean pattern correlates ~0 here; a cheat
/// reading the RNG correlates high. Returns `None` on a degenerate window.
pub fn corr_random_component(applied: &[f64], recoil: &[f64], mean_pattern: &[f64]) -> Option<f64> {
    if applied.len() != recoil.len() || applied.len() != mean_pattern.len() || applied.len() < 2 {
        return None;
    }
    let recoil_resid: Vec<f64> = recoil
        .iter()
        .zip(mean_pattern.iter())
        .map(|(r, m)| r - m)
        .collect();
    // The player is expected to counter-act recoil, so the applied motion correlates
    // NEGATIVELY with the recoil it cancels; subtract the (negated) learnable mean
    // from the applied stream to isolate the part that tracks the random residual.
    let applied_resid: Vec<f64> = applied
        .iter()
        .zip(mean_pattern.iter())
        .map(|(a, m)| a - (-m))
        .collect();
    // A player who compensated ONLY the learnable mean leaves a flat (zero-variance)
    // applied residual: they tracked NONE of the random component, so their correlation
    // to the RNG is zero by definition — not undefined. Same for a recoil window with no
    // random component to track. Pearson would return `None` (0/0) on a flat stream; map
    // that degenerate-but-meaningful case to 0.0 so the skilled-human path scores clean
    // rather than vanishing.
    if is_flat(&applied_resid) || is_flat(&recoil_resid) {
        return Some(0.0);
    }
    pearson(&applied_resid, &recoil_resid)
}

/// A detected dominant spectral peak: its frequency (in cycles-per-sample-index, i.e.
/// the bin frequency normalized to the sample spacing) and its signal-to-noise ratio
/// (peak magnitude over the mean of the rest of the spectrum).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SpectralPeak {
    /// Normalized frequency in cycles per sample (0..0.5 by Nyquist).
    pub freq_cycles_per_sample: f64,
    /// Peak-to-mean SNR of the magnitude spectrum (dimensionless; higher = sharper).
    pub snr: f64,
}

/// 178 — dominant off-harmonic peak in a reaction-latency series. Runs a real FFT and
/// returns the strongest non-DC bin with its SNR. The caller excludes harmonics of
/// the client refresh, the client tick, and the server tick before trusting the peak
/// (a cheat's fixed knowledge-refresh rate aliases into an OFF-harmonic peak). Returns
/// `None` for a series too short to resolve a peak or with no spectral structure.
pub fn dominant_peak(series: &[f64]) -> Option<SpectralPeak> {
    let n = series.len();
    if n < 4 {
        return None;
    }
    if series.iter().any(|x| !x.is_finite()) {
        return None;
    }
    // De-mean so DC does not dominate; a flat series then has no peak.
    let mean = series.iter().sum::<f64>() / n as f64;
    let mut buf: Vec<Complex<f64>> = series.iter().map(|x| Complex::new(x - mean, 0.0)).collect();

    let mut planner = FftPlanner::<f64>::new();
    let fft = planner.plan_fft_forward(n);
    fft.process(&mut buf);

    // Magnitude spectrum over the unique half (bins 1..=n/2; skip DC at bin 0).
    let half = n / 2;
    if half < 1 {
        return None;
    }
    let mags: Vec<f64> = (1..=half).map(|k| buf[k].norm()).collect();
    let (peak_idx, peak_mag) =
        mags.iter()
            .copied()
            .enumerate()
            .fold(
                (0usize, 0.0_f64),
                |(bi, bm), (i, m)| {
                    if m > bm {
                        (i, m)
                    } else {
                        (bi, bm)
                    }
                },
            );
    if peak_mag <= 0.0 {
        return None; // flat / no structure
    }
    // SNR = peak over the mean of the OTHER bins. Clamped to a finite cap so
    // callers can always check `is_finite()` or compare directly.
    let sum_other: f64 = mags.iter().sum::<f64>() - peak_mag;
    let denom = (mags.len() as f64 - 1.0).max(1.0);
    let noise_mean = sum_other / denom;
    let snr = if noise_mean > 0.0 {
        peak_mag / noise_mean
    } else {
        // Single non-zero bin: a perfectly periodic series — use a large finite
        // sentinel rather than f64::INFINITY so zscore propagation never sees NaN.
        1000.0_f64
    };
    // Bin index in the half-spectrum is (peak_idx + 1); normalized frequency = bin/n.
    let freq = (peak_idx as f64 + 1.0) / n as f64;
    Some(SpectralPeak {
        freq_cycles_per_sample: freq,
        snr,
    })
}

/// True iff `freq` is within `tol` (in normalized cycles-per-sample) of any harmonic
/// of one of `fundamentals` (also normalized). Used by 178 to EXCLUDE peaks that line
/// up with the client refresh / client tick / server tick before flagging an
/// off-harmonic cheat-refresh peak.
pub fn is_harmonic_of(freq: f64, fundamentals: &[f64], tol: f64) -> bool {
    for &f0 in fundamentals {
        if f0 <= 0.0 {
            continue;
        }
        // A fundamental whose harmonic spacing is below the match tolerance has a comb
        // dense enough to "match" every frequency on the axis — excluding on it would
        // suppress genuine off-harmonic cheat peaks (the FP-unsafe direction). Such a
        // fundamental carries no exclusion information; skip it.
        if f0 < 2.0 * tol {
            continue;
        }
        // Nearest harmonic index.
        let k = (freq / f0).round();
        if k >= 1.0 && (freq - k * f0).abs() <= tol {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zscore_against_known_baseline() {
        let b = Baseline {
            mean: 10.0,
            stddev: 2.0,
        };
        let z = zscore(16.0, b).expect("defined");
        assert!((z - 3.0).abs() < 1e-9, "z = (16-10)/2 = 3, got {z}");
    }

    #[test]
    fn zscore_degenerate_baseline_is_none() {
        let b = Baseline {
            mean: 10.0,
            stddev: 0.0,
        };
        assert!(
            zscore(16.0, b).is_none(),
            "zero-spread baseline yields no z"
        );
    }

    #[test]
    fn population_baseline_matches_known() {
        let b = population_baseline(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]).expect("defined");
        assert!((b.mean - 5.0).abs() < 1e-9);
        assert!((b.stddev - 2.0).abs() < 1e-9); // textbook population stddev = 2
    }

    #[test]
    fn rtt_p95_high_is_monotone_in_jitter() {
        // A steady stream: high estimate ~= mean (low jitter).
        let mut steady = RttEstimator::new(0.3, 2.0);
        for _ in 0..50 {
            steady.update(20.0);
        }
        let steady_high = steady.p95_high();

        // A jittery stream around the same mean: high estimate must be larger.
        let mut jittery = RttEstimator::new(0.3, 2.0);
        let pattern = [10.0, 30.0, 12.0, 28.0, 8.0, 32.0];
        for i in 0..60 {
            jittery.update(pattern[i % pattern.len()]);
        }
        assert!(
            jittery.p95_high() > steady_high,
            "jitter must widen the p95-high budget: jittery {} <= steady {}",
            jittery.p95_high(),
            steady_high
        );
        assert!(steady.p95_high() >= steady.mean());
    }

    #[test]
    fn pearson_flat_series_is_none() {
        assert!(pearson(&[1.0, 1.0, 1.0], &[1.0, 2.0, 3.0]).is_none());
    }

    #[test]
    fn pearson_perfect_positive() {
        let r = pearson(&[1.0, 2.0, 3.0], &[2.0, 4.0, 6.0]).expect("defined");
        assert!((r - 1.0).abs() < 1e-9);
    }

    #[test]
    fn corr_random_isolates_rng_not_mean() {
        // Mean (learnable) pattern: rising recoil per shot.
        let mean_pattern = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        // RNG residual the engine added on top of the mean (unlearnable).
        let rng = [0.3, -0.4, 0.5, -0.2, 0.4, -0.3];
        let recoil: Vec<f64> = mean_pattern.iter().zip(rng).map(|(m, r)| m + r).collect();

        // Cheat: counter-motion tracks the RNG residual (applied = -(mean+rng)).
        let cheat_applied: Vec<f64> = recoil.iter().map(|r| -r).collect();
        let c = corr_random_component(&cheat_applied, &recoil, &mean_pattern).expect("defined");
        assert!(c.abs() > 0.9, "cheat tracking RNG correlates high, got {c}");

        // Skilled human: matches ONLY the learnable mean, ignores the RNG.
        let human_applied: Vec<f64> = mean_pattern.iter().map(|m| -m).collect();
        let h = corr_random_component(&human_applied, &recoil, &mean_pattern).expect("defined");
        assert!(
            h.abs() < 1e-6,
            "human matching only the mean correlates ~0, got {h}"
        );
    }

    #[test]
    fn dominant_peak_finds_synthetic_period() {
        // A pure sinusoid at 8 cycles over 64 samples -> normalized freq 8/64 = 0.125.
        let n = 64usize;
        let series: Vec<f64> = (0..n)
            .map(|i| (2.0 * std::f64::consts::PI * 8.0 * i as f64 / n as f64).sin())
            .collect();
        let peak = dominant_peak(&series).expect("a periodic series has a peak");
        assert!(
            (peak.freq_cycles_per_sample - 0.125).abs() < 1e-3,
            "expected 0.125, got {}",
            peak.freq_cycles_per_sample
        );
        assert!(
            peak.snr > 5.0,
            "a clean sinusoid is high-SNR, got {}",
            peak.snr
        );
    }

    #[test]
    fn dominant_peak_flat_series_is_none() {
        assert!(
            dominant_peak(&[3.0; 32]).is_none(),
            "a flat series has no peak"
        );
    }

    #[test]
    fn harmonic_exclusion() {
        // 0.25 is the 2nd harmonic of a 0.125 fundamental -> excluded.
        assert!(is_harmonic_of(0.25, &[0.125], 1e-3));
        // An off-harmonic peak (0.20) of the same fundamental is NOT excluded.
        assert!(!is_harmonic_of(0.20, &[0.125], 1e-3));
    }

    #[test]
    fn dominant_peak_single_bin_snr_is_finite() {
        // A pure sinusoid at exactly one non-DC bin has zero energy in all
        // other bins (noise floor = 0). The SNR must be finite so downstream
        // zscore propagation never receives NaN or infinity.
        let n = 32usize;
        let bin = 4usize; // normalized freq = 4/32 = 0.125
        let series: Vec<f64> = (0..n)
            .map(|i| (2.0 * std::f64::consts::PI * bin as f64 * i as f64 / n as f64).sin())
            .collect();
        let peak = dominant_peak(&series).expect("single-bin sinusoid has a peak");
        assert!(
            peak.snr.is_finite(),
            "SNR must be finite for a single non-zero bin, got {}",
            peak.snr
        );
        assert!(
            peak.snr > 1.0,
            "SNR must be positive for a clean sinusoid, got {}",
            peak.snr
        );
    }
}
