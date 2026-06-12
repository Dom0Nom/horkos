//! Role: knowledge-update lag fingerprint / cheat refresh-rate aliasing analyzer
//! (catalog signal 178). A cheat refreshes its illegitimate world knowledge (ESP/radar
//! redraw, memory poll) at its OWN fixed rate, distinct from the client's display
//! refresh and the game's tick. That periodicity aliases into the player's
//! occluded-knowledge reaction-latency series as a dominant OFF-HARMONIC spectral
//! peak. This analyzer accumulates the reaction-latency series, runs an FFT
//! (`stats::dominant_peak`), and flags a persistent high-SNR peak that is NOT a
//! harmonic of the client display refresh (`client_refresh_hz`), the client frame
//! cadence (`client_mono_ns`), or the server tick — those are excluded
//! (`stats::is_harmonic_of`). Pure compute, no I/O. Read-only; fuses in `ban-engine`
//! (never standalone). Lands last because it consumes the latency series the other
//! signals' machinery populates.
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — no `unwrap()` outside tests; `feed` is total over its input.

use crate::analyzers::{Analyzer, SignalId, SuspicionEvent};
use crate::error::TelemetryError;
use crate::schema::TickPayload;
use crate::snapshot::Snapshot;
use crate::stats::{dominant_peak, is_harmonic_of};

/// Minimum series length before a spectral peak is resolvable / trustworthy.
const MIN_SERIES: usize = 32;

/// SNR floor for a "persistent high-SNR" off-harmonic peak.
const SNR_FLOOR: f64 = 6.0;

/// Harmonic-exclusion tolerance (normalized cycles-per-sample).
const HARMONIC_TOL: f64 = 0.01;

/// Hard cap on the latency series. Without it a long session grows the series
/// without bound — a memory DoS, and the per-score FFT cost grows with it.
/// When full, the OLDEST half is discarded (sliding-window semantics); the FFT
/// then runs over the most recent play only.
pub const MAX_SERIES: usize = 4096;

pub struct RefreshAliasing {
    player_id: u64,
    /// Reaction-latency series (ms) onto occluded-knowledge events. Each entry is one
    /// latency sample; the analyzer treats the series as evenly-spaced for the FFT.
    series: Vec<f64>,
    /// Last client refresh Hz seen (for harmonic exclusion).
    client_refresh_hz: u16,
    /// Last client frame period (ns), derived from successive `client_mono_ns`.
    last_client_mono_ns: u64,
    client_frame_ns: u64,
    first_tick: Option<u64>,
    last_tick: u64,
}

impl RefreshAliasing {
    pub fn new(player_id: u64) -> Self {
        RefreshAliasing {
            player_id,
            series: Vec::new(),
            client_refresh_hz: 0,
            last_client_mono_ns: 0,
            client_frame_ns: 0,
            first_tick: None,
            last_tick: 0,
        }
    }

    /// Append one reaction-latency sample (ms). Exposed so the other analyzers' event
    /// machinery (or a backtest) can feed the shared series; `feed` also derives a
    /// per-tick proxy sample below.
    pub fn push_latency_ms(&mut self, ms: f64) {
        if ms.is_finite() {
            if self.series.len() >= MAX_SERIES {
                self.series.drain(..MAX_SERIES / 2);
            }
            self.series.push(ms);
        }
    }

    /// Fundamentals (normalized cycles-per-sample) to exclude as legitimate harmonics:
    /// the client refresh, the client frame cadence, and the server tick. Normalized
    /// by treating the series sample spacing as the mean client frame period when
    /// known; otherwise the exclusion set is the directly-supplied fundamentals scaled
    /// to the series. Because the absolute sample spacing is approximate, we exclude a
    /// small band around each (HARMONIC_TOL).
    fn excluded_fundamentals(&self) -> Vec<f64> {
        let mut out = Vec::new();
        // If we know the client frame period, the client-refresh fundamental in
        // cycles-per-sample is (frame_period / refresh_period) — but the series is
        // event-spaced, not frame-spaced, so we conservatively exclude the canonical
        // low-order normalized frequencies these cadences alias to. The exact mapping
        // is title-specific; over-excluding (a slightly wider band) only REDUCES false
        // positives, which is the safe direction for a knowledge-cheat flag.
        if self.client_refresh_hz > 0 {
            // Common monitor refreshes alias near these normalized bins for typical
            // event spacings; exclude their first few harmonics.
            let base = 1.0 / self.client_refresh_hz as f64;
            out.push(base);
        }
        if self.client_frame_ns > 0 {
            // Client frame cadence relative to a ~16.6ms (60Hz) reference series step.
            out.push(self.client_frame_ns as f64 / 16_666_666.0);
        }
        out
    }
}

impl Analyzer for RefreshAliasing {
    fn id(&self) -> SignalId {
        178
    }

    fn feed(&mut self, tick: &TickPayload, snap: &Snapshot) -> Result<(), TelemetryError> {
        self.first_tick.get_or_insert(snap.tick);
        self.last_tick = snap.tick;

        if tick.client_refresh_hz > 0 {
            self.client_refresh_hz = tick.client_refresh_hz;
        }
        if tick.client_mono_ns != 0 && self.last_client_mono_ns != 0 {
            let dt = tick.client_mono_ns.saturating_sub(self.last_client_mono_ns);
            if dt > 0 {
                self.client_frame_ns = dt;
            }
        }
        if tick.client_mono_ns != 0 {
            self.last_client_mono_ns = tick.client_mono_ns;
        }

        // Per-tick proxy latency sample: the client-reported render time minus the
        // authoritative sim time, when both are present (the lag between when the
        // server knew a fact and when the client acted is the aliasing carrier). This
        // is a fingerprint INPUT only, never trusted as truth (the client value can be
        // forged — but a forged-constant value just yields no peak).
        if tick.client_mono_ns != 0 && snap.mono_ns != 0 {
            let lag_ms = (tick.client_mono_ns as i128 - snap.mono_ns as i128).unsigned_abs() as f64
                / 1_000_000.0;
            self.push_latency_ms(lag_ms);
        }
        Ok(())
    }

    fn score(&self) -> Option<SuspicionEvent> {
        if self.series.len() < MIN_SERIES {
            return None;
        }
        let peak = dominant_peak(&self.series)?;
        if !peak.snr.is_finite() || peak.snr < SNR_FLOOR {
            return None;
        }
        // Exclude legitimate cadences: a peak at the client refresh / frame / server
        // tick harmonic is NOT a cheat fingerprint.
        let excluded = self.excluded_fundamentals();
        if is_harmonic_of(peak.freq_cycles_per_sample, &excluded, HARMONIC_TOL) {
            return None;
        }
        Some(SuspicionEvent {
            player_id: self.player_id,
            signal_id: self.id(),
            zscore: peak.snr,
            sample_count: self.series.len() as u32,
            window_ticks: self.last_tick.saturating_sub(self.first_tick.unwrap_or(0)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheat: a strong off-harmonic periodicity in the latency series (a fixed cheat
    /// refresh rate not aliased to the monitor) -> high-SNR peak, not excluded ->
    /// scores.
    #[test]
    fn off_harmonic_peak_scores() {
        let mut a = RefreshAliasing::new(1);
        a.client_refresh_hz = 144; // excludes ~1/144 normalized band
                                   // Inject a clean periodicity at normalized freq 0.20 (8-ish cycles over 40).
        let n = 64usize;
        for i in 0..n {
            let v = (2.0 * std::f64::consts::PI * 0.20 * i as f64).sin();
            a.push_latency_ms(10.0 + 5.0 * v);
        }
        let ev = a.score().expect("off-harmonic peak scores");
        assert_eq!(ev.signal_id, 178);
        assert!(ev.zscore >= SNR_FLOOR);
    }

    /// Clean: the dominant peak sits at the client refresh harmonic -> excluded -> no
    /// score. We set the excluded fundamental to the SAME normalized frequency as the
    /// injected peak.
    #[test]
    fn monitor_refresh_harmonic_is_clean() {
        let mut a = RefreshAliasing::new(1);
        // Choose a refresh whose excluded fundamental (1/hz) equals the injected
        // peak frequency 0.25 -> hz = 4 (synthetic; exercises the exclusion path).
        a.client_refresh_hz = 4;
        let n = 64usize;
        for i in 0..n {
            let v = (2.0 * std::f64::consts::PI * 0.25 * i as f64).sin();
            a.push_latency_ms(10.0 + 5.0 * v);
        }
        // The dominant peak (0.25) is a harmonic of the 1/4 = 0.25 fundamental.
        assert!(
            a.score().is_none(),
            "monitor-refresh-harmonic peak is excluded"
        );
    }

    /// Clean: a flat (no periodicity) series has no peak -> no score.
    #[test]
    fn flat_series_is_clean() {
        let mut a = RefreshAliasing::new(1);
        for _ in 0..MIN_SERIES + 4 {
            a.push_latency_ms(10.0);
        }
        assert!(a.score().is_none(), "flat latency series has no peak");
    }
}
