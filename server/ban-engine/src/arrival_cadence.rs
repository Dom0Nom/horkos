//! src/arrival_cadence.rs
//!
//! Role: Server-side relativistic-burst (lag-switch) arrival-cadence detector,
//! catalog signal 186 (`docs/detection-catalog.md` §network-anomaly). Consumes a
//! per-`player_id` ring of `(tick, server_received_ts)` pairs taken from the
//! `telemetry::schema::TickPayload` stream and looks for the lag-switch
//! signature: a window where client-send cadence (implied by the monotonic
//! `tick` counter) and server-receive cadence (`server_received_ts`) diverge —
//! a quiet GAP followed by a compensating BURST whose displacement conserves the
//! gap (burst makes up exactly the ticks the gap withheld). A genuine one-off
//! network handover (NAT rebind, Wi-Fi roam) produces a SINGLE gap-then-burst
//! and is excluded; the detector only fires on REPEATED occurrences with a
//! conservation ratio near 1.
//!
//! This is the ONLY network-anomaly signal with no client field — 186 is derived
//! entirely from data already present on `TickPayload` (`tick` from the client,
//! `server_received_ts` stamped by `telemetry::ingest`). The client ships nothing
//! new for it.
//!
//! Target platforms: server.
//!
//! Guardrails:
//!   #8 — pure synchronous compute: NO `.await`, NO blocking syscall, NO I/O, so
//!        it cannot stall a tokio worker when called from the async ingest path.
//!        `thiserror` error type; ZERO `unwrap()`/`expect()`/`panic!` outside
//!        `#[cfg(test)]`. Per-player state is a BOUNDED ring (capacity capped) so
//!        an adversarial high-rate client cannot grow memory without bound (DoS
//!        gate).
//!   #14 — the DECISION thresholds (min repeats, conservation tolerance, gap
//!        floor) are conservative placeholders here; the authoritative values
//!        arrive as a SIGNED rule through `crate::bundle::BundleLoader` (the
//!        fail-closed verifier still governs — no unsigned rule path). This file
//!        scaffolds the structural detector + the feature it scores; it produces
//!        a typed observation, NEVER a ban verdict (ban authority is the signed
//!        enforcement path, not this module).

use telemetry::schema::TickPayload;

/// Hard cap on the per-player arrival ring. Bounds memory against an adversarial
/// client that floods ticks (DoS gate, guardrail #8). Old samples are evicted
/// FIFO once the ring is full; the detector only needs a sliding window.
pub const MAX_RING: usize = 256;

/// Errors from the arrival-cadence path. Kept as a typed `thiserror` enum even
/// though the current detector is total over its input (it returns `None`/empty
/// on a degenerate window rather than erroring) so the signed-rule integration in
/// `/tdd` has a place to surface a malformed-threshold or capacity error without
/// reaching for `panic!`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ArrivalCadenceError {
    /// A configured threshold parameter (arriving via the signed rule bundle) was
    /// outside its valid domain. Surfaced rather than panicked (guardrail #8).
    #[error("invalid arrival-cadence threshold: {0}")]
    InvalidThreshold(&'static str),
}

/// One observed arrival: the client's monotonic tick and the server wall-clock
/// receipt time (ns since UNIX epoch) stamped by `telemetry::ingest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arrival {
    pub tick: u64,
    pub server_received_ts: u64,
}

impl Arrival {
    /// Extract the arrival pair from a `TickPayload`. `server_received_ts` is set
    /// by the ingest handler before this runs; a `0` value means it was not
    /// stamped (e.g. a raw client payload in a unit test) and the sample is still
    /// stored — the detector's gap math simply yields no signal from a zero clock.
    #[must_use]
    pub fn from_payload(p: &TickPayload) -> Self {
        Arrival {
            tick: p.tick,
            server_received_ts: p.server_received_ts,
        }
    }
}

/// Bounded per-player ring of recent arrivals. One instance per `player_id`,
/// held in a bounded outer map by the caller (the ingest/session layer, later
/// phase). The ring itself caps its own length so a single player cannot grow it
/// past `MAX_RING`.
#[derive(Debug, Clone, Default)]
pub struct ArrivalRing {
    samples: std::collections::VecDeque<Arrival>,
}

impl ArrivalRing {
    #[must_use]
    pub fn new() -> Self {
        ArrivalRing {
            samples: std::collections::VecDeque::with_capacity(MAX_RING),
        }
    }

    /// Push one arrival, evicting the oldest when at capacity (FIFO). Out-of-order
    /// or duplicate ticks are stored as-is; the detector tolerates them (it scores
    /// on monotone-tick subsequences, not on raw adjacency).
    pub fn push(&mut self, a: Arrival) {
        if self.samples.len() == MAX_RING {
            let _ = self.samples.pop_front();
        }
        self.samples.push_back(a);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

/// Conservation parameters for the gap-then-burst test. Conservative placeholders
/// here; the authoritative values ride a SIGNED rule via `BundleLoader` (guardrail
/// #14) — this struct is the shape that rule deserialises into, not a hard
/// client-side threshold.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CadenceParams {
    /// Minimum number of conserved gap-then-burst occurrences before the window is
    /// flagged. A single occurrence is a benign handover (NAT rebind / Wi-Fi roam)
    /// and is excluded (FP gate). Must be >= 2.
    pub min_repeats: u32,
    /// Tolerance band (dimensionless) around the ideal conservation ratio of 1.0.
    /// A burst conserves the gap when `|ratio - 1| <= tol`. Must be in (0, 1).
    pub conservation_tol: f32,
    /// Minimum receive-gap-vs-expected ratio for a window to count as a GAP (a
    /// receive interval this many times the expected per-tick interval). Must be
    /// > 1. Jitter below this is normal network variance, not a lag-switch quiet.
    pub gap_factor: f32,
}

impl Default for CadenceParams {
    fn default() -> Self {
        // Placeholders only (guardrail #14): the live values are signed-rule
        // parameters. Chosen conservatively so the scaffold's own tests exercise
        // the structural math, NOT to convict in production.
        CadenceParams {
            min_repeats: 2,
            conservation_tol: 0.15,
            gap_factor: 3.0,
        }
    }
}

impl CadenceParams {
    /// Validate the (signed-rule-supplied) parameters. Returns a typed error
    /// rather than panicking on a malformed bundle (guardrail #8).
    fn validate(&self) -> Result<(), ArrivalCadenceError> {
        if self.min_repeats < 2 {
            return Err(ArrivalCadenceError::InvalidThreshold(
                "min_repeats must be >= 2",
            ));
        }
        if !(self.conservation_tol > 0.0 && self.conservation_tol < 1.0) {
            return Err(ArrivalCadenceError::InvalidThreshold(
                "conservation_tol must be in (0, 1)",
            ));
        }
        // NaN must fail validation, same as a gap_factor <= 1.
        if self.gap_factor.partial_cmp(&1.0) != Some(std::cmp::Ordering::Greater) {
            return Err(ArrivalCadenceError::InvalidThreshold(
                "gap_factor must be > 1",
            ));
        }
        Ok(())
    }
}

/// Typed observation emitted by the detector. A FEATURE for the server scoring
/// path, NOT a ban verdict (guardrail #14 — verdicts ride the signed enforcement
/// path). `conserved_repeats` is how many gap-then-burst pairs in the window
/// conserved their gap within tolerance; `worst_conservation` is the closest
/// observed ratio to the ideal 1.0 (informational).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CadenceObservation {
    pub conserved_repeats: u32,
    pub worst_conservation: f32,
    /// True iff `conserved_repeats >= params.min_repeats`. A flag for the scorer,
    /// not an action.
    pub flagged: bool,
}

/// Core detector. Pure function over the ring + params. Returns `Ok(None)` when
/// the window is too short or carries no usable clock; `Ok(Some(obs))` with the
/// structural feature otherwise. No verdict, no I/O, no `.await` (guardrail #8).
///
/// Mechanism: walk consecutive monotone-tick arrivals. For each adjacent pair
/// compute the per-tick receive interval and compare it to the window's median
/// per-tick interval. A receive interval >= `gap_factor` x median marks a GAP of
/// `gap_ticks`; the immediately-following arrivals whose receive interval is far
/// BELOW median (a burst) are summed and the displacement is the burst's tick
/// advance over its compressed receive time. The conservation ratio is
/// `burst_displacement_ticks / gap_ticks`; a lag-switch conserves it near 1
/// (the burst delivers exactly the ticks the gap withheld). Repeated conserved
/// pairs are counted; a single one is benign.
pub fn detect(
    ring: &ArrivalRing,
    params: &CadenceParams,
) -> Result<Option<CadenceObservation>, ArrivalCadenceError> {
    params.validate()?;

    // Need a usable window. Fewer than 4 arrivals cannot contain a gap+burst pair.
    if ring.samples.len() < 4 {
        return Ok(None);
    }

    // Build the monotone-tick, positive-clock subsequence so out-of-order and
    // unstamped (ts == 0) samples don't poison the interval math.
    let mut seq: Vec<Arrival> = Vec::with_capacity(ring.samples.len());
    for a in &ring.samples {
        if a.server_received_ts == 0 {
            continue;
        }
        match seq.last() {
            Some(prev) if a.tick <= prev.tick || a.server_received_ts < prev.server_received_ts => {
                // Non-monotone in tick or clock — skip to keep intervals positive.
            }
            _ => seq.push(*a),
        }
    }
    if seq.len() < 4 {
        return Ok(None);
    }

    // Per-tick receive interval for each adjacent pair: receive-ns delta divided
    // by tick delta. Tick delta is guaranteed >= 1 by the monotone filter above.
    let mut per_tick: Vec<f64> = Vec::with_capacity(seq.len() - 1);
    for w in seq.windows(2) {
        let dt_ns = w[1]
            .server_received_ts
            .saturating_sub(w[0].server_received_ts) as f64;
        let dticks = (w[1].tick - w[0].tick) as f64; // > 0 by construction
        per_tick.push(dt_ns / dticks);
    }

    let median = median_of(&per_tick);
    if median <= 0.0 {
        return Ok(None);
    }

    let gap_threshold = median * f64::from(params.gap_factor);
    let burst_threshold = median / f64::from(params.gap_factor);

    // Scan for gap[i] immediately followed by a burst[i+1..]. The burst is the run
    // of below-threshold per-tick intervals right after a gap; its conserved
    // displacement is the tick advance over that run.
    let mut conserved_repeats: u32 = 0;
    let mut worst_conservation = f32::INFINITY; // closest |ratio-1| tracked as the ratio
    let mut best_abs_dev = f32::INFINITY;

    let mut i = 0usize;
    while i < per_tick.len() {
        if per_tick[i] >= gap_threshold {
            // Gap span in ticks: how many ticks the slow receive interval covered.
            let gap_ticks = (seq[i + 1].tick - seq[i].tick) as f64;

            // Collect the immediately-following burst run.
            let mut j = i + 1;
            let mut burst_ticks = 0f64;
            while j < per_tick.len() && per_tick[j] <= burst_threshold {
                burst_ticks += (seq[j + 1].tick - seq[j].tick) as f64;
                j += 1;
            }

            if burst_ticks > 0.0 && gap_ticks > 0.0 {
                let ratio = (burst_ticks / gap_ticks) as f32;
                let abs_dev = (ratio - 1.0).abs();
                if abs_dev <= params.conservation_tol {
                    conserved_repeats = conserved_repeats.saturating_add(1);
                }
                if abs_dev < best_abs_dev {
                    best_abs_dev = abs_dev;
                    worst_conservation = ratio;
                }
                // Advance past the consumed burst run.
                i = j;
                continue;
            }
        }
        i += 1;
    }

    if conserved_repeats == 0 {
        return Ok(Some(CadenceObservation {
            conserved_repeats: 0,
            worst_conservation: if worst_conservation.is_finite() {
                worst_conservation
            } else {
                0.0
            },
            flagged: false,
        }));
    }

    Ok(Some(CadenceObservation {
        conserved_repeats,
        worst_conservation,
        flagged: conserved_repeats >= params.min_repeats,
    }))
}

/// Median of a slice, by sorting a copy. Empty -> 0.0. Total (no panic).
fn median_of(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a ring from (tick, ts_ns) pairs.
    fn ring_from(pairs: &[(u64, u64)]) -> ArrivalRing {
        let mut r = ArrivalRing::new();
        for &(tick, ts) in pairs {
            r.push(Arrival {
                tick,
                server_received_ts: ts,
            });
        }
        r
    }

    /// Stationary, jittered arrivals at ~10ms/tick: no gap-then-burst -> no flag.
    #[test]
    fn stationary_jitter_does_not_flag() {
        let base = 10_000_000u64; // 10 ms per tick
        let mut pairs = Vec::new();
        let mut ts = 0u64;
        for t in 0..40u64 {
            // +/- 8% jitter, deterministic.
            let jitter = if t % 2 == 0 { base / 12 } else { 0 };
            ts += base + jitter;
            pairs.push((t, ts));
        }
        let obs = detect(&ring_from(&pairs), &CadenceParams::default())
            .expect("valid params")
            .expect("enough samples");
        assert_eq!(obs.conserved_repeats, 0);
        assert!(!obs.flagged);
    }

    /// Engineered repeated gap-then-burst with conservation ~1 -> flagged.
    #[test]
    fn repeated_conserved_burst_flags() {
        let base = 10_000_000u64; // 10 ms/tick nominal receive cadence
        let mut pairs = Vec::new();
        let mut ts = 0u64;
        let mut tick = 0u64;
        // Helper invariant: each pushed arrival carries the NEXT tick. The gap
        // arrival advances `tick` by exactly GAP_TICKS over a long quiet receive
        // window; the following burst advances `tick` by exactly GAP_TICKS over a
        // compressed receive window — so the conservation ratio is exactly 1.0.
        const GAP_TICKS: u64 = 5;
        // Three lag-switch cycles: hold (gap, server clock advances but ticks
        // don't arrive), then a burst delivering the withheld ticks compressed.
        for _cycle in 0..3 {
            // Normal run: one tick advance per arrival.
            for _ in 0..5 {
                ts += base;
                tick += 1;
                pairs.push((tick, ts));
            }
            // GAP: next arrival advances tick by GAP_TICKS over a long quiet
            // period -> per-tick interval >> median.
            ts += base * 20; // long quiet
            tick += GAP_TICKS;
            pairs.push((tick, ts));
            // BURST: deliver GAP_TICKS more ticks in a compressed receive window
            // (tiny per-tick interval), conserving the gap exactly.
            for _ in 0..GAP_TICKS {
                ts += base / 20;
                tick += 1;
                pairs.push((tick, ts));
            }
        }
        let obs = detect(&ring_from(&pairs), &CadenceParams::default())
            .expect("valid params")
            .expect("enough samples");
        assert!(
            obs.conserved_repeats >= 2,
            "expected >=2 conserved bursts, got {}",
            obs.conserved_repeats
        );
        assert!(obs.flagged);
    }

    /// A SINGLE gap-then-burst (one NAT rebind) must NOT flag (FP gate).
    #[test]
    fn single_handover_does_not_flag() {
        let base = 10_000_000u64;
        let mut pairs = Vec::new();
        let mut ts = 0u64;
        let mut tick = 0u64;
        for _ in 0..8 {
            ts += base;
            pairs.push((tick, ts));
            tick += 1;
        }
        // One gap+burst.
        ts += base * 20;
        tick += 5;
        pairs.push((tick, ts));
        for _ in 0..5 {
            ts += base / 20;
            tick += 1;
            pairs.push((tick, ts));
        }
        // More normal traffic.
        for _ in 0..8 {
            ts += base;
            tick += 1;
            pairs.push((tick, ts));
        }
        let obs = detect(&ring_from(&pairs), &CadenceParams::default())
            .expect("valid params")
            .expect("enough samples");
        assert!(obs.conserved_repeats <= 1);
        assert!(!obs.flagged, "single handover must not flag");
    }

    #[test]
    fn short_window_returns_none() {
        let r = ring_from(&[(0, 1), (1, 2)]);
        assert_eq!(
            detect(&r, &CadenceParams::default()).expect("valid params"),
            None
        );
    }

    #[test]
    fn unstamped_clock_returns_none() {
        // All ts == 0 -> no usable clock.
        let r = ring_from(&[(0, 0), (1, 0), (2, 0), (3, 0), (4, 0)]);
        assert_eq!(
            detect(&r, &CadenceParams::default()).expect("valid params"),
            None
        );
    }

    #[test]
    fn invalid_params_error_not_panic() {
        let r = ring_from(&[(0, 1), (1, 2), (2, 3), (3, 4)]);
        let bad = CadenceParams {
            min_repeats: 1,
            ..CadenceParams::default()
        };
        assert_eq!(
            detect(&r, &bad),
            Err(ArrivalCadenceError::InvalidThreshold(
                "min_repeats must be >= 2"
            ))
        );
        let bad2 = CadenceParams {
            conservation_tol: 2.0,
            ..CadenceParams::default()
        };
        assert!(matches!(
            detect(&r, &bad2),
            Err(ArrivalCadenceError::InvalidThreshold(_))
        ));
    }

    #[test]
    fn ring_is_bounded() {
        let mut r = ArrivalRing::new();
        for t in 0..(MAX_RING as u64 + 50) {
            r.push(Arrival {
                tick: t,
                server_received_ts: t + 1,
            });
        }
        assert_eq!(r.len(), MAX_RING);
    }

    #[test]
    fn from_payload_reads_tick_and_ts() {
        let p = TickPayload {
            tick: 42,
            server_received_ts: 99,
            ..TickPayload::default()
        };
        let a = Arrival::from_payload(&p);
        assert_eq!(a.tick, 42);
        assert_eq!(a.server_received_ts, 99);
    }
}
