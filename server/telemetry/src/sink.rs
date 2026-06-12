//! Role: ingest-side tick sink. Routes validated, server-stamped `TickPayload`s
//! from the HTTP ingest handler into the ban-engine pipeline's sharded mpsc
//! channels (shard = `player_id % shards`, so one player's session state is
//! always owned by one pipeline task). Fronts the shared channels with a
//! per-player token bucket so a single flooding client cannot fill the channel
//! and shed every OTHER player's telemetry (cross-player flood-to-shed gate).
//! Backpressure is never silent: a full shard returns 503 (`Overloaded`) and
//! increments a counter; a closed shard means the pipeline task died and
//! returns 500 (`Internal`) — the analysis brain being dead must not look like
//! a healthy server (fail-closed posture; `/healthz` flips via the pipeline's
//! alive flag).
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — async-safe: the only lock is a short, never-awaited-across
//! `std::sync::Mutex` critical section on the bucket map; `thiserror` via
//! `TelemetryError`; no `unwrap()` outside tests.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use tokio::sync::mpsc;

use crate::error::TelemetryError;
use crate::schema::TickPayload;

/// Token-bucket refill rate (ticks/second) per player. Generous vs. any real
/// game tick rate (placeholder, guardrail #14: the live value is a signed-rule
/// parameter); the bucket exists to stop floods, not to meter honest play.
pub const BUCKET_RATE_PER_S: f64 = 256.0;

/// Token-bucket burst capacity per player (absorbs reconnect catch-up bursts).
pub const BUCKET_BURST: f64 = 512.0;

/// Hard cap on tracked per-player buckets (memory DoS gate on the map itself).
/// On overflow, refilled-to-full (idle) buckets are swept first; if every entry
/// is active, one arbitrary entry is evicted and counted — bounded memory wins
/// over perfect per-player accounting under that much concurrency.
pub const MAX_BUCKETS: usize = 65_536;

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(now: Instant) -> Self {
        TokenBucket {
            tokens: BUCKET_BURST,
            last_refill: now,
        }
    }

    fn try_take(&mut self, now: Instant) -> bool {
        let dt = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + dt * BUCKET_RATE_PER_S).min(BUCKET_BURST);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn is_idle_full(&self, now: Instant) -> bool {
        let dt = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens + dt * BUCKET_RATE_PER_S >= BUCKET_BURST
    }
}

/// Routes ingest ticks to the pipeline shards. Construct with the senders the
/// pipeline spawner returns; shard count is fixed for the sink's lifetime.
#[derive(Debug)]
pub struct TickSink {
    shards: Vec<mpsc::Sender<TickPayload>>,
    buckets: Mutex<HashMap<u64, TokenBucket>>,
    /// Ticks rejected because a shard channel was full (visible shedding).
    pub shed_full: AtomicU64,
    /// Ticks rejected per-player by the token bucket.
    pub shed_rate_limited: AtomicU64,
    /// Bucket-map entries evicted while active (cap pressure, accounting loss).
    pub bucket_evictions: AtomicU64,
}

impl TickSink {
    /// `shards` must be non-empty; the caller (pipeline spawner) guarantees it.
    pub fn new(shards: Vec<mpsc::Sender<TickPayload>>) -> Self {
        debug_assert!(!shards.is_empty());
        TickSink {
            shards,
            buckets: Mutex::new(HashMap::new()),
            shed_full: AtomicU64::new(0),
            shed_rate_limited: AtomicU64::new(0),
            bucket_evictions: AtomicU64::new(0),
        }
    }

    /// Admit one validated, already-stamped tick into its player's shard.
    pub fn send(&self, payload: TickPayload) -> Result<(), TelemetryError> {
        let player_id = payload.player_id;
        if !self.admit(player_id) {
            self.shed_rate_limited.fetch_add(1, Ordering::Relaxed);
            return Err(TelemetryError::RateLimited);
        }

        if self.shards.is_empty() {
            return Err(TelemetryError::Internal);
        }
        let idx = (player_id % self.shards.len() as u64) as usize;
        match self.shards[idx].try_send(payload) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.shed_full.fetch_add(1, Ordering::Relaxed);
                Err(TelemetryError::Overloaded)
            }
            // Receiver gone = the pipeline task died. Fail loudly (500), not
            // "retry later": this server can no longer analyze anything.
            Err(mpsc::error::TrySendError::Closed(_)) => Err(TelemetryError::Internal),
        }
    }

    fn admit(&self, player_id: u64) -> bool {
        let now = Instant::now();
        let mut buckets = match self.buckets.lock() {
            Ok(g) => g,
            // Poisoned = a panic mid-update on another thread. Fail open for
            // rate limiting only (the shard channel still bounds memory).
            Err(_) => return true,
        };
        if !buckets.contains_key(&player_id) && buckets.len() >= MAX_BUCKETS {
            buckets.retain(|_, b| !b.is_idle_full(now));
            if buckets.len() >= MAX_BUCKETS {
                if let Some(&victim) = buckets.keys().next() {
                    buckets.remove(&victim);
                    self.bucket_evictions.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        buckets
            .entry(player_id)
            .or_insert_with(|| TokenBucket::new(now))
            .try_take(now)
    }
}
