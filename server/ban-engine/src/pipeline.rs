//! src/pipeline.rs
//!
//! Role: the end-to-end analysis pipeline — the running system between HTTP
//! ingest and a persisted decision. `spawn()` starts N hash-sharded tokio
//! tasks; each shard SOLELY owns the sessions of the players routed to it
//! (`player_id % shards`), so analyzer state is single-threaded by
//! construction — no locks around `AnalyzerRegistry`, and one player's FFT
//! cost cannot head-of-line-block another shard. Per shard, per player
//! session: pair incoming ticks with buffered authoritative snapshots
//! (consume-once merge-join within `pair_window_ticks` — exact-tick pairing
//! would let a client offset its counter and starve the gamestate domain
//! silently), feed the analyzer registry + arrival ring, and every
//! `score_interval_ticks` run fusion. Verdicts LATCH upward per session
//! (Clean->Review->Ban, never auto-downgrade) and only transitions are
//! persisted — cumulative analyzer scores would otherwise re-emit the same
//! Ban every interval. Sustained zero pairing is surfaced as a Review-tier
//! integrity anomaly (never bannable alone): a starved analyzer domain must
//! not look like a clean player.
//!
//! Lifecycle/fail-closed: a shard task exiting clears the shared `alive` flag
//! (healthz turns 503 — a dead analysis brain must not look healthy). Session
//! eviction (TTL or capacity) writes a SessionSummary record when the session
//! carries live suspicion state, so cheat-burst/idle-past-TTL cycling leaves
//! an audit trail instead of silently resetting accumulation.
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — fully async; the per-tick path is pure compute, no
//! blocking syscalls; bounded channels, bounded session maps, bounded
//! snapshot buffers (DoS gates); `thiserror`; no `unwrap()` outside tests.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use telemetry::analyzers::AnalyzerRegistry;
use telemetry::schema::TickPayload;
use telemetry::snapshot::Snapshot;
use tokio::sync::mpsc;

use crate::arrival_cadence::{Arrival, ArrivalRing, CadenceParams};
use crate::fusion::{fuse, FusionParams, Verdict};
use crate::store::{DecisionRecord, DecisionStore, RecordKind};

/// Pipeline tuning. Defaults are PoC-scale; the live values are deployment
/// configuration (and, for the fusion/cadence members, signed-rule parameters
/// per guardrail #14).
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Number of shard tasks (>=1). Sessions route by `player_id % shards`.
    pub shards: usize,
    /// Per-shard tick/snapshot channel capacity.
    pub channel_capacity: usize,
    /// Run fusion every this many received ticks per session.
    pub score_interval_ticks: u64,
    /// Evict a session after this long without traffic.
    pub session_ttl: Duration,
    /// Hard cap on live sessions per shard (memory DoS gate). On overflow the
    /// oldest CLEAN session is evicted first; if every session is non-clean,
    /// the new player is rejected and counted (visible fail-open).
    pub max_sessions_per_shard: usize,
    /// Tick-tolerance for the snapshot merge-join (consume-once, nearest-first).
    pub pair_window_ticks: u64,
    /// Per-session buffer of not-yet-paired snapshots (oldest dropped on overflow).
    pub snapshot_buffer: usize,
    /// Minimum received ticks before sustained zero pairing raises the
    /// Review-tier pairing-integrity anomaly.
    pub pairing_anomaly_min_ticks: u64,
    pub fusion: FusionParams,
    pub cadence: CadenceParams,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        PipelineConfig {
            shards: 1,
            channel_capacity: 1024,
            score_interval_ticks: 64,
            session_ttl: Duration::from_secs(300),
            max_sessions_per_shard: 4096,
            pair_window_ticks: 2,
            snapshot_buffer: 256,
            pairing_anomaly_min_ticks: 256,
            fusion: FusionParams::default(),
            cadence: CadenceParams::default(),
        }
    }
}

/// The per-player decision the HTTP surface serves (`GET /api/decisions/{id}`).
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct LatestDecision {
    pub player_id: u64,
    pub verdict: Verdict,
    pub score: u32,
    pub decided_at_ns: u64,
    /// Audit-record sequence number backing this decision.
    pub record_seq: u64,
}

/// Operational counters (health/monitoring surface). Every fail-open path in
/// the pipeline is counted here — silently unanalyzed traffic is the one
/// thing this design refuses to allow.
#[derive(Debug, Default)]
pub struct PipelineStats {
    /// Ticks from players rejected at the session cap (unanalyzed!).
    pub sessions_rejected: AtomicU64,
    /// Sessions evicted by TTL.
    pub sessions_expired: AtomicU64,
    /// Clean sessions evicted to make room at the cap.
    pub sessions_capacity_evicted: AtomicU64,
    /// SessionSummary records written on eviction.
    pub session_summaries: AtomicU64,
    /// Snapshots dropped (unknown shard backlog / buffer overflow).
    pub snapshots_dropped: AtomicU64,
}

/// Handle returned by `spawn`. Owns the input senders, the shared decision
/// map, and the liveness flag.
pub struct PipelineHandle {
    /// False once any shard task has exited — wire to `/healthz`.
    pub alive: Arc<AtomicBool>,
    pub decisions: Arc<RwLock<HashMap<u64, LatestDecision>>>,
    pub stats: Arc<PipelineStats>,
    pub store: Arc<DecisionStore>,
    tick_txs: Vec<mpsc::Sender<TickPayload>>,
    snap_txs: Vec<mpsc::Sender<Snapshot>>,
}

impl PipelineHandle {
    /// Senders for the ingest sink (`telemetry::sink::TickSink::new`).
    pub fn tick_senders(&self) -> Vec<mpsc::Sender<TickPayload>> {
        self.tick_txs.clone()
    }

    /// Route one authoritative snapshot to its player's shard. Returns false
    /// if the shard backlog dropped it (counted).
    pub async fn send_snapshot(&self, snap: Snapshot) -> bool {
        let idx = (snap.local_player_id % self.snap_txs.len() as u64) as usize;
        match self.snap_txs[idx].try_send(snap) {
            Ok(()) => true,
            Err(_) => {
                self.stats.snapshots_dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }
}

/// Spawn the pipeline shard tasks. Requires a running tokio runtime.
pub fn spawn(cfg: PipelineConfig, store: Arc<DecisionStore>) -> PipelineHandle {
    let shards = cfg.shards.max(1);
    let alive = Arc::new(AtomicBool::new(true));
    let decisions = Arc::new(RwLock::new(HashMap::new()));
    let stats = Arc::new(PipelineStats::default());

    let mut tick_txs = Vec::with_capacity(shards);
    let mut snap_txs = Vec::with_capacity(shards);
    for _ in 0..shards {
        let (tick_tx, tick_rx) = mpsc::channel::<TickPayload>(cfg.channel_capacity);
        let (snap_tx, snap_rx) = mpsc::channel::<Snapshot>(cfg.channel_capacity);
        tick_txs.push(tick_tx);
        snap_txs.push(snap_tx);

        let cfg = cfg.clone();
        let store = Arc::clone(&store);
        let decisions = Arc::clone(&decisions);
        let alive = Arc::clone(&alive);
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            shard_loop(cfg, tick_rx, snap_rx, store, decisions, stats).await;
            // Any shard exiting means the pipeline can no longer analyze its
            // players: flag the whole pipeline unhealthy (fail closed).
            alive.store(false, Ordering::Release);
            tracing::error!("pipeline shard exited; pipeline marked dead");
        });
    }

    PipelineHandle {
        alive,
        decisions,
        stats,
        store,
        tick_txs,
        snap_txs,
    }
}

struct PlayerSession {
    registry: AnalyzerRegistry,
    arrivals: ArrivalRing,
    /// Not-yet-consumed authoritative snapshots, keyed by snapshot tick.
    snaps: BTreeMap<u64, Snapshot>,
    latched: Verdict,
    session_start_ns: u64,
    last_seen: Instant,
    first_tick: Option<u64>,
    last_tick: u64,
    ticks_received: u64,
    ticks_paired: u64,
    pairing_misses: u64,
    schema_versions_seen: Vec<u32>,
}

impl PlayerSession {
    fn new(player_id: u64, now: Instant) -> Self {
        PlayerSession {
            registry: AnalyzerRegistry::new(player_id),
            arrivals: ArrivalRing::new(),
            snaps: BTreeMap::new(),
            latched: Verdict::Clean,
            session_start_ns: unix_now_ns(),
            last_seen: now,
            first_tick: None,
            last_tick: 0,
            ticks_received: 0,
            ticks_paired: 0,
            pairing_misses: 0,
            schema_versions_seen: Vec::new(),
        }
    }

    /// Consume-once merge-join: nearest buffered snapshot within the window,
    /// removed on use so a duplicate feed can never double-count (e.g. the
    /// recoil-RNG correlator treats each fed snapshot as one RNG sample).
    fn take_paired_snapshot(&mut self, tick: u64, window: u64) -> Option<Snapshot> {
        let lo = tick.saturating_sub(window);
        let hi = tick.saturating_add(window);
        let best = self
            .snaps
            .range(lo..=hi)
            .map(|(&k, _)| k)
            .min_by_key(|&k| k.abs_diff(tick))?;
        self.snaps.remove(&best)
    }

    fn buffer_snapshot(&mut self, snap: Snapshot, cap: usize) -> bool {
        if self.snaps.len() >= cap {
            // Oldest-first drop: ticks only move forward; the oldest buffered
            // snapshot is the least likely to ever pair.
            if let Some((&oldest, _)) = self.snaps.iter().next() {
                self.snaps.remove(&oldest);
            }
        }
        self.snaps.insert(snap.tick, snap).is_none()
    }

    fn has_live_suspicion(&self) -> bool {
        self.latched > Verdict::Clean || !self.registry.collect_suspicions().is_empty()
    }
}

async fn shard_loop(
    cfg: PipelineConfig,
    mut tick_rx: mpsc::Receiver<TickPayload>,
    mut snap_rx: mpsc::Receiver<Snapshot>,
    store: Arc<DecisionStore>,
    decisions: Arc<RwLock<HashMap<u64, LatestDecision>>>,
    stats: Arc<PipelineStats>,
) {
    let mut sessions: HashMap<u64, PlayerSession> = HashMap::new();
    let sweep_every = cfg.session_ttl.checked_div(4).unwrap_or(cfg.session_ttl);
    let mut sweep = tokio::time::interval(sweep_every.max(Duration::from_secs(1)));
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut snaps_open = true;

    loop {
        tokio::select! {
            tick = tick_rx.recv() => match tick {
                Some(t) => {
                    handle_tick(&cfg, &mut sessions, t, &store, &decisions, &stats).await;
                }
                // Ingest sink gone: the pipeline has no input plane left.
                None => break,
            },
            snap = snap_rx.recv(), if snaps_open => match snap {
                Some(s) => handle_snapshot(&cfg, &mut sessions, s, &stats),
                None => snaps_open = false,
            },
            _ = sweep.tick() => {
                sweep_sessions(&cfg, &mut sessions, &store, &stats).await;
            }
        }
    }
}

fn handle_snapshot(
    cfg: &PipelineConfig,
    sessions: &mut HashMap<u64, PlayerSession>,
    snap: Snapshot,
    stats: &PipelineStats,
) {
    let player_id = snap.local_player_id;
    let now = Instant::now();
    if let Some(session) = sessions.get_mut(&player_id) {
        session.last_seen = now;
        session.buffer_snapshot(snap, cfg.snapshot_buffer);
        return;
    }
    // Snapshot for an unknown player: the game server is authoritative, so
    // pre-create the session (its ticks are likely in flight) — capacity
    // permitting; never evict a live player for a buffered snapshot.
    if sessions.len() >= cfg.max_sessions_per_shard {
        stats.snapshots_dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let mut session = PlayerSession::new(player_id, now);
    session.buffer_snapshot(snap, cfg.snapshot_buffer);
    sessions.insert(player_id, session);
}

async fn handle_tick(
    cfg: &PipelineConfig,
    sessions: &mut HashMap<u64, PlayerSession>,
    tick: TickPayload,
    store: &DecisionStore,
    decisions: &RwLock<HashMap<u64, LatestDecision>>,
    stats: &PipelineStats,
) {
    let player_id = tick.player_id;
    let now = Instant::now();

    if !sessions.contains_key(&player_id) {
        if sessions.len() >= cfg.max_sessions_per_shard
            && !evict_oldest_clean(cfg, sessions, store, stats).await
        {
            // Every session is non-clean and the shard is full: rejecting the
            // new player is fail-open for them — counted, never silent.
            stats.sessions_rejected.fetch_add(1, Ordering::Relaxed);
            return;
        }
        sessions.insert(player_id, PlayerSession::new(player_id, now));
    }
    let session = match sessions.get_mut(&player_id) {
        Some(s) => s,
        None => return,
    };

    session.last_seen = now;
    session.ticks_received += 1;
    session.first_tick.get_or_insert(tick.tick);
    session.last_tick = tick.tick;
    if !session.schema_versions_seen.contains(&tick.schema_version) {
        session.schema_versions_seen.push(tick.schema_version);
    }

    session.arrivals.push(Arrival::from_payload(&tick));

    match session.take_paired_snapshot(tick.tick, cfg.pair_window_ticks) {
        Some(snap) => {
            session.ticks_paired += 1;
            if let Err(e) = session.registry.feed(&tick, &snap) {
                // A malformed pairing is a degraded-evidence event, not a
                // pipeline failure; the remaining analyzers kept their state.
                tracing::warn!(player_id, error = %e, "analyzer feed error");
            }
        }
        None => session.pairing_misses += 1,
    }

    if session.ticks_received % cfg.score_interval_ticks == 0 {
        score_session(cfg, session, store, decisions).await;
    }
}

async fn score_session(
    cfg: &PipelineConfig,
    session: &mut PlayerSession,
    store: &DecisionStore,
    decisions: &RwLock<HashMap<u64, LatestDecision>>,
) {
    let player_id = session.registry.player_id();
    let events = session.registry.collect_suspicions();
    let cadence = match crate::arrival_cadence::detect(&session.arrivals, &cfg.cadence) {
        Ok(obs) => obs,
        Err(e) => {
            tracing::warn!(player_id, error = %e, "cadence detect error");
            None
        }
    };

    let outcome = match fuse(&events, cadence, &cfg.fusion) {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(player_id, error = %e, "fusion error; no decision this pass");
            return;
        }
    };

    // Sustained zero pairing = the gamestate domain is starved (tick-domain
    // offset, missing game-server feed, or deliberate evasion). Review-tier
    // integrity anomaly, NEVER bannable alone.
    let pairing_anomaly =
        session.ticks_received >= cfg.pairing_anomaly_min_ticks && session.ticks_paired == 0;
    let mut candidate = outcome.verdict;
    if pairing_anomaly && candidate < Verdict::Review {
        candidate = Verdict::Review;
    }

    if candidate <= session.latched {
        return; // latched: only upward transitions are persisted
    }

    let record = DecisionRecord {
        seq: 0, // assigned by the store
        kind: RecordKind::Transition,
        decided_at_ns: unix_now_ns(),
        player_id,
        session_start_ns: session.session_start_ns,
        prev_verdict: session.latched,
        verdict: candidate,
        score: outcome.score,
        contributions: outcome.contributions,
        skipped: outcome.skipped,
        cadence: outcome.cadence,
        params: cfg.fusion,
        window_first_tick: session.first_tick.unwrap_or(0),
        window_last_tick: session.last_tick,
        ticks_received: session.ticks_received,
        ticks_paired: session.ticks_paired,
        pairing_misses: session.pairing_misses,
        pairing_anomaly,
        schema_versions_seen: session.schema_versions_seen.clone(),
    };
    let score = record.score;
    let decided_at_ns = record.decided_at_ns;
    match store.append(record).await {
        Ok(seq) => {
            session.latched = candidate;
            if let Ok(mut map) = decisions.write() {
                map.insert(
                    player_id,
                    LatestDecision {
                        player_id,
                        verdict: candidate,
                        score,
                        decided_at_ns,
                        record_seq: seq,
                    },
                );
            }
            tracing::info!(player_id, ?candidate, score, seq, "verdict transition");
        }
        Err(e) => {
            // Do NOT latch: an unpersisted decision must re-fire next pass
            // rather than exist only in memory (the audit log is the decision).
            tracing::error!(player_id, error = %e, "decision store append failed");
        }
    }
}

/// Evict the oldest session whose latched verdict is Clean. Returns false if
/// every session is non-clean (caller then rejects the new player, counted).
async fn evict_oldest_clean(
    cfg: &PipelineConfig,
    sessions: &mut HashMap<u64, PlayerSession>,
    store: &DecisionStore,
    stats: &PipelineStats,
) -> bool {
    let victim = sessions
        .iter()
        .filter(|(_, s)| s.latched == Verdict::Clean)
        .min_by_key(|(_, s)| s.last_seen)
        .map(|(&id, _)| id);
    match victim {
        Some(id) => {
            if let Some(session) = sessions.remove(&id) {
                stats
                    .sessions_capacity_evicted
                    .fetch_add(1, Ordering::Relaxed);
                end_session(cfg, session, store, stats).await;
            }
            true
        }
        None => false,
    }
}

async fn sweep_sessions(
    cfg: &PipelineConfig,
    sessions: &mut HashMap<u64, PlayerSession>,
    store: &DecisionStore,
    stats: &PipelineStats,
) {
    let now = Instant::now();
    let expired: Vec<u64> = sessions
        .iter()
        .filter(|(_, s)| now.duration_since(s.last_seen) >= cfg.session_ttl)
        .map(|(&id, _)| id)
        .collect();
    for id in expired {
        if let Some(session) = sessions.remove(&id) {
            stats.sessions_expired.fetch_add(1, Ordering::Relaxed);
            end_session(cfg, session, store, stats).await;
        }
    }
}

/// Final accounting for a session leaving the map. A session carrying live
/// suspicion state writes a SessionSummary so eviction can never silently
/// discard accumulated evidence (cheat-burst-then-idle cycling leaves a trail).
async fn end_session(
    cfg: &PipelineConfig,
    session: PlayerSession,
    store: &DecisionStore,
    stats: &PipelineStats,
) {
    if !session.has_live_suspicion() {
        return;
    }
    let events = session.registry.collect_suspicions();
    let cadence = crate::arrival_cadence::detect(&session.arrivals, &cfg.cadence)
        .ok()
        .flatten();
    let outcome = match fuse(&events, cadence, &cfg.fusion) {
        Ok(o) => o,
        Err(_) => return,
    };
    let record = DecisionRecord {
        seq: 0,
        kind: RecordKind::SessionSummary,
        decided_at_ns: unix_now_ns(),
        player_id: session.registry.player_id(),
        session_start_ns: session.session_start_ns,
        // Eviction grants no new ban authority: the summary records the
        // latched verdict plus the final evidence state; an upward transition
        // only ever happens through the scoring path while the session lives.
        prev_verdict: session.latched,
        verdict: session.latched,
        score: outcome.score,
        contributions: outcome.contributions,
        skipped: outcome.skipped,
        cadence: outcome.cadence,
        params: cfg.fusion,
        window_first_tick: session.first_tick.unwrap_or(0),
        window_last_tick: session.last_tick,
        ticks_received: session.ticks_received,
        ticks_paired: session.ticks_paired,
        pairing_misses: session.pairing_misses,
        pairing_anomaly: false,
        schema_versions_seen: session.schema_versions_seen.clone(),
    };
    if store.append(record).await.is_ok() {
        stats.session_summaries.fetch_add(1, Ordering::Relaxed);
    }
}

/// Wall-clock ns since UNIX epoch, anchored once and advanced monotonically
/// (an NTP step must not reorder audit timestamps).
fn unix_now_ns() -> u64 {
    static ANCHOR: std::sync::OnceLock<(u64, Instant)> = std::sync::OnceLock::new();
    let (epoch_ns, anchor) = ANCHOR.get_or_init(|| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        (now, Instant::now())
    });
    epoch_ns.saturating_add(anchor.elapsed().as_nanos() as u64)
}
