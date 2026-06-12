//! Role: end-to-end pipeline integration — ingest sink -> sharded session ->
//! analyzer registry -> fusion -> latched verdict + persisted audit record.
//! Drives the real `pipeline::spawn` with synthetic authoritative snapshots
//! (no live game-server peer) and asserts the wiring, the latch, and the
//! audit-record content. Detection calibration is NOT under test here (the
//! fusion unit tests own that); thresholds are tuned per-test so the plumbing
//! outcome is deterministic.
//!
//! Target platforms: server (host-runnable).

use std::sync::Arc;
use std::time::Duration;

use ban_engine::fusion::{FusionParams, Verdict};
use ban_engine::pipeline::{spawn, PipelineConfig};
use ban_engine::store::{DecisionStore, RecordKind};
use telemetry::geom::Vec3;
use telemetry::schema::{TickPayload, SCHEMA_VERSION};
use telemetry::sink::TickSink;
use telemetry::snapshot::{ipc, EntityState, Snapshot};

/// One authoritative frame: local player at origin looking down +X, one
/// occluded + silent enemy straight ahead (the wallhack-preaim tell).
fn snapshot_with_occluded_enemy(player_id: u64, tick: u64) -> Snapshot {
    Snapshot {
        schema_version: ipc::SNAPSHOT_SCHEMA_VERSION,
        tick,
        mono_ns: tick * 16_666_666, // ~60 Hz sim
        local_player_id: player_id,
        cam_origin: Vec3::ZERO,
        cam_forward: Vec3::new(1.0, 0.0, 0.0),
        cam_up: Vec3::new(0.0, 0.0, 1.0),
        cam_fov_rad: std::f32::consts::FRAC_PI_2,
        visibility: vec![false], // occluded
        audiopath: vec![false],  // silent
        recoil_rng_vec: Vec3::ZERO,
        objective_seed: 0,
        entities: vec![EntityState {
            entity_id: 100,
            position: Vec3::new(10.0, 0.0, 0.0),
            velocity: Vec3::ZERO,
            flags: ipc::ENT_ALIVE,
        }],
        occluders: Vec::new(),
    }
}

/// A cheater's tick: aim locked dead-on the occluded enemy (zero deltas keep
/// the aim on +X), plus a client-side periodicity in `client_mono_ns` that the
/// refresh-aliasing analyzer resolves as an off-harmonic spectral peak.
fn cheater_tick(player_id: u64, tick: u64, i: usize) -> TickPayload {
    let sine = (2.0 * std::f64::consts::PI * 0.20 * i as f64).sin();
    let lag_ns = (10.0e6 + 5.0e6 * sine) as u64;
    TickPayload {
        schema_version: SCHEMA_VERSION,
        player_id,
        tick,
        aim_delta_x: 0.0,
        aim_delta_y: 0.0,
        client_refresh_hz: 144,
        client_mono_ns: tick * 16_666_666 + lag_ns,
        ..Default::default()
    }
}

fn test_config() -> PipelineConfig {
    PipelineConfig {
        shards: 2,
        score_interval_ticks: 16,
        pairing_anomaly_min_ticks: 48,
        // Plumbing-deterministic thresholds: occlusion-preaim's honest-baseline
        // z is ~2.67 here (moderate), refresh-aliasing's SNR is strong; the
        // two corroborate. Calibration of the real priors is fusion's problem.
        fusion: FusionParams {
            z_moderate: 2.5,
            review_threshold: 35,
            ban_threshold: 60,
            ..FusionParams::default()
        },
        ..PipelineConfig::default()
    }
}

/// Poll the decision map until `player_id` reaches `want` (or time out).
async fn wait_for_verdict(
    handle: &ban_engine::pipeline::PipelineHandle,
    player_id: u64,
    want: Verdict,
) -> bool {
    for _ in 0..100 {
        if let Ok(map) = handle.decisions.read() {
            if map.get(&player_id).is_some_and(|d| d.verdict >= want) {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[tokio::test]
async fn corroborated_cheater_is_banned_and_audited() {
    let store = Arc::new(DecisionStore::memory());
    let handle = spawn(test_config(), Arc::clone(&store));
    let sink = TickSink::new(handle.tick_senders());
    let player = 7u64;

    // Snapshots first, then a drain pause: the snap and tick channels are
    // processed by one select loop in nondeterministic order, and the
    // merge-join only pairs a tick against an ALREADY-buffered snapshot.
    for i in 0..96usize {
        let tick = i as u64 + 1;
        assert!(
            handle
                .send_snapshot(snapshot_with_occluded_enemy(player, tick))
                .await,
            "snapshot accepted"
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    for i in 0..96usize {
        let tick = i as u64 + 1;
        sink.send(cheater_tick(player, tick, i))
            .expect("tick accepted");
    }

    assert!(
        wait_for_verdict(&handle, player, Verdict::Ban).await,
        "corroborated multi-signal cheater reaches Ban"
    );

    let records = store.records().await;
    let bans: Vec<_> = records
        .iter()
        .filter(|r| r.verdict == Verdict::Ban && r.kind == RecordKind::Transition)
        .collect();
    // The latch: exactly ONE Ban transition, no re-fires on later intervals.
    assert_eq!(bans.len(), 1, "ban persisted exactly once: {records:#?}");
    let ban = bans[0];
    assert_eq!(ban.player_id, player);
    assert!(ban.contributions.len() >= 2, "corroborated evidence");
    let ids: Vec<u16> = ban.contributions.iter().map(|c| c.signal_id).collect();
    assert!(ids.contains(&172), "occlusion-preaim contributed: {ids:?}");
    assert!(ids.contains(&178), "refresh-aliasing contributed: {ids:?}");
    assert!(ban.ticks_paired > 0, "evidence came from paired ticks");
    assert_eq!(ban.params.ban_threshold, 60, "params inlined in the record");
}

#[tokio::test]
async fn clean_player_yields_no_decision() {
    let store = Arc::new(DecisionStore::memory());
    let handle = spawn(test_config(), Arc::clone(&store));
    let sink = TickSink::new(handle.tick_senders());
    let player = 11u64;

    for tick in 1..=96u64 {
        // Enemy VISIBLE: a tight aim is legitimately knowable; constant client
        // clock cadence: no off-harmonic peak.
        let mut snap = snapshot_with_occluded_enemy(player, tick);
        snap.visibility[0] = true;
        handle.send_snapshot(snap).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    for tick in 1..=96u64 {
        let t = TickPayload {
            schema_version: SCHEMA_VERSION,
            player_id: player,
            tick,
            client_refresh_hz: 144,
            client_mono_ns: tick * 16_666_666 + 10_000_000,
            ..Default::default()
        };
        sink.send(t).expect("tick accepted");
    }

    // Give the pipeline time to run several scoring passes.
    tokio::time::sleep(Duration::from_millis(300)).await;
    {
        let map = handle.decisions.read().expect("map readable");
        assert!(
            map.get(&player).is_none(),
            "clean traffic never transitions: {:?}",
            map.get(&player)
        );
    }
    assert!(store.records().await.is_empty(), "no audit records");
}

#[tokio::test]
async fn unpaired_session_raises_review_integrity_anomaly_never_ban() {
    let store = Arc::new(DecisionStore::memory());
    let handle = spawn(test_config(), Arc::clone(&store));
    let sink = TickSink::new(handle.tick_senders());
    let player = 13u64;

    // The tick-domain-offset evasion: the client offsets its counter so no
    // tick ever pairs with a snapshot. The gamestate domain is starved — that
    // must surface as a Review-tier anomaly, never silently look clean, and
    // never escalate to Ban on its own.
    for i in 0..96usize {
        let tick = i as u64 + 1;
        handle
            .send_snapshot(snapshot_with_occluded_enemy(player, tick))
            .await;
        sink.send(cheater_tick(player, tick + 1_000_000, i))
            .expect("tick accepted");
    }

    assert!(
        wait_for_verdict(&handle, player, Verdict::Review).await,
        "starved pairing surfaces as Review"
    );
    {
        let map = handle.decisions.read().expect("map readable");
        let d = map.get(&player).expect("decision present");
        assert_eq!(d.verdict, Verdict::Review, "anomaly alone never bans");
    }

    let records = store.records().await;
    let rec = records
        .iter()
        .find(|r| r.player_id == player && r.kind == RecordKind::Transition)
        .expect("transition record");
    assert!(rec.pairing_anomaly, "record names the anomaly");
    assert_eq!(rec.ticks_paired, 0);
    assert!(rec.pairing_misses > 0);
}

#[tokio::test]
async fn alive_flag_clears_when_input_plane_closes() {
    let store = Arc::new(DecisionStore::memory());
    let handle = spawn(test_config(), store);
    let alive = Arc::clone(&handle.alive);
    assert!(alive.load(std::sync::atomic::Ordering::Acquire));

    // Dropping the handle drops every tick sender; shards see a closed input
    // plane, exit, and clear the shared flag (healthz then serves 503).
    drop(handle);
    for _ in 0..100 {
        if !alive.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("pipeline death did not clear the alive flag");
}
