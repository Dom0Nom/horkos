//! Role: merge-gate bypass tests (guardrail #12) for the fusion + pipeline
//! decision path. Each test is an ATTACK on the ban path's policy invariants:
//! the attacker either tries to get an honest player banned (FP attack) or to
//! make a cheater's session unjudgeable (evasion). Registered as a `[[test]]`
//! in `server/ban-engine/Cargo.toml`; pure Rust, host-runnable, no game-server
//! peer.
//!
//! Target platforms: server (host CI).

use std::sync::Arc;
use std::time::Duration;

use ban_engine::error::BanEngineError;
use ban_engine::fusion::{fuse, FusionParams, Verdict};
use ban_engine::pipeline::{spawn, PipelineConfig};
use ban_engine::store::DecisionStore;
use telemetry::analyzers::SuspicionEvent;
use telemetry::geom::Vec3;
use telemetry::schema::{TickPayload, SCHEMA_VERSION};
use telemetry::sink::TickSink;
use telemetry::snapshot::{ipc, EntityState, Snapshot};

fn ev(signal_id: u16, z: f64, samples: u32) -> SuspicionEvent {
    SuspicionEvent {
        player_id: 1,
        signal_id,
        zscore: z,
        sample_count: samples,
        window_ticks: 100_000,
    }
}

/// ATTACK: a single compromised/buggy analyzer (or a single forged stream of
/// one signal) reports an astronomic z forever. The no-single-signal invariant
/// must hold at ANY magnitude and support.
#[test]
fn single_signal_cannot_ban_at_any_magnitude() {
    for z in [2.6, 5.0, 100.0, 1.0e12] {
        let out = fuse(&[ev(172, z, u32::MAX)], None, &FusionParams::default()).expect("fuse");
        assert_ne!(out.verdict, Verdict::Ban, "z={z} banned on one signal");
    }
}

/// ATTACK: replay the same signal id many times to fake corroboration.
#[test]
fn duplicated_signal_id_cannot_fake_corroboration() {
    let events: Vec<_> = (0..32).map(|i| ev(172, 5.0 + i as f64, 100)).collect();
    let out = fuse(&events, None, &FusionParams::default()).expect("fuse");
    assert_ne!(out.verdict, Verdict::Ban);
    assert_eq!(out.contributions.len(), 1, "one id = one contribution");
}

/// ATTACK: many signals, each individually sub-threshold, hoping bulk sums to
/// a ban (death-by-a-thousand-papercuts FP attack on an honest outlier).
#[test]
fn sub_threshold_bulk_never_aggregates() {
    let events: Vec<_> = (172u16..=180).map(|s| ev(s, 2.49, 1000)).collect();
    let out = fuse(&events, None, &FusionParams::default()).expect("fuse");
    assert_eq!(out.verdict, Verdict::Clean);
    assert_eq!(out.score, 0);
}

/// ATTACK: a poisoned rule bundle ships fusion params that disable the
/// corroboration gate or carry NaN tiers (NaN comparisons silently fail the
/// tier checks). Param validation must reject both regardless of source.
#[test]
fn poisoned_params_are_rejected() {
    let no_corroboration = FusionParams {
        min_corroborating_signals: 1,
        ..Default::default()
    };
    assert!(matches!(
        no_corroboration.validate(),
        Err(BanEngineError::InvalidFusionParams(_))
    ));

    let nan_tier = FusionParams {
        z_weak: f64::NAN,
        ..Default::default()
    };
    assert!(nan_tier.validate().is_err());

    // fuse() itself must refuse to run with poisoned params.
    assert!(fuse(&[ev(172, 5.0, 10)], None, &no_corroboration).is_err());
}

/// ATTACK: NaN injection through the event plane — a forged/buggy z must be
/// quarantined (skipped + recorded), neither convicting nor blinding fusion.
#[test]
fn nan_event_neither_convicts_nor_blinds() {
    let out = fuse(
        &[ev(172, f64::NAN, 100), ev(178, 5.0, 64), ev(173, 5.0, 64)],
        None,
        &FusionParams::default(),
    )
    .expect("fuse");
    assert_eq!(out.verdict, Verdict::Ban, "real evidence still convicts");
    assert!(out.skipped.iter().any(|s| s.signal_id == 172));
}

/// EVASION: the tick-domain offset. The client offsets its tick counter so no
/// telemetry tick ever pairs with an authoritative snapshot — every gamestate
/// analyzer is starved. The session must NOT look clean (that would be a free
/// bypass of the whole 172-180 domain), and the anomaly alone must never ban.
#[tokio::test]
async fn tick_offset_starvation_is_flagged_never_clean_never_banned() {
    let cfg = PipelineConfig {
        score_interval_ticks: 16,
        pairing_anomaly_min_ticks: 48,
        ..PipelineConfig::default()
    };
    let store = Arc::new(DecisionStore::memory());
    let handle = spawn(cfg, Arc::clone(&store));
    let sink = TickSink::new(handle.tick_senders());
    let player = 99u64;

    for tick in 1..=96u64 {
        handle
            .send_snapshot(Snapshot {
                schema_version: ipc::SNAPSHOT_SCHEMA_VERSION,
                tick,
                mono_ns: tick * 16_666_666,
                local_player_id: player,
                cam_origin: Vec3::ZERO,
                cam_forward: Vec3::new(1.0, 0.0, 0.0),
                cam_up: Vec3::new(0.0, 0.0, 1.0),
                cam_fov_rad: std::f32::consts::FRAC_PI_2,
                visibility: vec![false],
                audiopath: vec![false],
                recoil_rng_vec: Vec3::ZERO,
                objective_seed: 0,
                entities: vec![EntityState {
                    entity_id: 100,
                    position: Vec3::new(10.0, 0.0, 0.0),
                    velocity: Vec3::ZERO,
                    flags: ipc::ENT_ALIVE,
                }],
                occluders: Vec::new(),
            })
            .await;
        // The evasion: tick counter offset far outside any pairing window.
        sink.send(TickPayload {
            schema_version: SCHEMA_VERSION,
            player_id: player,
            tick: tick + 1_000_000,
            ..Default::default()
        })
        .expect("tick accepted");
    }

    let mut flagged = false;
    for _ in 0..100 {
        if let Ok(map) = handle.decisions.read() {
            if let Some(d) = map.get(&player) {
                assert_eq!(
                    d.verdict,
                    Verdict::Review,
                    "starvation alone must cap at Review"
                );
                flagged = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        flagged,
        "tick-domain offset must surface as an integrity anomaly, not silence"
    );
}

/// EVASION: flood-to-shed. One attacker floods ticks trying to fill the shared
/// channel so OTHER players' telemetry is shed. The per-player bucket must
/// shed the flooder visibly (429) while a second player stays admitted.
#[tokio::test]
async fn flood_is_shed_per_player_not_cross_player() {
    let cfg = PipelineConfig::default();
    let store = Arc::new(DecisionStore::memory());
    let handle = spawn(cfg, store);
    let sink = TickSink::new(handle.tick_senders());

    let mut flooder_shed = 0u32;
    for tick in 0..4096u64 {
        let r = sink.send(TickPayload {
            schema_version: SCHEMA_VERSION,
            player_id: 1,
            tick,
            ..Default::default()
        });
        if r.is_err() {
            flooder_shed += 1;
        }
    }
    assert!(flooder_shed > 0, "flooder is rate limited");

    // The victim's telemetry still goes through.
    sink.send(TickPayload {
        schema_version: SCHEMA_VERSION,
        player_id: 2,
        tick: 1,
        ..Default::default()
    })
    .expect("victim admitted despite the flood");
}
