//! bypass-tests/server/gamestate_replay.rs
//!
//! Role: bypass / FP-resistance merge-gate (guardrail #12) for the behavioral-
//! gamestate-knowledge analyzers (catalog signals 172-180). Each documented cheat
//! behavior is encoded as a synthetic authoritative-snapshot + client-tick stream and
//! asserted to TRIP its analyzer; a matched, deliberately-adversarial CLEAN decoy
//! (legit pre-fire, sound cue, teammate callout, lag-comp jitter edge, fixed-meta
//! spawn, monitor-refresh harmonic, mean-only recoil) is asserted NOT to trip — the
//! analyzer must be defeated by NEITHER the cheat being subtle NOR the clean case
//! looking superficially similar. A torn/garbage shm frame must fail closed-but-safe
//! (`InvalidPayload`, never a panic).
//!
//! Target platforms: server. Pure Rust; drives the public `telemetry::analyzers::*`
//! API against in-memory fixtures with no game-server peer (runs in normal CI under
//! the default `gamestate-analyzers` feature, `gamestate-ipc-shm` irrelevant — no live
//! ring is touched). Registered as a `[[test]]` target of the `telemetry` crate (see
//! `server/telemetry/Cargo.toml`) so `cargo test -p telemetry` is the gate.
//!
//! These mirror the unit tests embedded in each analyzer but live at the bypass path
//! so the merge gate is explicit and a reviewer can confirm one detect+evade pair per
//! signal in a single file. Every fixture builds `Snapshot`/`TickPayload` through the
//! crate's PUBLIC surface only.

use telemetry::analyzers::attention_budget::AttentionBudget;
use telemetry::analyzers::dynamic_occluder::DynamicOccluder;
use telemetry::analyzers::flick_precog::FlickPrecog;
use telemetry::analyzers::occlusion_preaim::OcclusionPreaim;
use telemetry::analyzers::peek_latency::PeekLatency;
use telemetry::analyzers::positional_prior::PositionalPrior;
use telemetry::analyzers::recoil_rng_corr::RecoilRngCorr;
use telemetry::analyzers::refresh_aliasing::RefreshAliasing;
use telemetry::analyzers::vision_cone::VisionCone;
use telemetry::analyzers::Analyzer;
use telemetry::geom::{Aabb, Vec3};
use telemetry::schema::TickPayload;
use telemetry::snapshot::ipc::{self, parse_slot};
use telemetry::snapshot::{EntityState, OccluderVolume, Snapshot};

// ---- fixture builders (public-surface only) -------------------------------

/// A neutral snapshot: local player at origin looking down +X, 90deg FOV, no others.
fn base(tick: u64, mono_ns: u64) -> Snapshot {
    Snapshot {
        schema_version: ipc::SNAPSHOT_SCHEMA_VERSION,
        tick,
        mono_ns,
        local_player_id: 1,
        cam_origin: Vec3::ZERO,
        cam_forward: Vec3::new(1.0, 0.0, 0.0),
        cam_up: Vec3::new(0.0, 0.0, 1.0),
        cam_fov_rad: std::f32::consts::FRAC_PI_2,
        visibility: Vec::new(),
        audiopath: Vec::new(),
        recoil_rng_vec: Vec3::ZERO,
        objective_seed: 0,
        entities: Vec::new(),
        occluders: Vec::new(),
    }
}

/// Push one enemy actor with its parallel visibility/audio bits.
fn enemy(snap: &mut Snapshot, id: u64, pos: Vec3, vel: Vec3, visible: bool, audio: bool) {
    snap.entities.push(EntityState {
        entity_id: id,
        position: pos,
        velocity: vel,
        flags: ipc::ENT_ALIVE,
    });
    snap.visibility.push(visible);
    snap.audiopath.push(audio);
}

/// Push one enemy flagged as a TEAMMATE (its visibility approximates teammate LoS).
fn teammate(snap: &mut Snapshot, id: u64, pos: Vec3) {
    snap.entities.push(EntityState {
        entity_id: id,
        position: pos,
        velocity: Vec3::ZERO,
        flags: ipc::ENT_ALIVE | ipc::ENT_TEAM,
    });
    snap.visibility.push(false);
    snap.audiopath.push(false);
}

/// Encode an aim as the yaw/pitch toward `target` from `origin` in the base (+X fwd,
/// +Z up) view frame, matching `geom::aim_from_yaw_pitch`'s convention.
fn aim_at(target: Vec3, origin: Vec3) -> TickPayload {
    let d = target - origin;
    TickPayload {
        aim_delta_x: d.y.atan2(d.x),
        aim_delta_y: (d.z / d.len().max(1e-6)).asin(),
        ..Default::default()
    }
}

// =====================================================================
// 172 occlusion pre-aim  +  177 flick precog (shared wallhack stimulus)
// =====================================================================

/// Wallhack pre-aim: aim locks onto a fully occluded, silent enemy every engagement.
#[test]
fn preaim_through_wall_detected() {
    let mut a = OcclusionPreaim::new(1);
    for t in 0..16u64 {
        let mut s = base(t, t * 1_000_000);
        enemy(
            &mut s,
            100,
            Vec3::new(10.0, 0.0, 0.0),
            Vec3::ZERO,
            false,
            false,
        );
        // Aim straight ahead (zero deltas keep forward = +X) -> ~0 error onto the
        // occluded enemy directly ahead.
        a.feed(&TickPayload::default(), &s).expect("feed");
    }
    let ev = a.score().expect("occluded tight-lock must trip 172");
    assert_eq!(ev.signal_id, 172);
    assert!(ev.zscore > 0.0);
}

/// Clean: a pre-fire on a learned common angle where the occluded enemy is NOT
/// actually there (the aim does not correlate with any live occluded position) ->
/// no occluded-enemy lock is ever recorded -> no score.
#[test]
fn preaim_prefire_common_angle_clean() {
    let mut a = OcclusionPreaim::new(1);
    for t in 0..16u64 {
        let mut s = base(t, t * 1_000_000);
        // Occluded enemy is off to the side; the player pre-fires straight ahead at a
        // doorway (the "common angle"), so the aim error onto the enemy is large.
        enemy(
            &mut s,
            100,
            Vec3::new(2.0, 9.0, 0.0),
            Vec3::ZERO,
            false,
            false,
        );
        a.feed(&TickPayload::default(), &s).expect("feed");
    }
    assert!(
        a.score().is_none(),
        "pre-fire on an empty common angle must stay clean"
    );
}

/// Wallhack flick precog: at LoS onset the aim hugs the LIVE (occluded-updated)
/// position of an enemy that moved while occluded.
#[test]
fn flick_precog_to_live_position_detected() {
    let mut a = FlickPrecog::new(1);
    let mut t = 0u64;
    for _ in 0..10 {
        // See it at the last-seen spot.
        let mut s0 = base(t, t * 1_000_000);
        enemy(
            &mut s0,
            100,
            Vec3::new(10.0, 0.0, 0.0),
            Vec3::ZERO,
            true,
            false,
        );
        a.feed(&TickPayload::default(), &s0).expect("feed");
        t += 1;
        // It vanishes and moves far while occluded.
        let mut s1 = base(t, t * 1_000_000);
        enemy(
            &mut s1,
            100,
            Vec3::new(10.0, 8.0, 0.0),
            Vec3::ZERO,
            false,
            false,
        );
        a.feed(&TickPayload::default(), &s1).expect("feed");
        t += 1;
        // LoS onset: aim already hugs the LIVE moved position.
        let mut s2 = base(t, t * 1_000_000);
        let live = Vec3::new(10.0, 8.0, 0.0);
        enemy(&mut s2, 100, live, Vec3::ZERO, true, false);
        a.feed(&aim_at(live, s2.cam_origin), &s2).expect("feed");
        t += 1;
    }
    let ev = a
        .score()
        .expect("aim hugging the live occluded position must trip 177");
    assert_eq!(ev.signal_id, 177);
    assert!(ev.zscore > 0.0);
}

// =====================================================================
// 173 vision cone  (off-frustum reaction)
// =====================================================================

/// Sub-floor reaction onto an enemy that is off-frustum, silent, and uncalled.
#[test]
fn offfrustum_reaction_detected() {
    let mut a = VisionCone::new(1);
    let behind = Vec3::new(-10.0, 0.0, 0.0); // directly behind the +X view
    for k in 0..8u64 {
        // Onset tick: enemy appears off-frustum.
        let mut s0 = base(k * 2, (k * 2) * 1_000_000);
        enemy(&mut s0, 100 + k, behind, Vec3::ZERO, false, false);
        a.feed(&TickPayload::default(), &s0).expect("feed");
        // 10 ms later: an instant corrective turn toward the unseen enemy (sub-floor).
        let mut s1 = base(k * 2 + 1, (k * 2) * 1_000_000 + 10_000_000);
        enemy(&mut s1, 100 + k, behind, Vec3::ZERO, false, false);
        a.feed(&aim_at(behind, s1.cam_origin), &s1).expect("feed");
    }
    let ev = a
        .score()
        .expect("sub-floor off-frustum reaction must trip 173");
    assert_eq!(ev.signal_id, 173);
    assert!(ev.zscore > 0.0);
}

/// Clean: the same off-frustum enemy but with an authoritative AUDIO path -> the
/// reaction is legitimately explainable by sound -> never counted.
#[test]
fn offfrustum_with_audio_path_clean() {
    let mut a = VisionCone::new(1);
    let behind = Vec3::new(-10.0, 0.0, 0.0);
    for k in 0..8u64 {
        let mut s0 = base(k * 2, (k * 2) * 1_000_000);
        enemy(&mut s0, 100 + k, behind, Vec3::ZERO, false, true); // audible
        a.feed(&TickPayload::default(), &s0).expect("feed");
        let mut s1 = base(k * 2 + 1, (k * 2) * 1_000_000 + 10_000_000);
        enemy(&mut s1, 100 + k, behind, Vec3::ZERO, false, true);
        a.feed(&aim_at(behind, s1.cam_origin), &s1).expect("feed");
    }
    assert!(
        a.score().is_none(),
        "an audible off-frustum enemy is legitimately knowable"
    );
}

/// Clean: the off-frustum enemy is one a TEAMMATE has LoS on (callout-explainable) ->
/// never counted.
#[test]
fn offfrustum_with_teammate_los_clean() {
    let mut a = VisionCone::new(1);
    let behind = Vec3::new(-10.0, 0.0, 0.0);
    for k in 0..8u64 {
        let mut s0 = base(k * 2, (k * 2) * 1_000_000);
        // The "enemy" is flagged as a team actor so `teammate_has_los` is true.
        teammate(&mut s0, 100 + k, behind);
        a.feed(&TickPayload::default(), &s0).expect("feed");
        let mut s1 = base(k * 2 + 1, (k * 2) * 1_000_000 + 10_000_000);
        teammate(&mut s1, 100 + k, behind);
        a.feed(&aim_at(behind, s1.cam_origin), &s1).expect("feed");
    }
    assert!(
        a.score().is_none(),
        "a teammate-seen actor is callout-explainable"
    );
}

// =====================================================================
// 174 peek latency  (peeker advantage vs RTT budget)
// =====================================================================

/// Sub-budget peek: with a ~40 ms RTT budget the player fires ~5 ms after mutual-LoS
/// onset, repeatedly.
#[test]
fn subbudget_peek_detected() {
    let mut a = PeekLatency::new(1);
    for _ in 0..40 {
        a.push_rtt_ns(40_000_000.0); // steady 40 ms
    }
    for t in 0..8u64 {
        let mut s0 = base(t, t * 50_000_000);
        enemy(
            &mut s0,
            100,
            Vec3::new(10.0, 0.0, 0.0),
            Vec3::ZERO,
            true,
            false,
        );
        a.feed(&TickPayload::default(), &s0).expect("feed"); // onset
        let mut s1 = base(t, t * 50_000_000 + 5_000_000); // shot 5 ms later
        enemy(
            &mut s1,
            100,
            Vec3::new(10.0, 0.0, 0.0),
            Vec3::ZERO,
            true,
            false,
        );
        let fire = TickPayload {
            fired: true,
            ..Default::default()
        };
        a.feed(&fire, &s1).expect("feed");
    }
    let ev = a
        .score()
        .expect("a 5 ms shot under a 40 ms budget must trip 174");
    assert_eq!(ev.signal_id, 174);
    assert!(ev.zscore > 0.0);
}

/// Clean: bursty jitter widens the p95-high budget; the player fires AFTER the widened
/// budget, so no deficit accrues even though the mean RTT is the same.
#[test]
fn peek_within_jitter_p95_clean() {
    let mut a = PeekLatency::new(1);
    let pattern = [20_000_000.0, 60_000_000.0, 24_000_000.0, 56_000_000.0];
    for i in 0..60 {
        a.push_rtt_ns(pattern[i % pattern.len()]);
    }
    // Fire well after a generous over-estimate of the jitter-widened p95-high budget
    // (the samples top out at 60 ms; 85 ms is safely past any p95-high estimate here),
    // so no sub-budget deficit accrues.
    let after = 85_000_000u64;
    for t in 0..8u64 {
        let mut s0 = base(t, t * 200_000_000);
        enemy(
            &mut s0,
            100,
            Vec3::new(10.0, 0.0, 0.0),
            Vec3::ZERO,
            true,
            false,
        );
        a.feed(&TickPayload::default(), &s0).expect("feed");
        let mut s1 = base(t, t * 200_000_000 + after);
        enemy(
            &mut s1,
            100,
            Vec3::new(10.0, 0.0, 0.0),
            Vec3::ZERO,
            true,
            false,
        );
        let fire = TickPayload {
            fired: true,
            ..Default::default()
        };
        a.feed(&fire, &s1).expect("feed");
    }
    assert!(
        a.score().is_none(),
        "firing after the jitter-widened budget must stay clean"
    );
}

// =====================================================================
// 175 dynamic occluder  (through-smoke tracking)
// =====================================================================

fn smoke() -> OccluderVolume {
    OccluderVolume {
        aabb: Aabb {
            min: Vec3::new(2.0, -3.0, -3.0),
            max: Vec3::new(4.0, 3.0, 3.0),
        },
        born_tick: 0,
        expire_tick: 100_000,
    }
}

/// Through-smoke lock: the enemy MANEUVERS (changes heading) inside the smoke yet the
/// aim tracks it with ~zero error variance.
#[test]
fn smoke_track_locked_detected() {
    let mut a = DynamicOccluder::new(1);
    let mut t = 0u64;
    for _ in 0..6 {
        // Pre-smoke open tracking with natural jitter (nonzero pre-variance).
        for k in 0..4 {
            let mut s = base(t, t * 1_000_000);
            let pos = Vec3::new(8.0, k as f32 * 0.5, 0.0);
            enemy(&mut s, 100, pos, Vec3::new(0.0, 1.0, 0.0), false, false);
            let jitter = Vec3::new(8.0, k as f32 * 0.5 + 0.4, 0.0);
            a.feed(&aim_at(jitter, s.cam_origin), &s).expect("feed");
            t += 1;
        }
        // Inside smoke: enemy turns each tick; aim locks perfectly (zero intra-variance).
        for h in [
            Vec3::new(0.0, 1.0, 0.0),
            Vec3::new(1.0, 0.5, 0.0),
            Vec3::new(1.0, -0.5, 0.0),
        ] {
            let mut s = base(t, t * 1_000_000);
            s.occluders.push(smoke());
            let pos = Vec3::new(6.0, 0.0, 0.0);
            enemy(&mut s, 100, pos, h, false, false);
            a.feed(&aim_at(pos, s.cam_origin), &s).expect("feed");
            t += 1;
        }
        // Post-smoke: finalize the event.
        let mut s = base(t, t * 1_000_000);
        let pos = Vec3::new(8.0, 0.0, 0.0);
        enemy(&mut s, 100, pos, Vec3::new(1.0, 0.0, 0.0), false, false);
        a.feed(&aim_at(pos, s.cam_origin), &s).expect("feed");
        t += 1;
    }
    let ev = a
        .score()
        .expect("locking onto a maneuvering enemy through smoke must trip 175");
    assert_eq!(ev.signal_id, 175);
    assert!(ev.zscore > 0.0);
}

/// Clean: the enemy moves STRAIGHT through the smoke (no heading change) -> a memorized
/// path explains any lock -> not scoreable.
#[test]
fn smoke_prefire_known_path_clean() {
    let mut a = DynamicOccluder::new(1);
    let mut t = 0u64;
    for _ in 0..6 {
        for _k in 0..3 {
            let mut s = base(t, t * 1_000_000);
            s.occluders.push(smoke());
            let pos = Vec3::new(6.0, 0.0, 0.0);
            enemy(&mut s, 100, pos, Vec3::new(0.0, 1.0, 0.0), false, false); // constant heading
            a.feed(&aim_at(pos, s.cam_origin), &s).expect("feed");
            t += 1;
        }
        let mut s = base(t, t * 1_000_000);
        enemy(
            &mut s,
            100,
            Vec3::new(8.0, 0.0, 0.0),
            Vec3::new(0.0, 1.0, 0.0),
            false,
            false,
        );
        a.feed(&TickPayload::default(), &s).expect("feed");
        t += 1;
    }
    assert!(
        a.score().is_none(),
        "a straight memorized path through smoke must stay clean"
    );
}

// =====================================================================
// 176 positional prior  (beeline to random objective)
// =====================================================================

fn local_moving(tick: u64, heading: Vec3, seed: u64) -> Snapshot {
    let mut s = base(tick, tick * 1_000_000);
    s.objective_seed = seed;
    s.local_player_id = 1;
    s.entities.push(EntityState {
        entity_id: 1,
        position: Vec3::new(tick as f32, 0.0, 0.0),
        velocity: heading,
        flags: ipc::ENT_ALIVE | ipc::ENT_LOCAL,
    });
    s.visibility.push(false);
    s.audiopath.push(false);
    s
}

/// Beeline: a dead-straight path (collapsed heading entropy) toward a SERVER-RANDOM
/// objective across several runs.
#[test]
fn beeline_to_random_objective_detected() {
    let mut a = PositionalPrior::new(1);
    for run in 0..4u64 {
        for k in 0..17u64 {
            let s = local_moving(run * 100 + k, Vec3::new(1.0, 0.0, 0.0), 0xABCDEF);
            a.feed(&TickPayload::default(), &s).expect("feed");
        }
    }
    let ev = a
        .score()
        .expect("a beeline to a random objective must trip 176");
    assert_eq!(ev.signal_id, 176);
    assert!(ev.sample_count >= 3);
}

/// Clean: the SAME beeline but to a FIXED-meta spawn (seed == 0, not randomized this
/// match) -> a legitimately memorizable location -> not scoreable.
#[test]
fn beeline_to_fixed_meta_spawn_clean() {
    let mut a = PositionalPrior::new(1);
    for run in 0..4u64 {
        for k in 0..17u64 {
            let s = local_moving(run * 100 + k, Vec3::new(1.0, 0.0, 0.0), 0); // fixed seed
            a.feed(&TickPayload::default(), &s).expect("feed");
        }
    }
    assert!(
        a.score().is_none(),
        "a beeline to a fixed meta spawn must stay clean"
    );
}

// =====================================================================
// 178 refresh aliasing  (cheat refresh-rate off-harmonic peak)
// =====================================================================

/// Off-harmonic peak: a strong periodicity in the occluded-knowledge latency series at
/// a frequency that is NOT a harmonic of the monitor refresh.
#[test]
fn offharmonic_refresh_peak_detected() {
    let mut a = RefreshAliasing::new(1);
    // Feed paired ticks/snaps so the analyzer derives its latency series from
    // (client_mono_ns - snap.mono_ns); inject a clean 0.20 cycles/sample periodicity
    // and a 144 Hz monitor (whose comb is too dense to legitimately exclude 0.20).
    for i in 0..64u64 {
        let mut s = base(i, i * 1_000_000);
        s.local_player_id = 1;
        let periodic = (2.0 * std::f64::consts::PI * 0.20 * i as f64).sin();
        let lag_ms = 10.0 + 5.0 * periodic; // ms
        let client_mono_ns = s.mono_ns + (lag_ms * 1_000_000.0) as u64;
        let tick = TickPayload {
            client_mono_ns,
            client_refresh_hz: 144,
            ..Default::default()
        };
        a.feed(&tick, &s).expect("feed");
    }
    let ev = a
        .score()
        .expect("an off-harmonic latency peak must trip 178");
    assert_eq!(ev.signal_id, 178);
}

/// Clean: the dominant latency periodicity sits exactly at the monitor-refresh
/// harmonic -> excluded -> no score. We pick a synthetic refresh whose excluded
/// fundamental equals the injected peak frequency (0.25 == 1/4).
#[test]
fn monitor_refresh_harmonic_clean() {
    let mut a = RefreshAliasing::new(1);
    for i in 0..64u64 {
        let mut s = base(i, i * 1_000_000);
        s.local_player_id = 1;
        let periodic = (2.0 * std::f64::consts::PI * 0.25 * i as f64).sin();
        let lag_ms = 10.0 + 5.0 * periodic;
        let client_mono_ns = s.mono_ns + (lag_ms * 1_000_000.0) as u64;
        let tick = TickPayload {
            client_mono_ns,
            client_refresh_hz: 4, // excluded fundamental 1/4 = 0.25 == the peak
            ..Default::default()
        };
        a.feed(&tick, &s).expect("feed");
    }
    assert!(
        a.score().is_none(),
        "a peak at the monitor-refresh harmonic must be excluded"
    );
}

// =====================================================================
// 179 attention budget  (multi-target attention impossibility)
// =====================================================================

/// Multi-occluded attention: the player simultaneously near-locks more distinct
/// occluded+silent+uncalled enemies than the human budget, window after window.
#[test]
fn multi_occluded_attention_detected() {
    let mut a = AttentionBudget::new(1);
    // Four occluded enemies at distinct bearings; the aim is dead-ahead (+X) so the
    // one ahead is locked, but the cheat fixture marks all four as tracked by feeding
    // the aim straight at each in turn within one tick window is not possible — instead
    // we place all four AT the same forward bearing band so each is within TRACK_LOCK
    // of the dead-ahead aim. Distinctness (4 ids) over budget (2) is the impossibility.
    let bearings = [
        Vec3::new(10.0, 0.0, 0.0),
        Vec3::new(10.0, 0.02, 0.0),
        Vec3::new(10.0, -0.02, 0.0),
        Vec3::new(10.0, 0.0, 0.02),
    ];
    let mut tick = 0u64;
    for _w in 0..6 {
        // Each window: every enemy is occluded, silent, uncalled, and within the
        // near-lock cone of the dead-ahead aim.
        for _ in 0..17u64 {
            let mut s = base(tick, tick * 1_000_000);
            for (k, b) in bearings.iter().enumerate() {
                enemy(&mut s, 200 + k as u64, *b, Vec3::ZERO, false, false);
            }
            a.feed(&TickPayload::default(), &s).expect("feed");
            tick += 1;
        }
    }
    let ev = a
        .score()
        .expect("tracking 4 occluded enemies over a budget of 2 must trip 179");
    assert_eq!(ev.signal_id, 179);
    assert!(ev.zscore > 0.0);
}

/// Clean: the same multiplicity but every extra occluded actor is one a TEAMMATE has
/// LoS on (callout-explainable) -> residual tracked count stays within budget.
#[test]
fn multi_callout_explained_clean() {
    let mut a = AttentionBudget::new(1);
    let mut tick = 0u64;
    for _w in 0..6 {
        for _ in 0..17u64 {
            let mut s = base(tick, tick * 1_000_000);
            // One genuinely-unseen enemy dead ahead...
            enemy(
                &mut s,
                200,
                Vec3::new(10.0, 0.0, 0.0),
                Vec3::ZERO,
                false,
                false,
            );
            // ...and three more at the same bearing that teammates can see (callouts).
            teammate(&mut s, 201, Vec3::new(10.0, 0.02, 0.0));
            teammate(&mut s, 202, Vec3::new(10.0, -0.02, 0.0));
            teammate(&mut s, 203, Vec3::new(10.0, 0.0, 0.02));
            a.feed(&TickPayload::default(), &s).expect("feed");
            tick += 1;
        }
    }
    assert!(
        a.score().is_none(),
        "callout-explained multiplicity must stay clean"
    );
}

// =====================================================================
// 180 recoil RNG correlation  (compensation under zero feedback)
// =====================================================================

/// Cheat recoil: while firing with NO enemy visible (zero feedback), the player's
/// counter-motion tracks the per-shot RANDOM recoil component (a mean-zero curve here,
/// so the correlation IS to the unlearnable RNG).
#[test]
fn recoil_random_component_correlated_detected() {
    let mut a = RecoilRngCorr::new(1); // default mean curve = zero (pure RNG)
                                       // A deterministic pseudo-random recoil sequence; the cheat applies its exact
                                       // negation as counter-motion -> correlation magnitude ~1.
    let rng = [
        0.3f32, -0.4, 0.5, -0.2, 0.45, -0.35, 0.25, -0.5, 0.4, -0.3, 0.2, -0.45, 0.5, -0.25,
    ];
    for (i, &r) in rng.iter().enumerate() {
        let mut s = base(i as u64, i as u64 * 1_000_000);
        s.recoil_rng_vec = Vec3::new(r, r * 0.5, 0.0);
        // No enemy visible at all -> zero-feedback gate passes.
        let tick = TickPayload {
            fire_active: true,
            aim_delta_x: -r,       // counter the X recoil exactly
            aim_delta_y: -r * 0.5, // counter the Y recoil exactly
            weapon_id: 1,
            shot_index: i as u32,
            ..Default::default()
        };
        a.feed(&tick, &s).expect("feed");
    }
    let ev = a
        .score()
        .expect("counter-motion tracking the RNG component must trip 180");
    assert_eq!(ev.signal_id, 180);
    assert!(ev.zscore >= 0.6);
}

/// Clean: a skilled human matches only the learnable MEAN recoil curve and ignores the
/// per-shot RNG. With a non-trivial injected mean curve and applied == -mean, the
/// random-component residual the player tracked is zero -> correlation ~0 -> no score.
#[test]
fn recoil_mean_pattern_only_clean() {
    // Injected signed mean-recoil curve: a rising pull the player has memorized.
    let mean_curve = |_w: u32, shot: u32| {
        let m = 0.1 * (shot as f32 + 1.0);
        (m, m * 0.5)
    };
    let mut a = RecoilRngCorr::with_mean_curve(1, Box::new(mean_curve));
    let rng = [
        0.3f32, -0.4, 0.5, -0.2, 0.45, -0.35, 0.25, -0.5, 0.4, -0.3, 0.2, -0.45, 0.5, -0.25,
    ];
    for (i, &r) in rng.iter().enumerate() {
        let (mx, my) = mean_curve(1, i as u32);
        let mut s = base(i as u64, i as u64 * 1_000_000);
        // Authoritative recoil = mean + RNG residual.
        s.recoil_rng_vec = Vec3::new(mx + r, my + r * 0.5, 0.0);
        // The skilled human compensates ONLY the mean (no knowledge of the RNG).
        let tick = TickPayload {
            fire_active: true,
            aim_delta_x: -mx,
            aim_delta_y: -my,
            weapon_id: 1,
            shot_index: i as u32,
            ..Default::default()
        };
        a.feed(&tick, &s).expect("feed");
    }
    assert!(
        a.score().is_none(),
        "matching only the learnable mean must stay clean"
    );
}

// =====================================================================
// fail-closed-but-safe: a torn / garbage shm frame never panics
// =====================================================================

/// A short (sub-head) and a garbage frame both return `InvalidPayload`, never panic
/// (guardrail #8; shm trust boundary). Exercises the same `parse_slot` the live reader
/// and the fixture replay share.
#[test]
fn torn_snapshot_frame_no_panic() {
    // Far shorter than the fixed head.
    let short = [0u8; 8];
    assert!(
        parse_slot(&short).is_err(),
        "a sub-head slot must be rejected, not panic"
    );

    // Full head length but a garbage schema version (0xFFFFFFFF at offset 0) -> the
    // trust boundary rejects it instead of indexing into junk.
    let garbage = vec![0xFFu8; ipc::RECORD_HEAD_BYTES];
    assert!(
        parse_slot(&garbage).is_err(),
        "a wrong-schema frame must be rejected, not panic"
    );

    // A well-formed, valid-schema, zero-count head is the non-panicking SUCCESS path of
    // the same trust boundary (entity_count == occluder_count == 0).
    let mut valid = vec![0u8; ipc::RECORD_HEAD_BYTES];
    valid[0..4].copy_from_slice(&ipc::SNAPSHOT_SCHEMA_VERSION.to_ne_bytes());
    assert!(
        parse_slot(&valid).is_ok(),
        "a valid zero-count head must parse cleanly"
    );
}
