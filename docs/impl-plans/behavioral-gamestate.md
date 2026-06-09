# Server-Side — Game-State Knowledge (`behavioral-gamestate`)

**Scope:** Nine pure server-side analyzers that detect "knowledge cheats" (wallhack/ESP/radar/silent-aim/no-recoil) by replaying the game server's **authoritative** snapshot stream and proving a player acted on information they could not legitimately have. No client signal is trusted as ground truth; every verdict derives from server-known visibility, audio, RTT, RNG, and navmesh state. All sensors are read-only; ban authority stays in `ban-engine`.

**Catalog signals covered:** 172 (occlusion-resolved pre-aim lead), 173 (vision-cone knowledge leakage), 174 (peeker-advantage vs RTT budget), 175 (through-smoke tracking continuity), 176 (positional-prior beelining), 177 (flick endpoint precognition), 178 (knowledge-update lag fingerprint / refresh aliasing), 179 (multi-target attention impossibility), 180 (recoil-RNG compensation under zero feedback).

These are all `server` / `server` layer. They share one new ingest primitive — an **authoritative snapshot replay ring** fed over IPC from the game-server process (`mmap`/`shm_open`) — and nine analyzer modules registered in the telemetry pipeline. The existing `TickPayload` (HTTP/JSON, client-reported) supplies the per-tick aim/input series; the new snapshot ring supplies the server-authoritative positions/visibility/RNG that the client is never told. The discriminator in every signal is **client-reported behavior vs. server-only ground truth**.

---

## New files

All Rust under `server/telemetry/`. Guardrail #1: no platform API outside a `backends/` folder — the only OS-specific code (`shm_open`/`mmap`, `getsockopt(TCP_INFO)`, `clock_gettime`) is isolated in `ipc/backends/` behind `HK_PLATFORM_*`-gated `cfg`. Guardrail #4 is a C/kernel concern (kernel vs userspace TU); these are all userspace Rust, but the IPC layer that mirrors the C snapshot layout lives in its own module and never pulls kernel headers.

| Path | Role | Module-comment summary (guardrail #3) |
|---|---|---|
| `server/telemetry/src/snapshot/mod.rs` | Authoritative snapshot-replay model: per-tick entity transforms, camera basis, visibility (PVS/BVH) results, audio-path graph, dynamic occluders, recoil RNG vectors, navmesh objective seed — the server-known truth the client lacks. | Role: authoritative game-state snapshot model + tick replay cursor for game-state-knowledge analyzers. Target: server. Interface: consumed by all `analyzers/*` in this domain; populated by `snapshot/ipc`. |
| `server/telemetry/src/snapshot/ipc.rs` | Lock-free SPSC reader over the shared-memory ring the game server publishes; maps the C-ABI `HkSnapshotRecord` frames into safe `snapshot` types. No blocking on async threads (guardrail #8): runs on a dedicated `spawn_blocking`/std thread feeding a `tokio::sync::mpsc`. | Role: shm/mmap SPSC consumer bridging the game-server snapshot ring into the async telemetry pipeline. Target: server. Interface: backend selected via `ipc/backends`. |
| `server/telemetry/src/snapshot/backends/posix.rs` | `shm_open`+`mmap` POSIX shared-memory attach (Linux/macOS game servers). | Role: POSIX shm backend for the snapshot ring. Target: server (HK_PLATFORM_LINUX/MACOS). Interface: implements `SnapshotRingAttach`. |
| `server/telemetry/src/snapshot/backends/win.rs` | `CreateFileMappingW`/`MapViewOfFile` named-section attach (Windows game servers). | Role: Win32 file-mapping backend for the snapshot ring. Target: server (HK_PLATFORM_WINDOWS). Interface: implements `SnapshotRingAttach`. |
| `server/telemetry/src/geom.rs` | Pure geometry/visibility helpers: ray-vs-AABB, frustum containment, angular error between aim vector and target, view-basis reconstruction. No I/O, fully unit-testable. | Role: pure geometry + visibility math for game-state analyzers. Target: server. Interface: used by every analyzer. |
| `server/telemetry/src/stats.rs` | Population-baseline z-score, EWMA RTT p95 estimator, FFT/autocorrelation over a latency series, per-shot-vs-mean correlation. Shared by FP-gating in all nine signals. | Role: shared statistical gating (z-score, p95, FFT, correlation) for game-state analyzers. Target: server. Interface: used by analyzers; no `unwrap()` (guardrail #8). |
| `server/telemetry/src/analyzers/mod.rs` | Analyzer registry + `Analyzer` trait; `feed(tick, snapshot)` per analyzer, `score()` accumulator, suspicion-event emission to `ban-engine`. | Role: analyzer trait + pipeline registry for the game-state-knowledge domain. Target: server. Interface: registered in `lib.rs`. |
| `server/telemetry/src/analyzers/occlusion_preaim.rs` | Signal 172. | Role: occlusion-resolved pre-aim lead analyzer. Target: server. Interface: `Analyzer`. |
| `server/telemetry/src/analyzers/vision_cone.rs` | Signal 173. | Role: vision-cone knowledge-leakage analyzer (off-frustum reaction). Target: server. Interface: `Analyzer`. |
| `server/telemetry/src/analyzers/peek_latency.rs` | Signal 174. | Role: peeker-advantage vs RTT+jitter budget analyzer. Target: server. Interface: `Analyzer`. |
| `server/telemetry/src/analyzers/dynamic_occluder.rs` | Signal 175. | Role: through-smoke/particle-volume tracking-continuity analyzer. Target: server. Interface: `Analyzer`. |
| `server/telemetry/src/analyzers/positional_prior.rs` | Signal 176. | Role: positional-prior beelining (entropy-collapsed pathing) analyzer. Target: server. Interface: `Analyzer`. |
| `server/telemetry/src/analyzers/flick_precog.rs` | Signal 177. | Role: flick-endpoint precognition (pre-LoS aim seeding) analyzer. Target: server. Interface: `Analyzer`. |
| `server/telemetry/src/analyzers/refresh_aliasing.rs` | Signal 178. | Role: knowledge-update lag fingerprint (cheat refresh-rate aliasing) analyzer. Target: server. Interface: `Analyzer`. |
| `server/telemetry/src/analyzers/attention_budget.rs` | Signal 179. | Role: multi-target attention-impossibility analyzer. Target: server. Interface: `Analyzer`. |
| `server/telemetry/src/analyzers/recoil_rng_corr.rs` | Signal 180. | Role: recoil/spread-RNG compensation under zero-feedback analyzer. Target: server. Interface: `Analyzer`. |
| `bypass-tests/server/gamestate_replay.rs` | Merge-gate bypass test (guardrail #12): synthetic snapshot streams that encode each cheat behavior; asserts each analyzer scores it, and that clean-but-adversarial decoys (pre-fire, sound-cue, lag-comp edge) do NOT trip. | Role: bypass/FP-resistance test harness for the game-state-knowledge analyzers. Target: server. Interface: drives `analyzers/*` against fixture snapshots. |

---

## Interfaces & data structures

### Snapshot wire frame (game-server → telemetry IPC)

The game server publishes fixed-size C-ABI frames into the shared ring. This is a **third wire plane**, distinct from both `event_schema.h` (kernel events) and `TickPayload` (HTTP client telemetry). It is authored as a C99 header so a non-Rust game server can produce it, mirrored by a `#[repr(C)]` Rust struct with `HK_STATIC_ASSERT`-equivalent compile-time size checks.

New header `sdk/include/horkos/snapshot_schema.h` (module comment: role = authoritative game-state snapshot IPC contract; target = server-side IPC; interface declared here, mirrored in `snapshot/ipc.rs`):

```c
#define HK_SNAPSHOT_SCHEMA_VERSION 1u
#define HK_SNAP_MAX_ENTITIES 256u

typedef struct HkVec3 { float x, y, z; } HkVec3;          /* 12 bytes */

typedef struct HkEntityState {        /* one actor this tick */
    uint64_t entity_id;
    HkVec3   position;                /* authoritative */
    HkVec3   velocity;
    uint32_t flags;                   /* HK_ENT_ALIVE | HK_ENT_LOCAL ... */
    uint32_t _pad;
} HkEntityState;                       /* 48 bytes */

typedef struct HkSnapshotRecord {
    uint32_t schema_version;          /* == HK_SNAPSHOT_SCHEMA_VERSION */
    uint32_t entity_count;
    uint64_t tick;
    uint64_t mono_ns;                 /* clock_gettime(CLOCK_MONOTONIC) at sim */
    uint64_t local_player_id;
    HkVec3   cam_origin;              /* view-frustum reconstruction (173,177) */
    HkVec3   cam_forward;
    HkVec3   cam_up;
    float    cam_fov_rad;
    uint32_t visibility_bits[HK_SNAP_MAX_ENTITIES / 32];  /* per-entity server PVS/BVH LoS to local */
    uint32_t audiopath_bits[HK_SNAP_MAX_ENTITIES / 32];   /* per-entity authoritative audio path exists */
    uint32_t occluder_count;          /* dynamic smoke/particle volumes (175) */
    HkVec3   recoil_rng_vec;          /* per-shot authoritative recoil incl. random component (180) */
    uint64_t objective_seed;          /* server-random spawn/objective seed (176) */
    HkEntityState entities[HK_SNAP_MAX_ENTITIES];
} HkSnapshotRecord;

HK_STATIC_ASSERT(sizeof(HkVec3) == 12, hkvec3_size);
HK_STATIC_ASSERT(sizeof(HkEntityState) == 48, hkentity_size);
/* full-record assert pinned once layout is frozen during impl */
```

Dynamic occluder volumes (175) are a variable-length trailer addressed by `occluder_count` (a parallel `HkOccluderVolume[]` ring, AABB + lifetime), kept out of the fixed head to bound frame size. Detailed at impl time.

Rust mirror in `snapshot/ipc.rs`:

```rust
#[repr(C)]
struct HkSnapshotRecord { /* field-for-field */ }
const _: () = assert!(core::mem::size_of::<HkVec3>() == 12);
const _: () = assert!(core::mem::size_of::<HkEntityState>() == 48);
```

### `TickPayload` additions (`server/telemetry/src/schema.rs`) — bump `SCHEMA_VERSION` 1 → 2

The analyzers integrate client-reported aim (`aim_delta_x/y` already present) against authoritative positions. To bind a client tick to the correct authoritative snapshot and to feed signals 174/178, three additive fields (guardrail: additive only, no renames, deprecated stays reserved):

```rust
/// Client-reported monotonic ns at frame render (178 aliasing input; never trusted as truth).
#[serde(default)] pub client_mono_ns: u64,
/// Client-reported display refresh rate (Hz) — harmonic-exclusion gate for 178.
#[serde(default)] pub client_refresh_hz: u16,
/// Client-reported shot-fired flag this tick (174/177/180 shot-registration alignment, cross-checked vs server hit-reg).
#[serde(default)] pub fired: bool,
```

**Guardrail #11:** each of `client_mono_ns`, `client_refresh_hz`, `fired` is a new telemetry field → `server/api/data-categories.md` §3 (Telemetry stream) gets a row per field **in the same PR**, with source = client, retention = "session lifetime + 30 days", legal basis = Contract performance / Legitimate-interest (anti-cheat) for `fired`. The snapshot IPC plane is server-internal authoritative game state (not collected *from the data subject*); it still gets a **new §5 "Authoritative game-state snapshot (server-internal)"** category documenting `position/velocity/visibility/audio/recoil_rng/objective_seed`, retention tied to the suspicion-evidence window, legal basis Legitimate-interest — because a derived suspicion event persists. Reviewer rejects the PR if §5 is missing.

### `Analyzer` trait (`analyzers/mod.rs`)

```rust
pub trait Analyzer: Send {
    fn id(&self) -> SignalId;                 // 172..=180
    fn feed(&mut self, tick: &TickPayload, snap: &Snapshot) -> Result<(), TelemetryError>;
    fn score(&self) -> Option<SuspicionEvent>; // None until threshold + recurrence met
}
```

`SuspicionEvent { player_id, signal_id, zscore, sample_count, window_ticks }` is handed to `ban-engine` (server-side authority); analyzers never ban. No new IOCTL codes — this domain is server↔game-server IPC + HTTP, it never touches `sdk/include/horkos/ioctl.h` (the kernel-event IOCTL bridge).

---

## Mechanism implementation notes

Common server/tokio rules (guardrail #8): the shm reader does the only blocking syscalls and lives on a dedicated thread; analyzers run on the async runtime over a bounded `mpsc`. No `unwrap()` outside tests — ring-parse failures return `TelemetryError::InvalidPayload`; a torn/short frame is dropped and counted, never panics. All errors are `thiserror`.

- **172 occlusion_preaim:** per tick, reconstruct aim vector by integrating `aim_delta_*`; compute angular error to each entity's authoritative position; correlate error-collapse against the tick visibility bit flipping to visible. Tell = sub-degree error while `visibility_bits` says occluded. FP gate (`stats.rs`): require no `audiopath_bits` set for N prior ticks AND no prior LoS in the engagement AND population z-score over many engagements. Uses `geom::angular_error` + `geom::view_basis`.
- **173 vision_cone:** `geom::frustum_contains(cam_*, fov, target)` false AND `audiopath_bits` clear AND no teammate-LoS (team LoS derived from per-entity visibility of other locals) → measure reaction onset (`mono_ns` of corrective turn minus stimulus tick). Flag sub-visual-floor reactions. Accumulate over a session.
- **174 peek_latency:** pair mutual-LoS-onset tick with the `fired` shot tick; subtract per-connection RTT. RTT source is OS transport stats, isolated in `ipc/backends`: Linux `getsockopt(libc::SOL_TCP, libc::TCP_INFO)` reading `tcpi_rtt`/`tcpi_rttvar`; for UDP/QUIC, the engine ping EWMA delivered in the snapshot. Use **p95-high** RTT estimate (`stats::rtt_p95`) so jitter widens the budget — fire-before-budget is the tell. `clock_gettime(CLOCK_MONOTONIC)` via the snapshot `mono_ns`.
- **175 dynamic_occluder:** ray-test target visibility against the dynamic occluder AABB+lifetime trailer (`geom::ray_aabb`); compare intra-occluder vs pre/post tracking-error variance from integrated aim. FP gate: target must have changed velocity/direction inside the volume (so a memorized path can't explain the lock) AND no audio path; score variance-ratio across many smoke events.
- **176 positional_prior:** log authoritative position/velocity; compute path divergence vs the engine navmesh A* route to the *server-random* objective (gate on `objective_seed` randomness this match) plus heading-change entropy. Navmesh/A* is the game engine's — telemetry consumes a precomputed route or runs a local A* over a supplied navmesh blob (decision flagged below). Weak prior only; never standalone.
- **177 flick_precog:** at LoS-onset tick compare aim error to (a) target last-visible position vs (b) target live (occluded) position. Systematically smaller error to live = tell. Require the target to have MOVED while occluded across many engagements; population-normalize. Reuses 172's integrated aim + visibility transitions.
- **178 refresh_aliasing:** build the occluded-knowledge reaction-latency series, run FFT/autocorrelation (`stats::spectral`) for a dominant off-harmonic peak. Exclude harmonics of `client_refresh_hz`, the client tick, and the server tick. Require persistent high-SNR off-harmonic peak over a long window. Pure compute, no I/O.
- **179 attention_budget:** per sliding window, count distinct occluded actors that each independently triggered a correct reaction; subtract any actor a teammate had LoS on (callout-explainable) and any with an audio path; flag residual simultaneous-occluded count over the human attention budget, repeatedly.
- **180 recoil_rng_corr:** correlate integrated `aim_delta_*` counter-motion against the authoritative `recoil_rng_vec` during ticks with no LoS and no tracer visibility. Discriminator is correlation to the per-shot **random** component (unlearnable), not the mean pattern (`stats::corr_random_component`). Require statistical significance over many magazines.

No kernel/ES/IRQL surface here — this is entirely userspace server Rust + an IPC reader. No raw `_WIN32`/`__linux__`: the two `backends/` files are selected with `#[cfg(...)]` keyed to the `HK_PLATFORM_*` build features (guardrail #1).

---

## Build wiring

- `server/telemetry/Cargo.toml`: add deps — `libc` (TCP_INFO/shm on POSIX), `windows-sys` (file mapping, `#[cfg(windows)]` only), `rustfft` (signal 178), `ndarray` (already transitively via `ort`; reuse for vectorized geom/stats). All added to `[workspace.dependencies]` and referenced with `{ workspace = true }`.
- Cargo features on the telemetry crate:
  - `gamestate-analyzers` (**default ON** — server build): compiles `snapshot/`, `analyzers/`, `geom`, `stats`.
  - `gamestate-ipc-shm` (**default ON**): the live shm reader. Off → analyzers run only from fixture/replay files (used by tests and offline backtests), so CI builds without a game-server peer.
- Platform backend selection by target `cfg`, gated through the workspace's `HK_PLATFORM_*` feature mapping; no `ort`/CUDA changes (CPU-only per locked decision; ML scoring of these features is a later phase — Phase-2/3 ships the deterministic statistical gates).
- No CMake/WDK/clang-19/libbpf/Xcode involvement — server-only domain, builds with stable Rust `1.95` per workspace.

---

## Test strategy

Unit (per analyzer, `#[cfg(test)]` + `stats`/`geom` table tests):
- `geom`: ray-AABB hit/miss, frustum containment edge (target exactly on FOV boundary), angular-error sign.
- `stats`: z-score against a known baseline, p95 estimator monotonicity, FFT peak detection on a synthetic periodic series, correlation isolating the random vs mean recoil component.
- Each analyzer: a "cheat" fixture snapshot scores; a matched "clean" fixture does not.
- Schema: `SCHEMA_VERSION` bumped to 2, round-trip of new fields, old payload (no new fields) still deserializes via `#[serde(default)]` — extend `server/telemetry/tests/ingest.rs`.

Bypass tests (guardrail #12 — **merge gate**, `bypass-tests/server/gamestate_replay.rs`), each named and asserting the analyzer is not defeated by the documented evasion:
- `preaim_through_wall_detected` — wallhack pre-aim on a fully occluded mover trips 172/177; **and** `preaim_prefire_common_angle_clean` — legit pre-fire on a learned angle with no live-position correlation does NOT trip.
- `offfrustum_reaction_detected` (173) vs `offfrustum_with_audio_path_clean` and `offfrustum_with_teammate_los_clean`.
- `subbudget_peek_detected` (174) vs `peek_within_jitter_p95_clean` (bursty jitter must not create a false sub-budget).
- `smoke_track_locked_detected` (175) vs `smoke_prefire_known_path_clean` (target did not change direction in smoke).
- `beeline_to_random_objective_detected` (176) vs `beeline_to_fixed_meta_spawn_clean` (non-random objective that match → must not trip).
- `offharmonic_refresh_peak_detected` (178) vs `monitor_refresh_harmonic_clean` (peak at client refresh harmonic excluded).
- `multi_occluded_attention_detected` (179) vs `multi_callout_explained_clean`.
- `recoil_random_component_correlated_detected` (180) vs `recoil_mean_pattern_only_clean` (skilled player matching the learnable mean must not trip).
- `torn_snapshot_frame_no_panic` — a short/garbage shm frame returns `InvalidPayload`, never panics (guardrail #8 fail-closed-but-safe).

Ships disabled-by-default like existing bypass tests (`HK_GAMESTATE_TEST_ENABLED` cfg) where they need the shm peer; the fixture-driven ones run in normal CI via `gamestate-ipc-shm` off.

---

## Sequencing

1. **`snapshot_schema.h` + `snapshot/ipc.rs` mirror + size asserts** — freeze the wire frame first; everything depends on it. Land the `repr(C)` + `const _: () = assert!` checks before any analyzer.
2. **`geom.rs` + `stats.rs`** — pure, fully unit-testable; no IPC. Land with their table tests.
3. **`snapshot/mod.rs` replay model + fixture loader** (file-backed, no live shm) — unblocks all analyzers and the bypass harness without a game-server peer.
4. **`analyzers/mod.rs` trait + registry**, wired into `telemetry/src/lib.rs` (replace the Phase-2 log-only stub path additively; HTTP ingest still 202s).
5. **Analyzers in dependency order:** 172 (occlusion baseline) → 177 (reuses 172's aim+visibility) → 173, 179 (frustum/audio/team-LoS share helpers) → 175 (occluder trailer) → 174 (needs RTT backend) → 180 (needs recoil_rng) → 176 (needs navmesh route) → 178 (needs the latency series the others populate; lands last).
6. **`snapshot/backends/{posix,win}.rs` live shm + TCP_INFO** — last, behind `gamestate-ipc-shm`; bypass tests for the shm path enable here.
7. **`data-categories.md` §3 rows + new §5** land in the **same PR** as the `schema.rs` field additions (#1 above touches no telemetry field; the field PR is step 4/5).

---

## Risks & UNCERTAINTY FLAGS

- **UNCERTAIN — game-server IPC contract is not yet specified.** The entire domain assumes the game server exposes its authoritative snapshot ring (positions, server PVS/BVH visibility results, audio-path graph, dynamic occluder volumes, per-shot recoil RNG, objective seed) over shared memory. Horkos does not own the game engine. Whether a given engine can or will publish *server-side visibility/audio/RNG* (vs. recomputing them in telemetry) is an integration decision per title. **Flag to user before implementing `snapshot_schema.h`:** is the frame produced by the engine, or must telemetry re-derive visibility from raw transforms + a supplied collision/navmesh blob? This changes signals 172/173/175/176/179 from "read a bit" to "run our own PVS/navmesh", a large scope swing.
- **UNCERTAIN — navmesh/A* ownership (176).** Catalog says "the engine's own navmesh." If telemetry must run A* itself it needs the navmesh blob and a pathfinder dependency; if the engine supplies the optimal route, 176 is cheap. Unresolved; flagged.
- **UNCERTAIN — UDP/QUIC RTT source (174).** `getsockopt(TCP_INFO)` only applies to TCP game sessions. Most competitive shooters are UDP/QUIC, where RTT must come from the engine ping EWMA inside the snapshot frame. If the engine does not expose a trustworthy per-client RTT, 174's budget is unmeasurable server-side. Confirm transport per title before relying on TCP_INFO.
- **FP severity (176 high, 172/173/175/177/179 medium):** per catalog, none of these may stand alone. The `Analyzer::score()` contract emits a `SuspicionEvent` with a z-score for fusion by `ban-engine`; **no single game-state signal should auto-ban.** This is a policy invariant, not just a tuning detail — encode it as a documented requirement on the ban-engine side.
- **Not a kernel/ES/signing risk:** this domain touches no kernel API, no EndpointSecurity, no code-signing surface, so guardrail #13's BSOD class does not apply. The hard risks are the IPC-contract and FP-policy items above.
- **shm trust boundary:** the game server and telemetry are separate processes; a compromised game-server process could feed forged snapshots. Out of scope for these analyzers (they trust the authoritative server by definition), but worth a note: the shm reader must bound-check `entity_count`/`occluder_count` against the schema maxima and reject overruns (`InvalidPayload`) — covered by `torn_snapshot_frame_no_panic`.
