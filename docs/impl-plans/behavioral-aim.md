# Implementation Plan — Server-Side: Aiming Behaviour (`behavioral-aim`)

Scope: read-only client sensors that quantify the **provenance and biomechanics**
of aim motion (raw-HID-to-render correlation, quantization residual, polling
cadence, flick/reaction/recoil/target-switch kinematics, cursor-confinement,
OS injection bit) and ship per-tick **features** to the server, which holds all
ban authority. No input injection, no foreign-process hooking, no view-angle
writes — the client only reads its own HID stream, its own view matrix, and the
engine's own target/occlusion/weapon state, then reports. All segmentation,
distribution-fitting, and verdicts are **server-side** (ban-engine + ort/ONNX).

Catalog signals covered: **163, 164, 165, 166, 167, 168, 169, 170, 171** (the
nine "Server-Side — Aiming Behaviour" designs in `docs/detection-catalog.md`,
lines 1699–1789).

Two cohorts:

- **Provenance/input sensors (163, 164, 165, 170, 171)** need a new SDK input
  backend under `sdk/src/input/` with per-platform implementations under
  `sdk/src/input/backends/<platform>/` (guardrail #1: platform API only in a
  `backends/` dir, `HK_PLATFORM_*`-gated, never raw `_WIN32`/`__linux__`/
  `__APPLE__`). They read OS HID/cursor/injection state. 170 is Windows+macOS;
  the rest are cross-platform with three backends each.
- **Kinematic/server signals (166, 167, 168, 169)** add **no new OS API** — the
  catalog marks them "feature transport." The client forwards view-vector
  kinematics and engine state (target list, occlusion/PVS, weapon/shot index)
  that the game already owns; the **ban-engine** does the segmentation and model
  scoring. These touch only `TickPayload` and `server/ban-engine`.

All nine land on the existing per-tick JSON plane (`TickPayload` in
`server/telemetry/src/schema.rs`) — the catalog's `Horkos slot` for every signal
names exactly that struct. Guardrail #4 (kernel/userspace TU split) is preserved:
none of these sensors run in the kernel and they share no TU with `kernel/`.

---

## 1. New files

| Path | Role | Module-comment summary |
|---|---|---|
| `sdk/src/input/AimSampler.h` | Internal façade declaring the aim-input sensor entry points + the shared per-tick aim-feature accumulator type. Platform-neutral declarations only. | Role: internal aim-input sensor interface (raw-HID provenance, quantization, polling jitter, cursor confinement, injection flag); declarations only. Target: all (declaration). Interface: implemented per-platform under `input/backends/<platform>/`; consumed by `sdk.cpp` AC tick; fills `hk_aim_features` mirrored by `server/telemetry/src/schema.rs::TickPayload`. |
| `sdk/src/input/AimAccumulator.cpp` | Platform-neutral fold of per-HID-report samples into the per-tick `hk_aim_features` block (counts, summed raw deltas, newest HID ts, inter-arrival moments, framelock count). No platform API. | Role: platform-neutral per-tick aim-feature accumulator; folds raw HID samples (delivered by the backends) into the fixed feature block. Target: all (no platform headers). Interface: implements `hk::sdk::aim::fold_tick` from `AimSampler.h`; kernel-free, shares no TU with `kernel/` (guardrail #4). |
| `sdk/src/input/backends/win/RawHidSamplerWin.cpp` | Signals 163/164/165: `WM_INPUT`/`RAWMOUSE` raw-count + QPC-timestamped report capture feeding the accumulator. | Role: Windows raw-HID aim sampler (RegisterRawInputDevices/GetRawInputData, RAWMOUSE.lLastX/lLastY, QueryPerformanceCounter). Target: Windows. Interface: implements `sample_raw_hid` from `AimSampler.h`. Catalog slots 163/164/165. Reads the game's own raw-input sink only. |
| `sdk/src/input/backends/win/CursorConfinementWin.cpp` | Signal 170: clip-rect / cursor-visibility / integrated-raw-vs-absolute consistency token. | Role: Windows cursor-confinement provenance sensor (GetClipCursor, GetCursorInfo CURSORINFO.flags, GetCursorPos, WM_ACTIVATE focus gating). Target: Windows. Interface: implements `sample_cursor_confinement`. Catalog slot 170. |
| `sdk/src/input/backends/win/InjectionFlagWin.cpp` | Signal 171: per-aim-event `LLMHF_INJECTED`/`LLMHF_LOWER_IL_INJECTED` fraction via the game's own `WH_MOUSE_LL`. | Role: Windows OS-injection-bit aim sensor (WH_MOUSE_LL, MSLLHOOKSTRUCT.flags). Target: Windows. Interface: implements `sample_injection_flag`. Catalog slot 171. Observes only the game's own input stream. |
| `sdk/src/input/backends/linux/RawHidSamplerLinux.cpp` | Signals 163/164/165 Linux: evdev `EV_REL` read() with `input_event.time` / `CLOCK_MONOTONIC_RAW`. | Role: Linux raw-HID aim sampler (evdev EV_REL REL_X/REL_Y, EVIOCGTIME, clock_gettime CLOCK_MONOTONIC_RAW). Target: Linux. Interface: implements `sample_raw_hid`. Catalog slots 163/164/165. Userspace evdev only — not the eBPF/LKM kernel plane. |
| `sdk/src/input/backends/linux/InjectionFlagLinux.cpp` | Signal 171 Linux: evdev device-provenance (real `/dev/input` node vs. `uinput`-created virtual via libudev `ID_INPUT`). | Role: Linux input-provenance sensor (libudev ID_INPUT, uinput virtual-device detection). Target: Linux. Interface: implements `sample_injection_flag` (virtual-device fraction analog). Catalog slot 171. |
| `sdk/src/input/backends/macos/RawHidSamplerMac.mm` | Signals 163/164/165 macOS: IOHIDManager value timestamps. | Role: macOS raw-HID aim sampler (IOHIDManager, IOHIDValueGetTimeStamp). Target: macOS. Interface: implements `sample_raw_hid`. Catalog slots 163/164/165. Userspace HID only; not the ES SystemExtension plane. |
| `sdk/src/input/backends/macos/CursorConfinementMac.mm` | Signal 170 macOS analog: synthetic-source flag on mouse events. | Role: macOS cursor/synthetic-source provenance sensor (CGEventTapCreate listen-only, kCGEventSourceStateID). Target: macOS. Interface: implements `sample_cursor_confinement`. Catalog slot 170. Listen-only tap; emits no events (no ES-style reply obligation — userspace CG, not EndpointSecurity). |
| `sdk/src/input/backends/macos/InjectionFlagMac.mm` | Signal 171 macOS: hardware-vs-synthesized source on aim events. | Role: macOS OS-injection-source aim sensor (CGEventGetIntegerValueField kCGMouseEventSubtype / kCGEventSourceStateID). Target: macOS. Interface: implements `sample_injection_flag`. Catalog slot 171. |
| `server/ban-engine/src/aim_kinematics.rs` | Server-side feature extractor + segmenters for 166/167/168/169 (flick curvature, reaction-floor CDF, recoil-residual, target-switch latency). Stub in Phase 2: typed feature structs + segmentation entry points, no model. | Role: aim-kinematics feature extractor; segments flick/reaction/recoil/target-switch events from the `TickPayload` stream and emits model features. Target: server. Interface: consumes `telemetry::schema::TickPayload`; feeds the ort/ONNX scoring path. No `unwrap()` outside tests (guardrail #8); `thiserror` errors. |
| `bypass-tests/win/aim_injection_provenance.cpp` | Bypass-test: a benign self-issued `SendInput`/`mouse_event` aim move (NULL-`hDevice`, `LLMHF_INJECTED` set) and a sub-count fractional view nudge must be **reported** by 163/164/171 — never silently dropped, never auto-banned client-side. | Role: aim-provenance merge-gate bypass test (disabled stub until enforcement TDD). Target: Windows. Interface: consumes the aim-feature schema. Guardrail #12. |
| `bypass-tests/win/aim_framelock_cadence.cpp` | Bypass-test: synthetic reports emitted on the render-frame cadence (frame-locked) must surface in the 165 inter-arrival framelock feature, while a real 1000 Hz cadence does not. | Role: polling-cadence merge-gate bypass test (disabled stub). Target: Windows. Interface: consumes the aim-feature schema. Guardrail #12. |

Module comment on every file above satisfies guardrail #3.

---

## 2. Interfaces & data structures

### 2.1 No new wire plane — extend `TickPayload`

Every catalog `Horkos slot` for 163–171 names
`server/telemetry/src/schema.rs (TickPayload: …)`. These are per-tick gameplay
features, not kernel ring records — they belong on the **existing JSON tick
plane**, not the C99 `event_schema.h`/IOCTL plane. So:

- **No `ioctl.h` changes.** No new `HK_IOCTL_*` code, no `HK_EVENT_*` type, no
  `hk_event_*` struct. These features never traverse `HK_IOCTL_DRAIN_EVENTS`;
  forcing per-tick aim kinematics through the 16-byte kernel payload would be
  wrong-plane (mirrors the decision in `win-input-automation.md` R1).
- **No `HK_STATIC_ASSERT` size pins** for the new fields: `TickPayload` is a
  serde JSON struct with no `#[repr(C)]` and no C byte-mirror (see its module
  comment, lines 1–14). It is **not** byte-compatible with any C struct, so
  there is no size invariant to assert. Sizing/`HK_STATIC_ASSERT` would only
  apply if these rode the kernel plane — they do not.
- **`SCHEMA_VERSION` bump:** `1 → 2`. New fields are additive with
  `#[serde(default)]` so older clients (omitting them) still deserialize.

### 2.2 SDK-side feature block: `sdk/src/input/AimSampler.h`

The SDK accumulator produces a plain C++ POD that `sdk.cpp` serializes into the
tick JSON. This is an **internal** SDK type (not a public wire header), so it
carries no `HK_STATIC_ASSERT` and no version constant of its own — the wire
version is `TickPayload::SCHEMA_VERSION`. Sketch:

```cpp
// sdk/src/input/AimSampler.h  (declarations only)
namespace hk { namespace sdk { namespace aim {

// Fixed per-tick aim-feature block. Serialized into the tick JSON by sdk.cpp.
// Fields map 1:1 to the new TickPayload members (§2.3). Provenance/quantization/
// cadence (163/164/165/170/171) are filled by the platform backends; the
// kinematic fields (166/167/168/169) are filled from the engine's own state the
// game already exposes (view matrix + target/occlusion/weapon lists) — no OS API.
struct hk_aim_features {
    // 163 raw HID -> render provenance
    uint32_t hid_report_count;        // HID reports consumed this tick
    int32_t  hid_raw_dx;              // summed raw integer HID counts, X
    int32_t  hid_raw_dy;              // summed raw integer HID counts, Y
    uint64_t hid_newest_ts_ns;       // newest HID hardware/QPC ts this tick
    // 164 quantization-floor
    uint32_t sens_scalar_q16;        // in-game DPI->angle sensitivity, Q16.16
    float    applied_angle_dx;       // actually-applied view delta, X (rad)
    float    applied_angle_dy;       // actually-applied view delta, Y (rad)
    // 165 polling-interval jitter
    uint64_t hid_interval_mean_ns;   // mean inter-report interval this tick
    uint64_t hid_interval_var_ns;    // variance of inter-report interval
    uint32_t hid_interval_framelock_count; // intervals == frame period
    // 166 flick curvature (engine-state transport)
    float    ang_vel;                // angular velocity of view vector (rad/s)
    float    ang_accel;              // angular acceleration (rad/s^2)
    float    ang_jerk;               // third-difference jerk (rad/s^3)
    float    dist_to_nearest_target_rad; // angular dist to nearest hitbox center
    // 167 reaction-latency floor
    uint64_t target_vis_onset_ts_ns; // occluded->visible onset ts (engine PVS)
    uint64_t first_impulse_ts_ns;    // first corrective impulse ts toward it
    uint64_t fire_ts_ns;             // fire-event ts toward it
    uint8_t  impulse_is_direction_change; // 1 = genuine new-direction impulse
    // 168 recoil phase-lock
    uint32_t weapon_id;              // engine weapon id
    uint32_t shot_index;             // shot index within current burst
    uint8_t  fire_active;            // full-auto fire-bit set this tick
    // 169 target-switch latency
    uint64_t aimed_target_id;        // id of currently-aimed-at target
    uint8_t  switch_event_flag;      // aim discretely re-locked this tick
    // candidate_target_offsets[] ships in the JSON envelope (variable length),
    // not in this fixed POD — see §2.3.
    // 170 cursor confinement (win/mac)
    uint8_t  clip_rect_ok;           // clip rect == game confinement rect
    uint8_t  cursor_hidden;          // CURSOR_SHOWING absent
    uint32_t raw_vs_abs_divergence_px; // |integrated raw - absolute cursor| px
    uint8_t  focus_active;           // WM_ACTIVATE focus held (alt-tab gate)
    // 171 OS injection bit
    uint16_t injected_event_fraction_q8; // frac of aim events flagged injected, Q0.8
    uint8_t  virtual_device_present; // virtual/uinput HID source seen this tick
};

bool sample_raw_hid(hk_aim_features* out);          // 163/164/165
bool sample_cursor_confinement(hk_aim_features* out); // 170 (win/mac)
bool sample_injection_flag(hk_aim_features* out);     // 171
void fold_tick(hk_aim_features* out);                 // AimAccumulator.cpp

} } } // namespace hk::sdk::aim
```

### 2.3 `TickPayload` additions: `server/telemetry/src/schema.rs`

`SCHEMA_VERSION` → `2`. All new fields `#[serde(default)]` (additive). The
variable-length `candidate_target_offsets` (169) rides as a `Vec<f32>` in the
JSON, not a fixed array — JSON has no fixed-array constraint and this is not a
byte-mirrored plane.

```rust
pub const SCHEMA_VERSION: u32 = 2; // was 1

// added to TickPayload, all #[serde(default)]:
//  163
pub hid_report_count: u32,
pub hid_raw_dx: i32,
pub hid_raw_dy: i32,
pub hid_newest_ts_ns: u64,
//  164
pub sens_scalar_q16: u32,
pub applied_angle_dx: f32,
pub applied_angle_dy: f32,
//  165
pub hid_interval_mean_ns: u64,
pub hid_interval_var_ns: u64,
pub hid_interval_framelock_count: u32,
//  166
pub ang_vel: f32,
pub ang_accel: f32,
pub ang_jerk: f32,
pub dist_to_nearest_target_rad: f32,
//  167
pub target_vis_onset_ts_ns: u64,
pub first_impulse_ts_ns: u64,
pub fire_ts_ns: u64,
pub impulse_is_direction_change: bool,
//  168
pub weapon_id: u32,
pub shot_index: u32,
pub fire_active: bool,
//  169
pub aimed_target_id: u64,
#[serde(default)] pub candidate_target_offsets: Vec<f32>,
pub switch_event_flag: bool,
//  170
pub clip_rect_ok: bool,
pub cursor_hidden: bool,
pub raw_vs_abs_divergence_px: u32,
pub focus_active: bool,
//  171
pub injected_event_fraction_q8: u16,
pub virtual_device_present: bool,
```

The existing `ingest` handler already rejects `schema_version != SCHEMA_VERSION`;
bumping the const makes v1 clients fail the check, so the same PR must either
keep accepting `1` (relax the check to `<= SCHEMA_VERSION` with the extra fields
defaulted) **or** bump clients in lockstep. Default plan: accept both `1` and
`2` for the migration window (the extra fields default to zero when absent),
documented in the handler.

### 2.4 `data-categories.md` additions (guardrail #11 — same PR)

Every new field above is telemetry and must be declared in
`server/api/data-categories.md` **section 3 (Telemetry stream)** in the same PR,
or the reviewer rejects it. Add rows (retention/legal-basis matching the
existing tick rows: `session lifetime + 30 days`, `Contract performance`):

| Field group | Source | Notes |
|---|---|---|
| `hid_report_count`, `hid_raw_dx`, `hid_raw_dy`, `hid_newest_ts_ns` | raw-HID sampler (RAWMOUSE / evdev / IOHIDManager) | raw integer mouse counts + newest hardware timestamp; **not** keystrokes/text |
| `sens_scalar_q16`, `applied_angle_dx`, `applied_angle_dy` | engine sensitivity + applied view delta | quantization-residual inputs |
| `hid_interval_mean_ns`, `hid_interval_var_ns`, `hid_interval_framelock_count` | inter-report timing | cadence moments only, not input content |
| `ang_vel`, `ang_accel`, `ang_jerk`, `dist_to_nearest_target_rad` | view matrix + engine target list | flick kinematics (166) |
| `target_vis_onset_ts_ns`, `first_impulse_ts_ns`, `fire_ts_ns`, `impulse_is_direction_change` | engine occlusion/PVS + view + fire | reaction-floor timing (167) |
| `weapon_id`, `shot_index`, `fire_active` | engine weapon state | recoil-residual (168) |
| `aimed_target_id`, `candidate_target_offsets`, `switch_event_flag` | engine target list + view | target-switch (169) |
| `clip_rect_ok`, `cursor_hidden`, `raw_vs_abs_divergence_px`, `focus_active` | GetClipCursor/GetCursorInfo/GetCursorPos (Win), CGEventTap (mac) | cursor-confinement provenance (170) |
| `injected_event_fraction_q8`, `virtual_device_present` | LLMHF_INJECTED (Win) / uinput-libudev (Linux) / kCGEventSourceStateID (mac) | OS injection-bit fraction (171) |

Note for the reviewer: the HID counts and timestamps are aim/pointer motion
metadata and weapon/target gameplay state — **never keystroke content, never
typed text**. `candidate_target_offsets` is angular geometry the game already
computes client-side, not new surveillance.

### 2.5 Server-side feature structs: `server/ban-engine/src/aim_kinematics.rs`

166/167/168/169 are segmented and scored in the ban-engine, not the client.
Phase-2 stub defines the typed feature outputs + segmentation entry points (no
ort session yet, mirroring how `telemetry::ort_linked_marker` keeps `ort` wired
without loading a model):

```rust
pub struct FlickFeatures { pub overshoot_ratio: f32, pub settle_ms: f32, pub jerk_min: f32 }
pub struct ReactionFeatures { pub rt_ms: f32, pub is_direction_change: bool }
pub struct RecoilResidual { pub resid_var: f32, pub xcorr_lag_ms: f32 }
pub struct SwitchFeatures { pub switch_latency_ms: f32, pub transit_straightness: f32, pub ang_sep_rad: f32 }

// segmenters consume a window of TickPayload; recoil needs signed weapon rules
// (the ban-engine already plumbs signed bundles via bundle.rs).
pub fn segment_flicks(ticks: &[TickPayload]) -> Vec<FlickFeatures> { /* … */ }
```

The recoil-residual model (168) needs the **signed weapon recoil curve** — that
rides the existing signed-rule plumbing (`server/ban-engine/src/bundle.rs`); no
new transport.

---

## 3. Mechanism implementation notes

All client sensors are **read-only**: they consume the game's own raw-input sink,
the game's own LL-hook, and engine state the game already computes; they never
inject, never write view angles, never hook another process. They run on the SDK
AC tick thread / the game's input thread — **not in the kernel**, so no
IRQL/IRP/`ObRegisterCallbacks` concerns apply, and the eBPF/LKM/ES kernel planes
are untouched (the Linux evdev and macOS IOKit/CG paths here are **userspace**).
Every OS-call failure path is handled; a sensor that cannot resolve a value
leaves the feature at its zero/default and the server simply gets no signal —
never a fabricated anomaly.

**163 — Raw HID-to-render provenance delta.** Per HID report, capture the raw
integer count and a hardware/high-res timestamp, and per tick emit
`hid_report_count`, summed `hid_raw_dx/dy`, and `hid_newest_ts_ns` alongside the
applied angle delta. Windows: `RegisterRawInputDevices` (the game's own
`RIDEV_INPUTSINK` sink) + `GetRawInputData` reading `RAWMOUSE.lLastX/lLastY`,
stamped with `QueryPerformanceCounter`. Linux: `read()` on the evdev node for
`EV_REL`/`REL_X`/`REL_Y`, timestamp from `input_event.time` (or `EVIOCGTIME`).
macOS: `IOHIDManager` value callbacks, `IOHIDValueGetTimeStamp`. The server
compares whether each applied aim_delta is backed by an upstream report whose ts
precedes the render tick. *FP gate (server-side):* virtual-HID provenance
(reWASD, Steam Input, Razer Synapse, accessibility head-trackers) is a separate
cohort, not a flag — the client only reports counts/timestamps, the server
decides. *Concern:* the `WM_INPUT` handler must size the buffer correctly (call
`GetRawInputData` once for size, once for data) and do O(1) work on the input
thread; never block it.

**164 — Sub-count residual / quantization-floor.** Carry the raw integer HID
count (`hid_raw_dx/dy`), the active in-game sensitivity/DPI scalar
(`sens_scalar_q16`, Q16.16), and the actually-applied angle delta
(`applied_angle_dx/dy`). The server reconstructs `expected = raw_count * scalar`
and reports the residual; persistent non-zero residual = motion not sourced from
integer counts. *Client sampling of OS accel state for the server's FP gate:*
read `SystemParametersInfo(SPI_GETMOUSE / SPI_GETMOUSESPEED)` (Windows Enhance
Pointer Precision) so the server can subtract declared smoothing before judging
the lattice violation — fold the accel state into an existing field or a small
side field if needed (declare it if added). The client never thresholds the
residual.

**165 — Polling-interval jitter spectrum.** Timestamp each report with
`QueryPerformanceCounter` (Win) / `clock_gettime(CLOCK_MONOTONIC_RAW)` (Linux) /
IOHID timestamp (mac); per tick emit compact moments —
`hid_interval_mean_ns`, `hid_interval_var_ns`, and
`hid_interval_framelock_count` (count of intervals equal to the render-frame
period). The server builds the polling-rate spectrum and looks for frame-locked
or timer-quantized cadence. *FP gate (server-side):* compare against the
**attested device's** nominal rate (HID descriptor / USB `bInterval`), not a
global prior — wireless power-save batching, hubs, and v-sync coalescing
legitimately alter cadence. The framelock comparison needs the current frame
period from the engine; the client supplies it, the server keeps the device
nominal-rate prior.

**166 — Flick onset-to-target curvature.** **No OS API** — pure engine-state
transport. Per tick emit angular velocity/acceleration/jerk (`ang_vel`,
`ang_accel`, `ang_jerk`; jerk = third difference of the view vector) and
`dist_to_nearest_target_rad` (from the game's own client-authoritative target
list). The **ban-engine** (`aim_kinematics.rs`) segments flick events and fits
the velocity profile (overshoot ratio, settle-time, jerk minima) against a
human-floor model in the ort/ONNX path. *FP gate:* high-skill/low-sens players
and aim-assist controllers produce smooth low-jerk arcs — this is a
**population-distribution** signal per `player_id`, never a per-event flag, and
requires corroboration from a provenance signal before any enforcement weight.
The client must not compute the verdict; it ships the kinematics.

**167 — Reaction-latency floor vs. visibility-onset.** **No new OS API** —
engine occlusion/PVS transport. Per tick carry the occluded→visible onset
timestamp for each newly-visible target (`target_vis_onset_ts_ns`, from the
engine's own occlusion/PVS query), the first corrective-impulse ts
(`first_impulse_ts_ns`), the fire ts (`fire_ts_ns`), all `QueryPerformanceCounter`
/ `CLOCK_MONOTONIC_RAW` stamped, plus `impulse_is_direction_change`. The server
computes the per-player reaction-time CDF and tests the left tail against the
~150–250 ms human floor. *FP gate (server-side):* pre-aiming/prediction produces
legitimately sub-floor apparent reactions — require the impulse to be a genuine
direction **change** toward a newly-visible target (`impulse_is_direction_change`),
model the full CDF, corroborate with provenance.

**168 — Recoil-compensation phase-lock residual.** **No new OS API** — engine
weapon-state transport. During full-auto fire (`fire_active`), emit per-tick the
applied aim delta (`applied_angle_dx/dy`, shared with 164) and `weapon_id` /
`shot_index`. The server knows the weapon's recoil curve from **signed rule
data** (existing `bundle.rs` plumbing), computes `residual = applied_delta -
(-recoil_step)`, and tracks residual variance and cross-correlation lag. *FP
gate (server-side):* drilled players reach low variance — require phase-lag at or
below human reaction latency (a script can be zero-lag, a human cannot) and
compare against the player's own learning curve over time, not a fixed
threshold.

**169 — Target-switch latency vs. saccade floor.** **No new OS API** — engine
target-list transport. Per tick carry `aimed_target_id`, the candidate set
`candidate_target_offsets[]` (angular offsets), and `switch_event_flag`. The
server detects switch events (aim discretely re-locks onto a different enemy),
measures switch latency and transit straightness, tests against a saccade
floor. *FP gate (server-side):* spray-transfer between close enemies is a real
skill — only score switches across **large angular gaps** where saccade latency
is unavoidable; distributional, never per-event; corroborate with provenance +
reaction floor.

**170 — Cursor-confinement / clip-rect provenance (Windows + macOS).** Windows:
periodically sample `GetClipCursor` (clip rect still == the game's confinement
rect → `clip_rect_ok`), `GetCursorInfo`/`CURSORINFO.flags` (`CURSOR_SHOWING`
absent → `cursor_hidden`), and `GetCursorPos` to compute
`raw_vs_abs_divergence_px` (integrated raw motion vs. absolute cursor position —
the load-bearing signal). macOS analog: `CGEventTapCreate` **listen-only** tap
checking the synthetic-source flag (`kCGEventSourceStateID`) on mouse events.
*FP gate:* correlate clip/cursor disturbances with `focus_active` (Windows
`WM_ACTIVATE` focus loss) so benign alt-tabs / Magnifier / overlay launchers
(Discord, Steam) are excused. *Concern (macOS):* the CGEventTap is **listen-only
and passive** — it does not modify or drop events, so there is **no
EndpointSecurity-style auth reply obligation** (guardrail #7 governs the ES
SystemExtension, not a CG event tap); this sensor lives in the userspace SDK,
not the ES plane. *Concern:* a passive CGEventTap still requires the
Accessibility/Input-Monitoring TCC permission — handle the not-granted case by
leaving 170 features at default, never crash.

**171 — Aim-input source-state synthetic flag.** Windows: the game's own
`WH_MOUSE_LL` reads `MSLLHOOKSTRUCT.flags` (`LLMHF_INJECTED` /
`LLMHF_LOWER_IL_INJECTED`) per aim-moving event; emit the injected fraction
`injected_event_fraction_q8` (Q0.8). macOS:
`CGEventGetIntegerValueField(kCGMouseEventSubtype)` / `kCGEventSourceStateID`
distinguishes hardware vs. synthesized. Linux: evdev provenance — real
`/dev/input` node vs. `uinput`-created virtual device via libudev `ID_INPUT`
properties → `virtual_device_present`. *FP gate (server-side):* remappers,
on-screen keyboards, KVM/streaming (Parsec, Steam Remote Play), Steam Input all
set the injected/virtual flag — this **segregates cohorts, it does not convict**;
the client ships the fraction graded, never auto-bans on the bit. *Concern
(Windows):* the `WH_MOUSE_LL` callback runs under the system
`LowLevelHooksTimeout` and must do strictly O(1) work and `CallNextHookEx`
promptly or Windows silently removes the hook (**flagged R3**).

**Server (`aim_kinematics.rs`, `telemetry` ingest).** Fully async on tokio; no
blocking calls on async threads; `thiserror` error types; no `unwrap()`/`expect()`
outside `#[cfg(test)]` (guardrail #8). Phase-2 ingest keeps the
validate→log→drop stub; the kinematic segmenters are pure functions over a
`&[TickPayload]` window so they unit-test on the host without a model.

---

## 4. Build wiring

- **SDK input sensors** compile into the existing `hk_sdk` static lib
  (`sdk/CMakeLists.txt`). Add the platform-neutral core unconditionally and a
  per-platform backend selected the same way `hk_sdk_backend` already selects
  `DriverProbe*`:

  ```cmake
  option(HK_AIM_SENSORS "Build aim-input provenance/biomechanics sensors" ON)
  if(HK_AIM_SENSORS)
      list(APPEND HK_SDK_SOURCES
          src/input/AimAccumulator.cpp)
      if(WIN32)
          list(APPEND HK_SDK_SOURCES
              src/input/backends/win/RawHidSamplerWin.cpp
              src/input/backends/win/CursorConfinementWin.cpp
              src/input/backends/win/InjectionFlagWin.cpp)
          # Win32 link deps confined to this branch:
          #   user32 (RegisterRawInputDevices/GetRawInputData/SetWindowsHookEx/
          #           GetClipCursor/GetCursorInfo/GetCursorPos/SystemParametersInfo)
      elseif(APPLE)
          list(APPEND HK_SDK_SOURCES
              src/input/backends/macos/RawHidSamplerMac.mm
              src/input/backends/macos/CursorConfinementMac.mm
              src/input/backends/macos/InjectionFlagMac.mm)
          # frameworks: IOKit (IOHIDManager), CoreGraphics (CGEventTap),
          #             CoreFoundation
      else() # Linux
          list(APPEND HK_SDK_SOURCES
              src/input/backends/linux/RawHidSamplerLinux.cpp
              src/input/backends/linux/InjectionFlagLinux.cpp)
          # link: libudev (ID_INPUT provenance). evdev is read() on /dev/input,
          #       no extra lib. CLOCK_MONOTONIC_RAW via clock_gettime (librt/libc).
      endif()
  endif()
  ```

  `target_compile_definitions(hk_sdk PRIVATE HK_PLATFORM_WINDOWS|LINUX|MACOS)`
  already governs the conditional code; sources use the `HK_PLATFORM_*` macros,
  never raw `_WIN32`/`__linux__`/`__APPLE__` (guardrail #1). Default **ON** —
  these are core product sensors. macOS files are `.mm` (Obj-C++ for IOKit/CG).

- **Toolchain:** Windows = MSVC + Windows SDK (**no WDK** — usermode only, no
  driver, no test-signing). macOS = Xcode/clang, IOKit + CoreGraphics frameworks,
  **no entitlement** needed for a passive CGEventTap / IOHIDManager beyond the
  TCC Input-Monitoring/Accessibility grant (not an Apple-approved entitlement
  like the ES SystemExtension). Linux = clang/gcc + `libudev` (`libudev-dev`);
  evdev needs the user in the `input` group or appropriate access — **userspace,
  not the eBPF `-Wall -Wextra -Werror` kernel build** (guardrail #6 applies to
  `kernel/linux/`, not these SDK files).

- **Server:** add `pub mod aim_kinematics;` to `server/ban-engine/src/lib.rs`.
  Bump `telemetry::schema::SCHEMA_VERSION` to `2` and add the fields. No new
  crate, no new Cargo deps (reuses `axum`, `serde`, `thiserror`, `tracing`,
  `ort`). Extend `TelemetryError` only if a new validation case is needed.

- **Bypass tests:** add the two new executables to `bypass-tests/win/CMakeLists.txt`
  alongside `byovd_load`, disabled-by-default (activation flag
  `HK_AIM_BYPASS_ENABLED`, mirroring `HK_BYOVD_TEST_ENABLED`).

---

## 5. Test strategy

### Unit / integration

- **Quantization residual (164)** — pure, host-runnable: feed `(raw_count,
  sens_scalar_q16, applied_angle)` triples and assert the server-side
  reconstruction `expected = raw_count * scalar` and residual are computed
  deterministically; assert a sub-count fractional nudge yields a non-zero
  residual and an exact integer-count motion yields ~zero. Highest-value unit.
- **Polling moments (165)** — feed synthetic inter-arrival sequences (true 1000 Hz
  jitter, fixed-period frame-locked, timer-quantized) and assert
  `hid_interval_mean_ns`/`var_ns`/`framelock_count`; assert framelock_count fires
  only when intervals equal the supplied frame period.
- **Flick segmentation (166)** — `aim_kinematics::segment_flicks` over a window of
  synthetic `TickPayload`s: a ballistic-then-corrective profile yields a flick
  with overshoot+settle; a monotone point-to-point profile yields the
  low-jerk/zero-overshoot signature. Pure function, no model.
- **Reaction CDF left-tail (167)** — feed visibility-onset/impulse timestamp
  pairs; assert the reaction-time computation and that
  `impulse_is_direction_change == false` (continuation of prior tracking) is
  excluded from the CDF (guards the pre-aim FP).
- **Recoil residual (168)** — given a signed weapon recoil curve and an applied
  motion stream, assert `residual` and the cross-correlation lag; assert a
  zero-lag perfect-inverse stream produces near-zero residual variance and a
  noisy human-like stream does not.
- **Target-switch (169)** — given candidate offsets and an aim re-lock, assert
  switch detection, latency, and that small-angular-gap transfers are **not**
  scored (only large-gap switches).
- **Cursor divergence (170)** — given integrated-raw vs. absolute-cursor inputs
  and a `focus_active` flag, assert `raw_vs_abs_divergence_px` and that a
  focus-loss (alt-tab) window suppresses the disturbance.
- **Injection fraction (171)** — given a sequence of aim events with/without the
  injected flag, assert `injected_event_fraction_q8` (Q0.8) and that
  `virtual_device_present` reflects a simulated uinput/virtual source.
- **Serde round-trip + version** — a `#[test]` asserting the extended
  `TickPayload` round-trips, that a v1 payload (omitting the new fields)
  deserializes with defaults, and that `SCHEMA_VERSION == 2`. (No
  `HK_STATIC_ASSERT` — this plane has no C byte-mirror; §2.1.)
- **Server route** — extend `server/telemetry/tests/`: a v2 `TickPayload` →
  `202`; a v1 payload still `202` during the migration window; an unknown version
  → `400` via `TelemetryError`.

### Bypass tests (guardrail #12 — merge gate)

Any change under a security folder (`sdk/src/input/`) needs a corresponding
bypass test. Two added, both **disabled stubs** in this scaffolding phase (logic
lands under `/tdd`, guardrail #14) — compile now, print `DISABLED`, return 0,
exactly like `byovd_load.cpp`:

- **`aim_injection_provenance`** — must demonstrate: a benign self-issued
  `SendInput`/`mouse_event` aim move (NULL-`hDevice`, `LLMHF_INJECTED` set) is
  **reported** by signals 163 (no backing HID report / post-dated ts) and 171
  (`injected_event_fraction_q8 > 0`), and a sub-count fractional view nudge is
  **reported** by 164 (non-zero quantization residual) — none of them
  auto-banned client-side (proves the report-only contract: synthetic/fractional
  motion ≠ ban; the server decides). Must also demonstrate that a virtual-HID
  source (simulated remapper/Steam-Input) is reported as a **cohort flag**
  (`virtual_device_present`), not a raw conviction (the FP-gating contract).
  Activation flag `HK_AIM_BYPASS_ENABLED`.
- **`aim_framelock_cadence`** — must demonstrate: reports emitted on the
  render-frame cadence (frame-locked synthetic input) surface in signal 165 with
  `hid_interval_framelock_count > 0`, while a real 1000 Hz cadence with bounded
  jitter yields `framelock_count == 0` against the same frame period (proves the
  cadence feature distinguishes timer-locked injection from real polling without
  a client-side verdict).

Both compile now and print `DISABLED` until the enforcement/scoring path lands.

---

## 6. Sequencing

1. **`TickPayload` v2 + `data-categories.md` section 3 rows + serde/version
   tests.** Land the contract first (bump `SCHEMA_VERSION`, add fields with
   `#[serde(default)]`, relax the ingest version check to accept `1` and `2`).
   Nothing else compiles/serializes against a moving schema. Guardrail #11
   satisfied in this same step.
2. **`AimSampler.h` + `AimAccumulator.cpp`** — the platform-neutral feature
   block + per-tick fold the backends depend on; unit-test the fold (counts,
   moments) before the platform backends.
3. **163 + 164 + 165 raw-HID backends (Win first, then Linux, then macOS)** —
   highest-confidence provenance signals; share the raw-HID sampler. Land the
   Windows `RawHidSamplerWin.cpp` with the `aim_injection_provenance` and
   `aim_framelock_cadence` bypass-test stubs.
4. **171 injection-flag backends** — share the game's own `WH_MOUSE_LL` (Win) /
   CG source field (mac) / libudev provenance (Linux). Land after the LL-hook
   timeout concern (R3) is confirmed for Windows.
5. **170 cursor-confinement (Win + macOS only)** — independent of the raw-HID
   inventory; Windows clip/cursor reads + macOS listen-only CGEventTap. Confirm
   the macOS TCC-permission path (R5) before the `.mm` backend.
6. **166/167/168/169 kinematic transport + `aim_kinematics.rs` segmenters** —
   client side is pure engine-state forwarding into `TickPayload` (no OS API);
   the ban-engine segmenters are pure functions, unit-tested on the host. Land
   last among signals because the model that consumes them is later work, and
   168 depends on the signed weapon-rule plumbing (`bundle.rs`).
7. **CMake wiring + bypass-test CMake + `ban-engine` module export.** Wire the
   `HK_AIM_SENSORS` option, the per-platform backend lists, the two bypass
   executables, and `pub mod aim_kinematics;`. Run the full suite.

Per-signal logic that makes a **decision** (segmentation thresholds, human-floor
models, distribution fits, recoil curves, signer/cohort allow-lists) is deferred
to the server (ort/ONNX + signed rules) and to `/tdd` phases (guardrail #14) —
this plan scaffolds read-only sensors + the feature contract, not the verdict
engine. The kinematic signals (166/167/168/169) **must not** acquire client-side
thresholds at any point (catalog mandate: population/distributional, server-side).

---

## 7. Risks & uncertainty flags

- **R1 — plane choice (resolved by design, flag for reviewer).** All nine ride
  the existing per-tick JSON `TickPayload`, **not** the C99 `event_schema.h`/
  IOCTL kernel plane (every catalog `Horkos slot` names `TickPayload`). No
  `ioctl.h`/`event_schema.h` change, no new `HK_IOCTL_*`/`HK_EVENT_*`, and
  **no `HK_STATIC_ASSERT` size pin** — `TickPayload` is a serde JSON struct with
  no `#[repr(C)]` C byte-mirror, so no size invariant exists to assert (its own
  module comment states this). Reviewer should confirm the single-plane decision
  rather than expecting an IOCTL/size-assert extension.

- **R2 — kinematic signals are fundamentally server-side (166/167/168/169 and
  the timing parts of 163/165).** High-skill/low-sens players, aim-assist
  controllers, pre-aiming/prediction, drilled recoil control, and spray-transfer
  all mimic the bot signature at the event level. The client must ship **raw
  features only**; any client-side thresholding will false-positive on skilled
  and assisted players. Explicitly out of scope for the client and flagged so it
  is not "optimized" into the sensor later (catalog-mandated population-model
  framing; these need corroboration from a provenance signal before enforcement
  weight).

- **R3 — UNCERTAINTY: `WH_MOUSE_LL` callback timeout (171 Windows).** A
  `WH_MOUSE_LL` hook callback runs under the system `LowLevelHooksTimeout`
  (`HKLM\Control Panel\Desktop`, commonly cited ~300 ms) after which Windows
  silently removes the hook and may stop calling it. Reading
  `MSLLHOOKSTRUCT.flags` must be strictly O(1) and `CallNextHookEx` must be
  prompt. **I am not fully certain of the exact current-OS timeout semantics or
  whether a removed hook is re-armed or just dropped** — confirm the documented
  `LowLevelHooksTimeout` behavior and the re-arm strategy before implementing
  171, rather than guessing. (Usermode, not a BSOD risk, but a detection-validity
  uncertainty per guardrail #13's spirit. Same uncertainty as
  `win-input-automation.md` R3.)

- **R4 — UNCERTAINTY: macOS injection-source field semantics (171/170 macOS).**
  Whether `CGEventGetIntegerValueField(kCGMouseEventSubtype)` and
  `kCGEventSourceStateID` reliably distinguish hardware vs. `CGEventPost`-
  synthesized mouse motion across macOS versions — and whether all synthetic
  paths set a stable, queryable source state — is **not something I am certain
  of**. Confirm against current CoreGraphics docs/behavior on the target macOS
  before relying on the bit; until confirmed, treat the macOS injection fraction
  as best-effort and let the cross-platform Windows/Linux signals carry the
  weight. (Not a kernel/ES API, so no BSOD/ES-deadline risk — a
  detection-validity uncertainty.)

- **R5 — macOS TCC permission for CGEventTap / IOHIDManager (163/170/171
  macOS).** A passive `CGEventTapCreate` listen-only tap and `IOHIDManager`
  value access require the Input-Monitoring / Accessibility TCC grant. This is
  **not** the Apple-approved EndpointSecurity entitlement (guardrail #4/#7 ES
  concerns do **not** bind a passive CG tap — it drops no events and owes no
  auth reply). But the not-granted path must leave features at default and never
  crash. Reviewer should confirm the product's macOS bring-up already requests
  Input-Monitoring, or these three sensors no-op on macOS until it does.

- **R6 — Linux evdev access + uinput provenance (163/165/171 Linux).** Reading
  `/dev/input/event*` requires the `input` group or equivalent ACL; the
  `uinput`-vs-real-node distinction via libudev `ID_INPUT` is well-trodden but
  the exact property set marking a virtual device varies by distro/udev version.
  This is **userspace**, entirely separate from the eBPF/LKM kernel plane — the
  `-Wall -Wextra -Werror` kernel build (guardrail #6) does not apply. Flag for
  confirmation of the `ID_INPUT` property used to mark virtual devices on the
  target distros (Steam Deck included).

- **R7 — FP gating is a real-user safety floor (all nine).** Virtual-HID
  remappers, Steam Input, accessibility head-trackers, KVM/streaming, on-screen
  keyboards, high-skill players, aim-assist controllers, and pre-aiming/prediction
  all produce signatures these sensors flag. The server-side cohort segregation
  (attested device path/VID-PID, declared smoothing/accel state, focus-loss
  correlation, distribution-over-`player_id`, provenance corroboration) is
  load-bearing and must ship with the model, not as a later refinement, or the
  first telemetry wave mislabels legitimate and disabled players. The client-side
  inputs that feed these gates (accel state for 164, frame period for 165,
  `focus_active` for 170, `impulse_is_direction_change` for 167) are
  non-negotiable parts of this plan.

None of these nine signals touch a kernel API, IRP lifecycle, IRQL,
`ObRegisterCallbacks`, an EndpointSecurity auth deadline, or code-signing of our
driver — they are usermode SDK sensors + server feature transport. The genuine
API uncertainties (R3 Windows LL-hook timeout, R4 macOS CG injection-source
semantics, R5 macOS TCC, R6 Linux uinput provenance) are flagged above for
confirmation before coding rather than guessed (guardrail #13).
