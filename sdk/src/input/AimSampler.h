/*
 * Role: SDK-internal façade for the behavioral-aim input sensors (catalog
 *       signals 163/164/165/170/171 provenance + 166/167/168/169 engine-state
 *       transport). Declares the per-platform sensor entry points and the shared
 *       per-tick aim-feature accumulator type (`hk_aim_features`) that `sdk.cpp`
 *       serialises into the per-tick JSON `TickPayload`. Platform-neutral
 *       declarations only — the Win32/IOKit/CG/evdev bodies live in the *Win.cpp
 *       / *Mac.mm / *Linux.cpp siblings under backends/<platform>/ (guardrail #1).
 *       The platform-free fold (`fold_tick`) lives in AimAccumulator.cpp.
 * Target platforms: all (declaration). The fields map 1:1 to the v2 additions on
 *       `server/telemetry/src/schema.rs::TickPayload`.
 * Interface: implemented per-platform under input/backends/<platform>/; consumed
 *       by the SDK AC tick. Findings ride the JSON tick plane, never the kernel
 *       ring (guardrail #4 — no kernel TU includes this header; the Linux evdev /
 *       macOS IOKit-CG paths here are USERSPACE, not the eBPF/LKM/ES kernel plane).
 *
 * Read-only contract: every sensor below consumes only the GAME'S OWN raw-input
 * sink / LL-hook / engine state. None injects input, writes a view angle, or
 * hooks a foreign process. A sensor that cannot resolve a value leaves the
 * feature at its zero/default and the server simply gets no signal — NEVER a
 * fabricated anomaly. ALL thresholds/verdicts are server-side (catalog mandate).
 */

#pragma once

#include <cstdint>

namespace hk { namespace sdk { namespace aim {

/* -------------------------------------------------------------------------
 * Fixed per-tick aim-feature block. Serialised into the tick JSON by sdk.cpp.
 * Fields map 1:1 to the v2 `TickPayload` members. This is an INTERNAL SDK POD
 * (not a public wire header), so it carries no HK_STATIC_ASSERT and no version
 * constant of its own — the wire version is `TickPayload::SCHEMA_VERSION` (=2).
 *
 * Provenance/quantization/cadence (163/164/165/170/171) are filled by the
 * platform backends below; the kinematic fields (166/167/168/169) are filled
 * from the engine's OWN state the game already exposes (view matrix + target/
 * occlusion/weapon lists) — no OS API, no new sensor.
 *
 * `candidate_target_offsets[]` (169) is variable-length and ships in the JSON
 * envelope (a Vec<f32> on the Rust side), NOT in this fixed POD — sdk.cpp appends
 * it from the engine's candidate set when serialising.
 * ------------------------------------------------------------------------- */
struct hk_aim_features {
    /* 163 raw HID -> render provenance */
    uint32_t hid_report_count;             /* HID reports consumed this tick */
    int32_t  hid_raw_dx;                   /* summed raw integer HID counts, X */
    int32_t  hid_raw_dy;                   /* summed raw integer HID counts, Y */
    uint64_t hid_newest_ts_ns;             /* newest HID hardware/QPC ts this tick */

    /* 164 quantization-floor */
    uint32_t sens_scalar_q16;              /* in-game DPI->angle sensitivity, Q16.16 */
    float    applied_angle_dx;             /* actually-applied view delta, X (rad) */
    float    applied_angle_dy;             /* actually-applied view delta, Y (rad) */

    /* 165 polling-interval jitter */
    uint64_t hid_interval_mean_ns;         /* mean inter-report interval this tick */
    uint64_t hid_interval_var_ns;          /* variance of inter-report interval */
    uint32_t hid_interval_framelock_count; /* intervals == render-frame period */

    /* 166 flick curvature (engine-state transport) */
    float    ang_vel;                      /* angular velocity of view vector (rad/s) */
    float    ang_accel;                    /* angular acceleration (rad/s^2) */
    float    ang_jerk;                     /* third-difference jerk (rad/s^3) */
    float    dist_to_nearest_target_rad;   /* angular dist to nearest hitbox centre */

    /* 167 reaction-latency floor */
    uint64_t target_vis_onset_ts_ns;       /* occluded->visible onset ts (engine PVS) */
    uint64_t first_impulse_ts_ns;          /* first corrective impulse ts toward it */
    uint64_t fire_ts_ns;                   /* fire-event ts toward it */
    uint8_t  impulse_is_direction_change;  /* 1 = genuine new-direction impulse */

    /* 168 recoil phase-lock */
    uint32_t weapon_id;                    /* engine weapon id */
    uint32_t shot_index;                   /* shot index within current burst */
    uint8_t  fire_active;                  /* full-auto fire-bit set this tick */

    /* 169 target-switch latency (candidate_target_offsets[] ships in the JSON
     * envelope, not here — see struct comment) */
    uint64_t aimed_target_id;              /* id of currently-aimed-at target */
    uint8_t  switch_event_flag;            /* aim discretely re-locked this tick */

    /* 170 cursor confinement (win/mac) */
    uint8_t  clip_rect_ok;                 /* clip rect == game confinement rect */
    uint8_t  cursor_hidden;                /* CURSOR_SHOWING absent */
    uint32_t raw_vs_abs_divergence_px;     /* |integrated raw - absolute cursor| px */
    uint8_t  focus_active;                 /* WM_ACTIVATE focus held (alt-tab gate) */

    /* 171 OS injection bit */
    uint16_t injected_event_fraction_q8;   /* frac of aim events flagged injected, Q0.8 */
    uint8_t  virtual_device_present;       /* virtual/uinput HID source seen this tick */
};

/* -------------------------------------------------------------------------
 * Platform-free per-report sample the backends hand to the accumulator. One per
 * HID report drained from the game's own raw-input sink this tick. Kept platform-
 * neutral (no OS types) so AimAccumulator.cpp and the host unit test fold it with
 * no platform TU (guardrail #4).
 * ------------------------------------------------------------------------- */
struct hk_hid_sample {
    int32_t  raw_dx;     /* raw integer HID count, X (RAWMOUSE.lLastX / EV_REL REL_X / IOHID) */
    int32_t  raw_dy;     /* raw integer HID count, Y */
    uint64_t ts_ns;      /* hardware/high-res timestamp (QPC / CLOCK_MONOTONIC_RAW / IOHID) */
    uint8_t  injected;   /* 1 = this report's source was flagged injected/synthetic (171) */
};

/* -------------------------------------------------------------------------
 * Platform-free fold: collapse a window of `hk_hid_sample`s (delivered by the
 * backends this tick) plus the supplied render-frame period into the 163/165/171
 * fields of `out` (counts, summed raw deltas, newest ts, inter-arrival mean/
 * variance, framelock count, injected fraction). Does NOT touch the engine-state
 * (166-169) or quantization (164) or cursor (170) fields — those are filled by
 * the engine transport and the cursor/injection backends respectively. Pure;
 * no OS API; implemented in AimAccumulator.cpp; host-tested.
 *   `samples`/`count` : the per-report samples for this tick (count may be 0).
 *   `frame_period_ns` : the engine's current render-frame period (for framelock).
 * ------------------------------------------------------------------------- */
void fold_tick(const hk_hid_sample* samples, uint32_t count,
               uint64_t frame_period_ns, hk_aim_features* out);

/* -------------------------------------------------------------------------
 * Per-platform sensor entry points. Each fills the subset of `out` it owns and
 * returns the number of HID samples observed (sample-producing sensors) or 0/1
 * as documented. A sensor with nothing to observe this tick returns 0 and leaves
 * its fields at default — never fabricates. Implemented under backends/<platform>/.
 * ------------------------------------------------------------------------- */

/* 163/164/165 — drain the game's own raw-HID sink into `samples` (up to `cap`),
 * stamping each with a hardware/high-res ts and the raw integer counts. Returns
 * the number of samples written. The CALLER then runs fold_tick over them. */
uint32_t sample_raw_hid(hk_hid_sample* samples, uint32_t cap);

/* 170 — fill clip_rect_ok / cursor_hidden / raw_vs_abs_divergence_px /
 * focus_active (Windows + macOS only; no-op returning false elsewhere). Returns
 * true if the sample was taken, false if the platform path was unavailable
 * (e.g. macOS TCC not granted) — leaving the 170 fields at default. */
bool sample_cursor_confinement(hk_aim_features* out);

/* 171 — fill injected_event_fraction_q8 / virtual_device_present from the OS
 * injection/source-state bit on the game's own input stream. Returns true if a
 * source-state read was available this tick. */
bool sample_injection_flag(hk_aim_features* out);

} } } // namespace hk::sdk::aim
