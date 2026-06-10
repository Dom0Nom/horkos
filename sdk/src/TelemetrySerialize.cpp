/*
 * sdk/src/TelemetrySerialize.cpp
 * Role: Implementation of the platform-free per-tick TickPayload serializer
 *       (TelemetrySerialize.h). Hand-rolls minimal JSON (no allocation, no JSON
 *       library) into a caller buffer, echoing the server simulation tick into
 *       the `tick` field. Pure; host-tested (tests/unit/test_telemetry_serialize.cpp).
 * Target platforms: all. Platform-free (guardrail #4) — no OS API.
 */

#include "TelemetrySerialize.h"

#include <cstdio>
#include <cstring>

namespace hk {
namespace sdk {
namespace telemetry {

namespace {

/* A bounded forward-only writer: tracks the total bytes the document WOULD
 * occupy (so the caller can detect truncation) while never writing past cap. */
struct Writer {
    char*  out;
    size_t cap;
    size_t need; /* total bytes the full document needs (excl. NUL). */

    void put(const char* s, size_t n)
    {
        for (size_t i = 0; i < n; ++i) {
            if (need + 1 < cap) {
                out[need] = s[i];
            }
            ++need;
        }
    }
    void puts(const char* s) { put(s, std::strlen(s)); }

    void key(const char* k)
    {
        put("\"", 1);
        puts(k);
        put("\":", 2);
    }

    void u64(uint64_t v)
    {
        char tmp[24];
        int n = std::snprintf(tmp, sizeof tmp, "%llu", (unsigned long long)v);
        if (n > 0) put(tmp, (size_t)n);
    }
    void i64(int64_t v)
    {
        char tmp[24];
        int n = std::snprintf(tmp, sizeof tmp, "%lld", (long long)v);
        if (n > 0) put(tmp, (size_t)n);
    }
    /* JSON numbers: emit floats with enough precision to round-trip f32. */
    void f32(float v)
    {
        char tmp[40];
        int n = std::snprintf(tmp, sizeof tmp, "%.9g", (double)v);
        if (n > 0) put(tmp, (size_t)n);
    }
    void boolean(bool v) { puts(v ? "true" : "false"); }
};

} // namespace

size_t serialize_tick(const hk_tick_input& in, char* out, size_t cap)
{
    Writer w{out, cap, 0};
    const hk::sdk::aim::hk_aim_features& f = in.features;

    w.put("{", 1);

    // Core (v1) fields.
    w.key("schema_version"); w.u64(in.schema_version);     w.put(",", 1);
    w.key("player_id");      w.u64(in.player_id);          w.put(",", 1);
    // THE ECHO: the wire `tick` carries the server simulation tick.
    w.key("tick");           w.u64(in.server_tick);        w.put(",", 1);
    // aim_delta_x/y = the actually-applied view delta this tick (164 fields).
    w.key("aim_delta_x");    w.f32(f.applied_angle_dx);    w.put(",", 1);
    w.key("aim_delta_y");    w.f32(f.applied_angle_dy);    w.put(",", 1);
    w.key("input_state");    w.u64(in.input_state);        w.put(",", 1);

    // v2 aim-feature block (163-171), names mirror schema.rs exactly.
    w.key("hid_report_count");            w.u64(f.hid_report_count);            w.put(",", 1);
    w.key("hid_raw_dx");                  w.i64(f.hid_raw_dx);                  w.put(",", 1);
    w.key("hid_raw_dy");                  w.i64(f.hid_raw_dy);                  w.put(",", 1);
    w.key("hid_newest_ts_ns");            w.u64(f.hid_newest_ts_ns);            w.put(",", 1);
    w.key("applied_angle_dx");            w.f32(f.applied_angle_dx);            w.put(",", 1);
    w.key("applied_angle_dy");            w.f32(f.applied_angle_dy);            w.put(",", 1);
    w.key("hid_interval_mean_ns");        w.u64(f.hid_interval_mean_ns);        w.put(",", 1);
    w.key("hid_interval_var_ns");         w.u64(f.hid_interval_var_ns);         w.put(",", 1);
    w.key("hid_interval_framelock_count"); w.u64(f.hid_interval_framelock_count); w.put(",", 1);
    w.key("ang_vel");                     w.f32(f.ang_vel);                     w.put(",", 1);
    w.key("ang_accel");                   w.f32(f.ang_accel);                   w.put(",", 1);
    w.key("ang_jerk");                    w.f32(f.ang_jerk);                    w.put(",", 1);
    w.key("dist_to_nearest_target_rad");  w.f32(f.dist_to_nearest_target_rad);  w.put(",", 1);
    w.key("target_vis_onset_ts_ns");      w.u64(f.target_vis_onset_ts_ns);      w.put(",", 1);
    w.key("first_impulse_ts_ns");         w.u64(f.first_impulse_ts_ns);         w.put(",", 1);
    w.key("fire_ts_ns");                  w.u64(f.fire_ts_ns);                  w.put(",", 1);
    w.key("impulse_is_direction_change"); w.boolean(f.impulse_is_direction_change != 0); w.put(",", 1);
    w.key("weapon_id");                   w.u64(f.weapon_id);                   w.put(",", 1);
    w.key("shot_index");                  w.u64(f.shot_index);                  w.put(",", 1);
    w.key("fire_active");                 w.boolean(f.fire_active != 0);        w.put(",", 1);
    w.key("aimed_target_id");             w.u64(f.aimed_target_id);             w.put(",", 1);
    w.key("switch_event_flag");           w.boolean(f.switch_event_flag != 0);  w.put(",", 1);
    w.key("clip_rect_ok");                w.boolean(f.clip_rect_ok != 0);       w.put(",", 1);
    w.key("cursor_hidden");               w.boolean(f.cursor_hidden != 0);      w.put(",", 1);
    w.key("raw_vs_abs_divergence_px");    w.u64(f.raw_vs_abs_divergence_px);    w.put(",", 1);
    w.key("focus_active");                w.boolean(f.focus_active != 0);       w.put(",", 1);
    w.key("virtual_device_present");      w.boolean(f.virtual_device_present != 0); w.put(",", 1);

    // 178 harmonic-exclusion inputs.
    w.key("client_mono_ns");              w.u64(in.client_mono_ns);             w.put(",", 1);
    w.key("client_refresh_hz");           w.u64(in.client_refresh_hz);          w.put(",", 1);
    w.key("fired");                       w.boolean(in.fired != 0);             w.put(",", 1);

    // 169 candidate target offsets array.
    w.key("candidate_target_offsets");
    w.put("[", 1);
    for (uint32_t i = 0; i < in.candidate_count; ++i) {
        if (i) w.put(",", 1);
        w.f32(in.candidate_offsets ? in.candidate_offsets[i] : 0.0f);
    }
    w.put("]", 1);

    w.put("}", 1);

    // NUL-terminate within cap.
    if (cap > 0) {
        size_t term = w.need < cap ? w.need : cap - 1;
        out[term] = '\0';
    }
    return w.need;
}

} // namespace telemetry
} // namespace sdk
} // namespace hk
