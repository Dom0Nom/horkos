/*
 * tests/unit/test_aim_accumulator.cpp
 * Role: Host unit test for the platform-free behavioral-aim per-tick fold
 *       (sdk/src/input/AimAccumulator.cpp, catalog signals 163/165/171). Exercises
 *       the count/summed-delta/newest-ts provenance fold (163), the inter-arrival
 *       mean/variance + render-frame-locked interval count (165), and the
 *       injected-fraction Q0.8 computation (171) with synthetic hk_hid_sample
 *       windows — no platform API, no live HID, no OS call. Proves the fold derives
 *       features deterministically and that the framelock count fires ONLY when an
 *       interval equals the supplied frame period (distinguishing timer-locked
 *       synthetic input from real polling without any client-side verdict).
 * Target platforms: host (CI). Guardrail #4: links only the platform-free
 *       AimAccumulator TU; no kernel/platform TU.
 */

#include "input/AimSampler.h"

#include <gtest/gtest.h>

using hk::sdk::aim::fold_tick;
using hk::sdk::aim::hk_aim_features;
using hk::sdk::aim::hk_hid_sample;

namespace {

hk_aim_features zeroed()
{
    hk_aim_features f{};
    return f;
}

} // namespace

TEST(AimAccumulator, EmptyWindowLeavesFeaturesAtDefault)
{
    hk_aim_features f = zeroed();
    fold_tick(nullptr, 0, 0, &f);
    EXPECT_EQ(f.hid_report_count, 0u);
    EXPECT_EQ(f.hid_raw_dx, 0);
    EXPECT_EQ(f.hid_raw_dy, 0);
    EXPECT_EQ(f.hid_newest_ts_ns, 0u);
    EXPECT_EQ(f.hid_interval_mean_ns, 0u);
    EXPECT_EQ(f.hid_interval_var_ns, 0u);
    EXPECT_EQ(f.hid_interval_framelock_count, 0u);
    EXPECT_EQ(f.injected_event_fraction_q8, 0u);
}

TEST(AimAccumulator, NullOutIsSafe)
{
    hk_hid_sample s{1, 2, 100, 0};
    fold_tick(&s, 1, 0, nullptr); // must not crash
    SUCCEED();
}

TEST(AimAccumulator, SumsRawDeltasAndTracksNewestTimestamp)
{
    hk_hid_sample samples[3] = {
        {10, -5, 1000, 0},
        {3, 7, 3000, 0},
        {-1, 2, 2000, 0}, // out of order: newest ts is still 3000
    };
    hk_aim_features f = zeroed();
    fold_tick(samples, 3, 0, &f);
    EXPECT_EQ(f.hid_report_count, 3u);
    EXPECT_EQ(f.hid_raw_dx, 12);  // 10 + 3 - 1
    EXPECT_EQ(f.hid_raw_dy, 4);   // -5 + 7 + 2
    EXPECT_EQ(f.hid_newest_ts_ns, 3000u);
}

TEST(AimAccumulator, RealThousandHzCadenceHasNoFramelock)
{
    // ~1000 Hz: 1,000,000 ns intervals with bounded jitter. Frame period is
    // 16,666,667 ns (60 Hz). No interval equals the frame period -> framelock 0.
    const uint64_t frame_period_ns = 16'666'667;
    hk_hid_sample samples[5];
    uint64_t t = 5'000'000;
    const uint64_t jittered[5] = {0, 1'000'100, 999'900, 1'000'050, 999'950};
    for (int i = 0; i < 5; ++i) {
        t += jittered[i];
        samples[i] = {1, 0, t, 0};
    }
    hk_aim_features f = zeroed();
    fold_tick(samples, 5, frame_period_ns, &f);
    EXPECT_EQ(f.hid_interval_framelock_count, 0u);
    // Mean interval is ~1,000,000 ns, far from the 60 Hz frame period.
    EXPECT_NEAR(static_cast<double>(f.hid_interval_mean_ns), 1'000'000.0, 1000.0);
}

TEST(AimAccumulator, FrameLockedCadenceSurfacesInFramelockCount)
{
    // Synthetic reports emitted on the render-frame cadence: every interval
    // equals the frame period -> framelock count == number of intervals.
    const uint64_t frame_period_ns = 16'666'667;
    hk_hid_sample samples[4];
    uint64_t t = 1'000'000;
    for (int i = 0; i < 4; ++i) {
        samples[i] = {2, 1, t, 0};
        t += frame_period_ns;
    }
    hk_aim_features f = zeroed();
    fold_tick(samples, 4, frame_period_ns, &f);
    EXPECT_EQ(f.hid_interval_framelock_count, 3u); // 4 samples -> 3 intervals
    EXPECT_EQ(f.hid_interval_mean_ns, frame_period_ns);
    EXPECT_EQ(f.hid_interval_var_ns, 0u); // perfectly periodic
}

TEST(AimAccumulator, InjectedFractionIsQ08)
{
    // 2 of 4 events injected -> 0.5 -> Q0.8 == 128.
    hk_hid_sample samples[4] = {
        {1, 0, 1000, 1},
        {1, 0, 2000, 0},
        {1, 0, 3000, 1},
        {1, 0, 4000, 0},
    };
    hk_aim_features f = zeroed();
    fold_tick(samples, 4, 0, &f);
    EXPECT_EQ(f.injected_event_fraction_q8, 128u);
}

TEST(AimAccumulator, AllInjectedSaturatesBelowOverflow)
{
    // 3 of 3 injected -> 1.0; Q0.8 caps at 255 (256 would overflow the byte).
    hk_hid_sample samples[3] = {
        {1, 0, 1000, 1},
        {1, 0, 2000, 1},
        {1, 0, 3000, 1},
    };
    hk_aim_features f = zeroed();
    fold_tick(samples, 3, 0, &f);
    EXPECT_EQ(f.injected_event_fraction_q8, 255u);
}

TEST(AimAccumulator, SingleSampleHasNoIntervals)
{
    hk_hid_sample s{4, 4, 9999, 0};
    hk_aim_features f = zeroed();
    fold_tick(&s, 1, 16'666'667, &f);
    EXPECT_EQ(f.hid_report_count, 1u);
    EXPECT_EQ(f.hid_interval_mean_ns, 0u);
    EXPECT_EQ(f.hid_interval_framelock_count, 0u);
}
