/*
 * tests/unit/test_timing_logic.cpp
 * Role: Host-buildable unit tests for the timing-side-channels PURE decision cores
 *       (catalog signals 154-162). These are the platform-free functions the sampler
 *       TUs call; testing them here proves the divergence/modality/cadence/drift/fan
 *       math without a debugger, a VM, or any OS hook (the plan's "factor the decision
 *       logic out into pure functions" + the 159/161 synthetic-histogram requirement).
 *       The cores live in hk_ac (timing_logic.cpp), which this target links.
 * Target platforms: host (any) — arithmetic over sampled scalars/vectors only.
 * Interface: exercises hk::timing::{watchdog_divergence_pct, watchdog_window_usable,
 *       clock_ratio_drift_ppm, histogram_mode_count, cadence_is_uniform_burst,
 *       cpuid_fan_spread}.
 */

#include <gtest/gtest.h>

#include <cstdint>

#include "horkos/timing/timing_signals.h"

using namespace hk::timing;

/* ---- 156 watchdog divergence + usable-window ---- */

TEST(TimingLogic, DivergenceZeroWindowIsNoEvidence) {
    EXPECT_EQ(watchdog_divergence_pct(0u, 1000u), 0u); /* no divide-by-zero spike */
}

TEST(TimingLogic, DivergencePercentAndClamp) {
    EXPECT_EQ(watchdog_divergence_pct(1000u, 1000u), 0u);  /* identical */
    EXPECT_EQ(watchdog_divergence_pct(1000u, 1500u), 50u); /* 50% faster watchdog */
    EXPECT_EQ(watchdog_divergence_pct(1000u, 500u), 50u);  /* 50% slower */
    /* A 100x divergence clamps to 1000. */
    EXPECT_EQ(watchdog_divergence_pct(10u, 100000u), 1000u);
}

TEST(TimingLogic, WindowUsableGates) {
    /* clean: no ctx switch, same known core */
    EXPECT_TRUE(watchdog_window_usable(0u, 3u, 3u));
    /* ctx switch discards */
    EXPECT_FALSE(watchdog_window_usable(1u, 3u, 3u));
    /* known migration discards */
    EXPECT_FALSE(watchdog_window_usable(0u, 3u, 5u));
    /* unknown core (aux==0) must NOT by itself discard */
    EXPECT_TRUE(watchdog_window_usable(0u, 0u, 5u));
    EXPECT_TRUE(watchdog_window_usable(0u, 3u, 0u));
}

/* ---- 157 shared-page vs API clock drift ---- */

TEST(TimingLogic, ClockDriftPpm) {
    EXPECT_EQ(clock_ratio_drift_ppm(1000u, 0u), 0u);       /* no API advance */
    EXPECT_EQ(clock_ratio_drift_ppm(1000u, 1000u), 0u);    /* in lockstep */
    /* shared advanced 1% more than the (hooked) API clock => 10000 ppm */
    EXPECT_EQ(clock_ratio_drift_ppm(1010u, 1000u), 10000u);
    /* direction folded away: API ahead of shared reads the same magnitude */
    EXPECT_EQ(clock_ratio_drift_ppm(990u, 1000u), 10000u);
}

/* ---- 159/161 histogram modality ---- */

TEST(TimingLogic, HistogramModeCount) {
    uint32_t unimodal[8] = {0, 1, 5, 9, 4, 1, 0, 0};
    EXPECT_EQ(histogram_mode_count(unimodal, 8u, 2u), 1u);

    /* Two well-separated peaks above the noise floor. */
    uint32_t bimodal[8] = {1, 8, 1, 0, 1, 7, 1, 0};
    EXPECT_EQ(histogram_mode_count(bimodal, 8u, 2u), 2u);

    /* Below the noise floor => no modes. */
    uint32_t noise[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    EXPECT_EQ(histogram_mode_count(noise, 8u, 2u), 0u);

    /* Endpoint peak counts against its single neighbor. */
    uint32_t left_peak[4] = {9, 2, 1, 0};
    EXPECT_EQ(histogram_mode_count(left_peak, 4u, 2u), 1u);

    EXPECT_EQ(histogram_mode_count(nullptr, 8u, 2u), 0u);
}

/* ---- 161 uniform-cadence burst ---- */

TEST(TimingLogic, UniformCadenceBurst) {
    /* 100 faults all landing in one inter-arrival bucket = single-step stepping. */
    uint32_t tight[8] = {0, 0, 100, 0, 0, 0, 0, 0};
    EXPECT_TRUE(cadence_is_uniform_burst(tight, 8u, /*faults=*/100u,
                                         /*min_faults=*/16u, /*conc=*/80u));

    /* Spread-out human-ish faults: no single bucket dominates. */
    uint32_t spread[8] = {12, 14, 13, 12, 15, 11, 12, 11};
    EXPECT_FALSE(cadence_is_uniform_burst(spread, 8u, 100u, 16u, 80u));

    /* Too few faults: not a burst regardless of concentration. */
    uint32_t few[8] = {0, 0, 5, 0, 0, 0, 0, 0};
    EXPECT_FALSE(cadence_is_uniform_burst(few, 8u, 5u, 16u, 80u));
}

/* ---- 162 CPUID leaf-fan spread ---- */

TEST(TimingLogic, CpuidFanSpread) {
    /* Bare-metal-flat: all leaves ~ same latency => small spread. */
    uint32_t flat_lat[4] = {40, 42, 41, 43};
    uint32_t flat_id[4]  = {0x1, 0x7, 0x40000000u, 0x40000001u};
    EXPECT_EQ(cpuid_fan_spread(flat_lat, flat_id, 4u), 3u); /* 43 - 40 */

    /* VMM-fanned: a hypervisor leaf spikes. */
    uint32_t fan_lat[4] = {40, 42, 900, 41};
    uint32_t fan_id[4]  = {0x1, 0x7, 0x40000000u, 0x40000001u};
    EXPECT_EQ(cpuid_fan_spread(fan_lat, fan_id, 4u), 860u); /* 900 - 40 */

    /* id==0 slots are skipped as unpopulated; fewer than 2 populated => 0. */
    uint32_t one_lat[4] = {40, 0, 0, 0};
    uint32_t one_id[4]  = {0x1, 0x0, 0x0, 0x0};
    EXPECT_EQ(cpuid_fan_spread(one_lat, one_id, 4u), 0u);
}
