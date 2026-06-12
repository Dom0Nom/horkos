/*
 * Role: Host-buildable unit tests for the Windows self-check false-positive-gate
 *       decision logic (kernel/win/include/selfcheck_fpgate.h). These are the
 *       pure predicates the kernel work item calls; testing them here proves the
 *       "N consecutive misses AND heartbeat advanced" and "census monotone-drop
 *       including own slot" gates without a WDK (the plan's FP-gate test
 *       requirement). The header is platform-free C99 so it compiles in a C++
 *       gtest TU directly.
 * Target platforms: host (any) — decision math only.
 * Interface: exercises HkFpObMissingVerdict / HkFpCensusDropVerdict /
 *       HkFpRegTamperHighWeight.
 */

#include <gtest/gtest.h>

#include "selfcheck_fpgate.h"

/* ---- Signal 1: Ob liveness FP gate ---- */

TEST(SelfCheckFpGate, ObMissing_SuppressedWhenEngineStarved)
{
    /* Even at/above the miss threshold, no verdict if the heartbeat did not
     * advance — that is scheduler starvation, not a removed callback. */
    EXPECT_EQ(0, HkFpObMissingVerdict(HK_SELFCHECK_MISS_THRESHOLD, /*hb*/ 0));
    EXPECT_EQ(0, HkFpObMissingVerdict(HK_SELFCHECK_MISS_THRESHOLD + 5, 0));
}

TEST(SelfCheckFpGate, ObMissing_NoVerdictBelowThreshold)
{
    EXPECT_EQ(0, HkFpObMissingVerdict(0, 1));
    EXPECT_EQ(0, HkFpObMissingVerdict(HK_SELFCHECK_MISS_THRESHOLD - 1, 1));
}

TEST(SelfCheckFpGate, ObMissing_VerdictAtThresholdWithHeartbeat)
{
    EXPECT_EQ(1, HkFpObMissingVerdict(HK_SELFCHECK_MISS_THRESHOLD, 1));
    EXPECT_EQ(1, HkFpObMissingVerdict(HK_SELFCHECK_MISS_THRESHOLD + 10, 1));
}

/* ---- Signal 4: notify census drop FP gate ---- */

TEST(SelfCheckFpGate, Census_NoVerdictBeforeFloorEstablished)
{
    /* floor==0 means boot not settled; never a verdict regardless of count. */
    EXPECT_EQ(0, HkFpCensusDropVerdict(/*floor*/ 0, /*current*/ 0, /*own*/ 0));
    EXPECT_EQ(0, HkFpCensusDropVerdict(0, 1, 0));
}

TEST(SelfCheckFpGate, Census_NoVerdictWhenOwnSlotPresent)
{
    /* A drop that does NOT include our own slot is foreign churn, not our signal. */
    EXPECT_EQ(0, HkFpCensusDropVerdict(/*floor*/ 3, /*current*/ 2, /*own*/ 1));
}

TEST(SelfCheckFpGate, Census_VerdictOnDropBelowFloorWithOwnSlotMissing)
{
    EXPECT_EQ(1, HkFpCensusDropVerdict(/*floor*/ 3, /*current*/ 2, /*own*/ 0));
    EXPECT_EQ(1, HkFpCensusDropVerdict(3, 0, 0));
}

TEST(SelfCheckFpGate, Census_NoVerdictAtOrAboveFloor)
{
    EXPECT_EQ(0, HkFpCensusDropVerdict(/*floor*/ 3, /*current*/ 3, /*own*/ 0));
    EXPECT_EQ(0, HkFpCensusDropVerdict(3, 4, 0));
}

TEST(SelfCheckFpGate, Census_RejectsImpossibleFloor)
{
    /* A floor above the documented cap is a corrupt baseline — reject it. */
    EXPECT_EQ(0, HkFpCensusDropVerdict(HK_PSP_MAX_NOTIFY + 1, 0, 0));
}

/* ---- Signal 5/9: registry-tamper writer-trust gate ---- */

TEST(SelfCheckFpGate, RegTamper_HighWeightForNonSystemWriter)
{
    EXPECT_EQ(1, HkFpRegTamperHighWeight(/*writer_is_system*/ 0));
}

TEST(SelfCheckFpGate, RegTamper_LowWeightForSystemWriter)
{
    EXPECT_EQ(0, HkFpRegTamperHighWeight(/*writer_is_system*/ 1));
}
