/*
 * Role: Host unit test for the AC client lifecycle (ac/src/ac.cpp). Exercises
 *       the start/stop state machine (single-start guard, degraded-vs-active by
 *       driver presence) and the latched detection-flag channel that sensors
 *       report into and the bypass tests read via ac_get_last_flag.
 * Target platforms: host (CI). Links hk_ac; no platform TU.
 */

#include <horkos/ac.h>

#include <gtest/gtest.h>

// Backend hooks (not in the public header) the lifecycle exposes for the
// platform driver-probe and the sensors.
extern "C" void hk_ac_set_driver_present(int present);
extern "C" void hk_ac_report_flag(uint32_t flag_bit);

namespace {

// Each test starts from a clean Idle state (globals persist within the binary).
void reset() {
    ac_stop();
    hk_ac_set_driver_present(0);
}

} // namespace

TEST(AcLifecycle, DegradedWithoutDriver) {
    reset();
    EXPECT_EQ(ac_start(nullptr), HK_AC_DEGRADED);
    ac_stop();
}

TEST(AcLifecycle, ActiveWithDriver) {
    reset();
    hk_ac_set_driver_present(1);
    EXPECT_EQ(ac_start(nullptr), HK_AC_OK);
    ac_stop();
}

TEST(AcLifecycle, DoubleStartRejected) {
    reset();
    EXPECT_NE(ac_start(nullptr), HK_AC_ALREADY_RUNNING); // first start succeeds
    EXPECT_EQ(ac_start(nullptr), HK_AC_ALREADY_RUNNING);  // second is rejected
    ac_stop();
}

TEST(AcLifecycle, RestartAfterStop) {
    reset();
    ac_start(nullptr);
    EXPECT_EQ(ac_stop(), HK_AC_OK);
    EXPECT_NE(ac_start(nullptr), HK_AC_ALREADY_RUNNING); // stop allows restart
    ac_stop();
}

TEST(AcLifecycle, FlagChannelRoundTrips) {
    reset();
    ac_start(nullptr);
    EXPECT_EQ(ac_get_last_flag(), 0u); // start clears the latch
    hk_ac_report_flag(0x0000'0004u);
    hk_ac_report_flag(0x0000'0010u);
    EXPECT_EQ(ac_get_last_flag(), 0x0000'0014u); // OR-accumulated
    ac_stop();
}

TEST(AcLifecycle, StartClearsPreviousFlags) {
    reset();
    ac_start(nullptr);
    hk_ac_report_flag(0x0000'00FFu);
    ac_stop();
    ac_start(nullptr);
    EXPECT_EQ(ac_get_last_flag(), 0u); // a fresh run starts clean
    ac_stop();
}
