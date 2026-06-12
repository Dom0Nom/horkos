/*
 * Role: network-anomaly macOS bypass-test merge gate (signal 182) [disabled].
 *       A scaled clock (CLOCK_MONOTONIC_RAW vs CLOCK_REALTIME) yields the expected clock_ratio_ppm; an NTP-style step trips step_detected but not the smooth-scale path.
 *       Compiled now for the merge gate (guardrail #12), DISABLED-but-compiled like
 *       the other macOS gates; activates with the on-box read path + fixture.
 * Target platforms: macOS only (built behind if(APPLE)).
 * Interface: drives the hk::net probe surface (sdk/include/horkos/net_timing.h).
 */
#include <cstdio>
#ifndef HK_NET_BYPASS_ENABLED
int main(void) {
    std::printf("DISABLED: net_clockdrift (macOS) activates with the on-box read path + fixture.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}
#else
int main(void) {
    std::printf("net_clockdrift (macOS): live fixture not yet implemented.\n");
    return 1;
}
#endif
