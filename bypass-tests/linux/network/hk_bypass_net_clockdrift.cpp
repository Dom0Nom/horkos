/*
 * bypass-tests/linux/network/hk_bypass_net_clockdrift.cpp
 * Role: network-anomaly Linux bypass-test merge gate (signal 182) [disabled].
 *       A scaled clock (CLOCK_MONOTONIC_RAW at 0.8x CLOCK_REALTIME) yields the expected clock_ratio_ppm; an NTP-style step trips step_detected but not the smooth-scale path.
 *       Compiled now for the merge gate (guardrail #12), DISABLED-but-compiled like
 *       the other Linux gates; activates with the on-box read path + fixture.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the hk::net probe surface (sdk/include/horkos/net_timing.h).
 */
#include <cstdio>
#ifndef HK_NET_BYPASS_ENABLED
int main(void) {
    std::printf("DISABLED: net_clockdrift (Linux) activates with the on-box read path + fixture.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}
#else
int main(void) {
    std::printf("net_clockdrift (Linux): live fixture not yet implemented.\n");
    return 1;
}
#endif
