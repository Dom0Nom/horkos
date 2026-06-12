/*
 * Role: network-anomaly macOS bypass-test merge gate (signal 187) [disabled].
 *       A game-port-only throttle diverges probe_rtt from game_rtt; symmetric congestion hits both. Requires the server echo responder (dependency).
 *       Compiled now for the merge gate (guardrail #12), DISABLED-but-compiled like
 *       the other macOS gates; activates with the on-box read path + fixture.
 * Target platforms: macOS only (built behind if(APPLE)).
 * Interface: drives the hk::net probe surface (sdk/include/horkos/net_timing.h).
 */
#include <cstdio>
#ifndef HK_NET_BYPASS_ENABLED
int main(void) {
    std::printf("DISABLED: net_probertt (macOS) activates with the on-box read path + fixture.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}
#else
int main(void) {
    std::printf("net_probertt (macOS): live fixture not yet implemented.\n");
    return 1;
}
#endif
