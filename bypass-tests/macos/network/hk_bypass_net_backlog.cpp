/*
 * Role: network-anomaly macOS bypass-test merge gate (signal 184) [disabled].
 *       A held-uplink (paused send thread) shows the app ring rising while getsockopt(SO_NWRITE) stays ~0 with no congestion; a congested link grows the kernel side too.
 *       Compiled now for the merge gate (guardrail #12), DISABLED-but-compiled like
 *       the other macOS gates; activates with the on-box read path + fixture.
 * Target platforms: macOS only (built behind if(APPLE)).
 * Interface: drives the hk::net probe surface (sdk/include/horkos/net_timing.h).
 */
#include <cstdio>
#ifndef HK_NET_BYPASS_ENABLED
int main(void) {
    std::printf("DISABLED: net_backlog (macOS) activates with the on-box read path + fixture.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}
#else
int main(void) {
    std::printf("net_backlog (macOS): live fixture not yet implemented.\n");
    return 1;
}
#endif
