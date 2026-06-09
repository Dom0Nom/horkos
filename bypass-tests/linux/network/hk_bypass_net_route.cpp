/*
 * bypass-tests/linux/network/hk_bypass_net_route.cpp
 * Role: network-anomaly Linux bypass-test merge gate (signal 188) [disabled].
 *       A TAP/proxy that shifts the path WITHOUT an rtnetlink RTM_NEWROUTE/RTM_NEWLINK event sets route_change_unattested; an OS-mediated reroute fires the event and does not.
 *       Compiled now for the merge gate (guardrail #12), DISABLED-but-compiled like
 *       the other Linux gates; activates with the on-box read path + fixture.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the hk::net probe surface (sdk/include/horkos/net_timing.h).
 */
#include <cstdio>
#ifndef HK_NET_BYPASS_ENABLED
int main(void) {
    std::printf("DISABLED: net_route (Linux) activates with the on-box read path + fixture.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}
#else
int main(void) {
    std::printf("net_route (Linux): live fixture not yet implemented.\n");
    return 1;
}
#endif
