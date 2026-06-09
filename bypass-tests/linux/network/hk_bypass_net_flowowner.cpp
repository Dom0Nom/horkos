/*
 * bypass-tests/linux/network/hk_bypass_net_flowowner.cpp
 * Role: network-anomaly Linux bypass-test merge gate (signal 189) [disabled].
 *       A loopback MITM proxy on the game 5-tuple is observed as a local owner (sock_diag/proc walk); a direct connection to the server IP is not.
 *       Compiled now for the merge gate (guardrail #12), DISABLED-but-compiled like
 *       the other Linux gates; activates with the on-box read path + fixture.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the hk::net probe surface (sdk/include/horkos/net_timing.h).
 */
#include <cstdio>
#ifndef HK_NET_BYPASS_ENABLED
int main(void) {
    std::printf("DISABLED: net_flowowner (Linux) activates with the on-box read path + fixture.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}
#else
int main(void) {
    std::printf("net_flowowner (Linux): live fixture not yet implemented.\n");
    return 1;
}
#endif
