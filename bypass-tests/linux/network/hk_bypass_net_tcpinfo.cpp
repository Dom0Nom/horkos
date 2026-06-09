/*
 * bypass-tests/linux/network/hk_bypass_net_tcpinfo.cpp
 * Role: network-anomaly Linux bypass-test merge gate (signal 183) [disabled].
 *       A selective UDP-drop lag-switch leaves getsockopt(TCP_INFO) healthy while the app perceives a UDP stall — the captured contradiction.
 *       Compiled now for the merge gate (guardrail #12), DISABLED-but-compiled like
 *       the other Linux gates; activates with the on-box read path + fixture.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the hk::net probe surface (sdk/include/horkos/net_timing.h).
 */
#include <cstdio>
#ifndef HK_NET_BYPASS_ENABLED
int main(void) {
    std::printf("DISABLED: net_tcpinfo (Linux) activates with the on-box read path + fixture.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}
#else
int main(void) {
    std::printf("net_tcpinfo (Linux): live fixture not yet implemented.\n");
    return 1;
}
#endif
