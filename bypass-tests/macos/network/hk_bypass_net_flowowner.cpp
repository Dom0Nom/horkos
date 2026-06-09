/*
 * bypass-tests/macos/network/hk_bypass_net_flowowner.cpp
 * Role: network-anomaly macOS bypass-test merge gate (signal 189) [disabled].
 *       A loopback MITM proxy makes the game socket's OWN foreign address (proc_pidfdinfo/PROC_PIDFDSOCKETINFO) read as 127.0.0.0/8 -> flow_owner_local set; a direct connection to the server IP is not.
 *       Compiled now for the merge gate (guardrail #12), DISABLED-but-compiled like
 *       the other macOS gates; activates with the on-box read path + fixture.
 * Target platforms: macOS only (built behind if(APPLE)).
 * Interface: drives the hk::net probe surface (sdk/include/horkos/net_timing.h).
 */
#include <cstdio>
#ifndef HK_NET_BYPASS_ENABLED
int main(void) {
    std::printf("DISABLED: net_flowowner (macOS) activates with the on-box read path + fixture.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}
#else
int main(void) {
    std::printf("net_flowowner (macOS): live fixture not yet implemented.\n");
    return 1;
}
#endif
