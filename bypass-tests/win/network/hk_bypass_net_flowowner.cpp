/*
 * Role: network-anomaly flow-owner merge-gate bypass test (signal 189) [disabled].
 *       When enabled: a loopback MITM proxy on the game 5-tuple is observed as a
 *       local owner PID; a direct connection to the server IP is not. A signed
 *       allowlisted interposer is REPORTED but down-weighted (high-FP gate). Compiled
 *       now for the merge gate (guardrail #12).
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: drives hk::net::probe_flow_owner (SocketTableProbeWin.cpp).
 */
#include <cstdio>
#ifndef HK_NET_BYPASS_ENABLED
int main(void) {
    std::printf("DISABLED: net_flowowner activates with the GetExtendedUdpTable owner "
                "resolution + the loopback-proxy fixture.\n");
    return 0;
}
#else
int main(void) {
    std::printf("net_flowowner: loopback-proxy owner fixture not yet implemented.\n");
    return 1;
}
#endif
