/*
 * bypass-tests/win/network/hk_bypass_net_route.cpp
 * Role: network-anomaly route-integrity merge-gate bypass test (signal 188)
 *       [disabled]. When enabled: a TAP/proxy that shifts the on-wire path WITHOUT an
 *       OS route/link event sets route_change_unattested; a real OS-mediated reroute
 *       fires NotifyRouteChange2/NotifyIpInterfaceChange and does NOT (the
 *       discriminator). Compiled now for the merge gate (guardrail #12).
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: drives hk::net::probe_route_integrity (RouteWatchWin.cpp).
 */
#include <cstdio>
#ifndef HK_NET_BYPASS_ENABLED
int main(void) {
    std::printf("DISABLED: net_route activates with the NotifyRouteChange2 callback "
                "wiring + the TAP-without-event fixture.\n");
    return 0;
}
#else
int main(void) {
    std::printf("net_route: route-change-without-event fixture not yet implemented.\n");
    return 1;
}
#endif
