/*
 * Role: network-anomaly probe-RTT merge-gate bypass test (signal 187) [disabled].
 *       When enabled: a game-port-only throttle diverges probe_rtt from game_rtt,
 *       while symmetric path congestion hits both equally (no divergence). Requires
 *       the server-side UDP echo responder (HK-UNCERTAIN / dependency) before the
 *       HK_NET_PROBE_CHANNEL path can run live. Compiled now for the merge gate
 *       (guardrail #12).
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: drives hk::net::probe_rtt_divergence (ProbeChannel.cpp via net_backend.h).
 */
#include <cstdio>
#ifndef HK_NET_BYPASS_ENABLED
int main(void) {
    std::printf("DISABLED: net_probertt activates once the server UDP echo responder "
                "ships and HK_NET_PROBE_CHANNEL is enabled (dependency).\n");
    return 0;
}
#else
int main(void) {
    std::printf("net_probertt: probe-socket echo path not yet implemented.\n");
    return 1;
}
#endif
