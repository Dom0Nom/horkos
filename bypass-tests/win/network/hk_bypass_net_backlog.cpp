/*
 * Role: network-anomaly send-backlog merge-gate bypass test (signal 184) [disabled].
 *       When enabled: a held-uplink (paused send thread) shows the app send-ring
 *       rising while the kernel unsent/ideal-backlog stays ~0 and the link reports no
 *       congestion — the contradiction SendBacklogProbe pairs. A genuinely congested
 *       link grows the kernel side too (no contradiction). Compiled now for the merge
 *       gate (guardrail #12). Host equivalent: tests/unit/test_net_collect.cpp.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: drives hk::net::probe_send_backlog (SendBacklogProbe.cpp via net_backend.h).
 */
#include <cstdio>
#ifndef HK_NET_BYPASS_ENABLED
int main(void) {
    std::printf("DISABLED: net_backlog live form activates with the on-box socket "
                "backend; the app-vs-kernel pairing is host-tested in the unit suite.\n");
    return 0;
}
#else
int main(void) {
    std::printf("net_backlog: held-uplink socket fixture not yet implemented.\n");
    return 1;
}
#endif
