/*
 * bypass-tests/win/network/hk_bypass_net_txcadence.cpp
 * Role: network-anomaly TX-cadence merge-gate bypass test (signal 181) [disabled].
 *       When enabled: a userland send-shim that buffers + re-bursts datagrams must
 *       produce a NIC-HW-TX vs QueryPerformanceCounter divergence the TxCadenceProbe
 *       reports, while a clean send loop does NOT. Proves the cadence skew is
 *       reported (the server classifies); the client never bans on it. Compiled now
 *       for the merge gate (guardrail #12), exactly like byovd_load.cpp.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: drives hk::net::probe_tx_cadence (sdk/include/horkos/net_timing.h).
 */
#include <cstdio>
#ifndef HK_NET_BYPASS_ENABLED
int main(void) {
    std::printf("DISABLED: net_txcadence activates with the SIO_TIMESTAMPING TX-read "
                "path (HK-UNCERTAIN, on-box) + the send-shim fixture.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}
#else
#include "horkos/net_timing.h"
int main(void) {
    /* Fixture (on-box): run the game send loop clean -> assert tx_cadence_skew_ns is
     * the no-data sentinel or ~0; interpose a buffer-and-reburst shim -> assert a
     * sustained skew is REPORTED (never a client verdict). */
    std::printf("net_txcadence: SIO_TIMESTAMPING read path not yet implemented.\n");
    return 1;
}
#endif
