/*
 * sdk/src/backends/win/NetTimingWin.cpp
 * Role: Signal 181 — NIC-hardware-TX-timestamp vs QueryPerformanceCounter
 *       send-cadence sensor. Intends to enable SIO_TIMESTAMPING (WSAIoctl) and read
 *       the per-datagram TX timestamp via WSASendMsg/WSARecvMsg WSAMSG control
 *       buffers (SO_TIMESTAMP), comparing it to the QPC app-send time to unmask a
 *       send-pacing shim that buffers + re-bursts. All Win32/Winsock API confined
 *       to this backends/win/ TU (guardrail #1). Usermode (PASSIVE_LEVEL); no
 *       kernel TU.
 * Target platforms: Windows.
 * Interface: implements `hk::net::probe_tx_cadence` (181) from `net_probes.h`.
 *
 * Cannot be compiled on the macOS dev host; written against the impl-plan + the
 * sibling backends/win sources.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "horkos/net_timing.h"
#include "net_probes.h"

#include <cstdint>

namespace hk { namespace net {

namespace {

/* The game uplink socket + the bound-adapter tunnel flag the SDK publishes. */
intptr_t g_tx_fd = static_cast<intptr_t>(INVALID_SOCKET);
uint32_t g_adapter_is_tunnel = 0; /* set from the bound adapter media type (FP gate) */

} // namespace

void hk_net_set_tx_socket(intptr_t fd, uint32_t adapter_is_tunnel)
{
    g_tx_fd = fd;
    g_adapter_is_tunnel = adapter_is_tunnel ? 1u : 0u;
}

hk_net_tx_cadence probe_tx_cadence(void)
{
    hk_net_tx_cadence out;
    /* Default to the no-data sentinel so an unsupported NIC is NEVER a positive. */
    out.tx_cadence_skew_ns = HK_NET_TX_SKEW_NO_DATA;
    out.queue_depth_growth = 0;
    out.adapter_is_tunnel = g_adapter_is_tunnel;

    if (g_tx_fd == static_cast<intptr_t>(INVALID_SOCKET)) {
        return out;
    }

    /* HK-UNCERTAIN(win-sio-timestamping): NIC/software TX timestamping via
     * WSAIoctl(SIO_TIMESTAMPING) is driver- AND Windows-build-dependent; the exact
     * TIMESTAMPING_CONFIG control structure, the per-adapter capability query, and
     * the SO_TIMESTAMP control-message retrieval through WSASendMsg/WSARecvMsg
     * (resolving LPFN_WSARECVMSG via SIO_GET_EXTENSION_FUNCTION_POINTER) have NOT
     * been verified on the target Windows baseline (impl-plan Risks: 181). Per
     * guardrail #13 the live TX-timestamp read is NOT implemented here — doing so
     * blind risks a false skew on NICs that silently ignore the request. The probe
     * emits the no-data sentinel until the SIO_TIMESTAMPING control structure +
     * capability query are confirmed on-box and the read lands under /tdd with the
     * hk_bypass_net_txcadence fixture. The app-send QPC half (QueryPerformanceCounter)
     * is trivially available; it is only useful PAIRED with a real HW-TX timestamp,
     * so it is not sampled in isolation here. */
    return out;
}

} } // namespace hk::net
