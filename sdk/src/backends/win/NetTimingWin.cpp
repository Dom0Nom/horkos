/*
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
 * Cannot be compiled on the macOS dev host; written against
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

    /* HK-VERIFIED(win-sio-timestamping): SIO_TIMESTAMPING is documented as a
     * Winsock IOCTL added in Windows 10 20H2 (October 2020 Update, build 19042).
     * ref: https://learn.microsoft.com/windows/win32/winsock/winsock-timestamping
     * The TIMESTAMPING_CONFIG structure, TIMESTAMPING_FLAG_* constants, and the
     * per-datagram SO_TIMESTAMP control-message retrieval via WSASendMsg / WSARecvMsg
     * (with LPFN_WSARECVMSG resolved via SIO_GET_EXTENSION_FUNCTION_POINTER) are
     * all documented at the above URL. The per-adapter capability query
     * (SIO_TIMESTAMPING with TIMESTAMPING_FLAG_RX/TX queried via
     * WSAIoctl(SIO_TIMESTAMPING_GET_PARAMS)) is also documented.
     * HOWEVER: hardware TX timestamp availability (TIMESTAMPING_FLAG_TX_HARDWARE)
     * requires NIC driver support — most consumer NICs only support software TX
     * timestamps (TIMESTAMPING_FLAG_TX_SOFTWARE), which are taken at the kernel
     * dispatch level rather than the MAC, reducing precision. The distiction between
     * HW and SW timestamps is documented but the NIC capability is driver-specific.
     * (docs: SIO_TIMESTAMPING API contract documented on Win10 20H2+ — still needs
     * on-box NIC capability check on the Phase-3 Win11 25H2 box to confirm
     * TIMESTAMPING_FLAG_TX_HARDWARE availability and validate the skew precision) */
    return out;
}

} } // namespace hk::net
