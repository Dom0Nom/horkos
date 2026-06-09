/*
 * sdk/src/backends/win/TcpInfoProbeWin.cpp
 * Role: Signal 183 Windows half — kernel-TCP_INFO vs perceived-stall sensor.
 *       WSAIoctl(SIO_TCP_INFO) on the game TCP CONTROL/matchmaking channel reads
 *       the kernel's SmoothedRtt + retransmits so the server can spot the
 *       lag-switch contradiction "TCP healthy while the UDP game channel stalls".
 *       All Win32/Winsock API confined to this backends/win/ TU (guardrail #1).
 *       Usermode (PASSIVE_LEVEL); no kernel TU.
 * Target platforms: Windows.
 * Interface: implements `hk::net::probe_conn_health` (Windows half) from
 *       `net_probes.h`. The POSIX half is backends/posix/TcpInfoProbePosix.cpp;
 *       exactly one is compiled per platform.
 *
 * Cannot be compiled on the macOS dev host; written against the impl-plan +
 * sibling backends/win sources.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h> /* SIO_TCP_INFO, TCP_INFO_v0 */
#include <windows.h>

#include "horkos/net_timing.h"
#include "net_probes.h"

#include <cstdint>

namespace hk { namespace net {

namespace {

intptr_t g_tcp_fd = static_cast<intptr_t>(INVALID_SOCKET);
uint32_t g_app_perceived_stall = 0;

} // namespace

void hk_net_set_control_channel(intptr_t tcp_fd, uint32_t app_perceived_stall)
{
    g_tcp_fd = tcp_fd;
    g_app_perceived_stall = app_perceived_stall ? 1u : 0u;
}

hk_net_conn_health probe_conn_health(void)
{
    hk_net_conn_health out;
    out.conn_rtt_us = 0;
    out.conn_retrans = 0;
    out.app_perceived_stall = g_app_perceived_stall;
    out.reserved = 0;

    if (g_tcp_fd == static_cast<intptr_t>(INVALID_SOCKET)) {
        return out;
    }
    const SOCKET s = static_cast<SOCKET>(g_tcp_fd);

    /* TCP_INFO_v0 (Win10 1703+) carries RttUs + RtoUs + TcpRetransmitCount, which
     * is sufficient for the 183 contradiction. We request version 0 explicitly. */
    TCP_INFO_v0 info;
    for (unsigned i = 0; i < sizeof(info); ++i) {
        reinterpret_cast<unsigned char*>(&info)[i] = 0;
    }
    DWORD info_version = 0; /* request v0 */
    DWORD bytes = 0;
    const int rc = WSAIoctl(s, SIO_TCP_INFO,
                            &info_version, sizeof(info_version),
                            &info, sizeof(info),
                            &bytes, nullptr, nullptr);
    if (rc != 0 || bytes < sizeof(info)) {
        /* HK-UNCERTAIN(win-tcp-info-version): TCP_INFO_v0 vs _v1 availability is
         * Windows-build-gated (impl-plan Risks: 183). On a build where SIO_TCP_INFO
         * with v0 is rejected, the documented fallback is GetPerTcpConnectionEStats
         * — NOT implemented here pending on-box confirmation of the minimum target
         * build (guardrail #13). On failure we report no-data (zeros), never a
         * fabricated stall. */
        return out;
    }

    /* RttUs is microseconds; TcpRetransmitCount is cumulative on the connection. */
    out.conn_rtt_us = static_cast<uint32_t>(info.RttUs);
    out.conn_retrans = static_cast<uint32_t>(info.TcpRetransmitCount);
    return out;
}

} } // namespace hk::net
