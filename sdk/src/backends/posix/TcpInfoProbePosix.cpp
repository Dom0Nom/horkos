/*
 * Role: Signal 183 POSIX half — kernel-TCP_INFO vs perceived-stall sensor. Reads
 *       the kernel's view of the TCP CONTROL/matchmaking channel (smoothed RTT +
 *       retransmits) so the server can spot the lag-switch contradiction "TCP
 *       healthy while the UDP game channel stalls". Linux: getsockopt(SOL_TCP,
 *       TCP_INFO) -> tcpi_rtt / tcpi_retrans. macOS: getsockopt(IPPROTO_TCP,
 *       TCP_CONNECTION_INFO) -> tcpi_srtt / tcpi_rxretransmit. Every OS call is
 *       gated behind HK_PLATFORM_LINUX / HK_PLATFORM_MACOS (guardrail #1); compiles
 *       -Wall -Wextra -Werror clean (guardrail #6).
 * Target platforms: Linux, macOS.
 * Interface: implements `hk::net::probe_conn_health` (POSIX half) from
 *       `net_probes.h`. The Windows half is in backends/win/TcpInfoProbeWin.cpp;
 *       exactly one is compiled per platform.
 */

#include "platform.h"
#include "net_probes.h"

#include <cstdint>

#if defined(HK_PLATFORM_LINUX) || defined(HK_PLATFORM_MACOS)
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

namespace hk { namespace net {

namespace {

/* The TCP control-channel socket fd the SDK matchmaking/control client owns, and a
 * stall flag it sets when the app perceived a stall this window. -1 = no control
 * channel yet (the live wiring lands in a later /tdd integration); until then the
 * probe reports no-data, never a positive. */
intptr_t g_tcp_fd = -1;
uint32_t g_app_perceived_stall = 0;

} // namespace

/* Published by the SDK control-channel owner once per window. */
void hk_net_set_control_channel(intptr_t tcp_fd, uint32_t app_perceived_stall)
{
    g_tcp_fd = tcp_fd;
    g_app_perceived_stall = app_perceived_stall;
}

hk_net_conn_health probe_conn_health(void)
{
    hk_net_conn_health out;
    out.conn_rtt_us = 0;
    out.conn_retrans = 0;
    out.app_perceived_stall = g_app_perceived_stall;
    out.reserved = 0;

    if (g_tcp_fd < 0) {
        return out;
    }
    const int fd = static_cast<int>(g_tcp_fd);

#if defined(HK_PLATFORM_LINUX)
    struct tcp_info info;
    socklen_t len = sizeof(info);
    /* zero so an unchanged field reads as 0, not stack garbage (guardrail #6). */
    for (unsigned i = 0; i < sizeof(info); ++i) {
        reinterpret_cast<unsigned char*>(&info)[i] = 0;
    }
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &len) != 0) {
        return out; /* no-data on failure */
    }
    /* tcpi_rtt is microseconds already. */
    out.conn_rtt_us = static_cast<uint32_t>(info.tcpi_rtt);
    out.conn_retrans = static_cast<uint32_t>(info.tcpi_total_retrans);
    return out;
#elif defined(HK_PLATFORM_MACOS)
    struct tcp_connection_info info;
    socklen_t len = sizeof(info);
    for (unsigned i = 0; i < sizeof(info); ++i) {
        reinterpret_cast<unsigned char*>(&info)[i] = 0;
    }
    if (getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &info, &len) != 0) {
        return out;
    }
    /* tcpi_srtt is in milliseconds on Darwin; convert to microseconds. */
    out.conn_rtt_us = static_cast<uint32_t>(info.tcpi_srtt) * 1000u;
    out.conn_retrans = static_cast<uint32_t>(info.tcpi_txretransmitpackets);
    return out;
#else
    (void)fd;
    return out;
#endif
}

} } // namespace hk::net
