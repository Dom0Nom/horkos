/*
 * Role: POSIX backend for the cross-platform clock-drift / send-backlog / probe-RTT
 *       probes (signals 182 / 184 / 187). Implements the `net_backend.h` seam:
 *       clock_gettime(CLOCK_MONOTONIC_RAW) vs CLOCK_REALTIME (182); ioctl(SIOCOUTQ)
 *       on Linux / getsockopt(SO_NWRITE) on macOS for kernel unsent bytes (184); a
 *       bounded UDP echo probe socket (187, behind HK_NET_PROBE_CHANNEL). Every OS
 *       call is gated behind HK_PLATFORM_LINUX / HK_PLATFORM_MACOS, never raw
 *       __linux__/__APPLE__ (guardrail #1). Compiles -Wall -Wextra -Werror clean
 *       (guardrail #6): every struct initialised, every syscall return checked.
 * Target platforms: Linux, macOS.
 * Interface: implements `net_backend.h` (`hk::net::backend_*`).
 */

#include "platform.h" /* sets HK_PLATFORM_LINUX / HK_PLATFORM_MACOS */
#include "net_backend.h"

#include <cstdint>
#include <ctime>

#if defined(HK_PLATFORM_LINUX) || defined(HK_PLATFORM_MACOS)
#include <sys/socket.h>
#include <sys/ioctl.h>
#endif

#if defined(HK_PLATFORM_LINUX)
#include <linux/sockios.h> /* SIOCOUTQ */
#endif

namespace hk { namespace net {

bool backend_read_clock_pair(clock_sample* out)
{
    if (out == nullptr) {
        return false;
    }
#if defined(HK_PLATFORM_LINUX) || defined(HK_PLATFORM_MACOS)
    struct timespec mono = {0, 0};
    struct timespec real = {0, 0};

    /* CLOCK_MONOTONIC_RAW is NTP/slew-free (the whole point of 182). macOS gained
     * it in 10.12; both platforms in scope have it. */
#if defined(CLOCK_MONOTONIC_RAW)
    const clockid_t mono_id = CLOCK_MONOTONIC_RAW;
#else
    const clockid_t mono_id = CLOCK_MONOTONIC;
#endif
    if (clock_gettime(mono_id, &mono) != 0) {
        return false;
    }
    if (clock_gettime(CLOCK_REALTIME, &real) != 0) {
        return false;
    }
    out->mono_ns = static_cast<uint64_t>(mono.tv_sec) * 1000000000ull +
                   static_cast<uint64_t>(mono.tv_nsec);
    out->real_ns = static_cast<uint64_t>(real.tv_sec) * 1000000000ull +
                   static_cast<uint64_t>(real.tv_nsec);
    return true;
#else
    return false;
#endif
}

bool backend_read_kernel_backlog(intptr_t fd, kernel_backlog* out)
{
    if (out == nullptr || fd < 0) {
        return false;
    }
    const int sockfd = static_cast<int>(fd);

#if defined(HK_PLATFORM_LINUX)
    /* SIOCOUTQ returns the amount of unsent data in the socket send queue. */
    int unsent = 0;
    if (ioctl(sockfd, SIOCOUTQ, &unsent) != 0) {
        return false;
    }
    if (unsent < 0) {
        unsent = 0;
    }
    out->kernel_unsent_bytes = static_cast<uint32_t>(unsent);
    /* Linux exposes congestion via TCP_INFO (signal 183 path), not here; this
     * backend reports unsent bytes only and leaves congestion unknown (0). */
    out->link_congested = 0;
    return true;
#elif defined(HK_PLATFORM_MACOS)
    /* macOS: SO_NWRITE reports the bytes queued but not yet sent on the socket. */
    int nwrite = 0;
    socklen_t len = sizeof(nwrite);
    if (getsockopt(sockfd, SOL_SOCKET, SO_NWRITE, &nwrite, &len) != 0) {
        return false;
    }
    if (nwrite < 0) {
        nwrite = 0;
    }
    out->kernel_unsent_bytes = static_cast<uint32_t>(nwrite);
    out->link_congested = 0;
    return true;
#else
    (void)sockfd;
    return false;
#endif
}

/* -- 187 probe socket ---------------------------------------------------------
 * HK-UNCERTAIN(probe-echo): the server-side UDP echo responder these RTTs need
 * does not exist yet (impl-plan Risks: Dependency 187). The probe channel is
 * compiled only under HK_NET_PROBE_CHANNEL (default OFF). Even under the flag,
 * these report no-data until the paired server milestone lands and the exact echo
 * wire format + Linux SO_TIMESTAMPING RX-time path are verified on-box. Do NOT
 * implement a live round-trip against an unspecified responder. */
probe_socket_t backend_probe_open(const char* server_ip, uint16_t server_port)
{
    (void)server_ip;
    (void)server_port;
    return nullptr; /* no responder to talk to yet */
}

bool backend_probe_rtt(probe_socket_t sock, uint32_t timeout_us, uint32_t* out_rtt_us)
{
    (void)sock;
    (void)timeout_us;
    if (out_rtt_us != nullptr) {
        *out_rtt_us = 0;
    }
    return false; /* no-data */
}

void backend_probe_close(probe_socket_t sock)
{
    (void)sock;
}

} } // namespace hk::net
