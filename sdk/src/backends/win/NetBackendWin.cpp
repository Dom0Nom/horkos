/*
 * Role: Windows backend for the cross-platform clock-drift / send-backlog /
 *       probe-RTT probes (signals 182 / 184 / 187). Implements the `net_backend.h`
 *       seam: QueryPerformanceCounter vs GetSystemTimePreciseAsFileTime (182);
 *       WSAIoctl(SIO_IDEAL_SEND_BACKLOG_QUERY) for kernel unsent/ideal backlog
 *       (184); a bounded UDP echo probe socket (187, behind HK_NET_PROBE_CHANNEL).
 *       All Win32/Winsock API confined to this backends/win/ TU (guardrail #1).
 * Target platforms: Windows.
 * Interface: implements `net_backend.h` (`hk::net::backend_*`).
 *
 * NOTE: usermode only — runs at PASSIVE_LEVEL in the game process. No kernel TU,
 * no IRQL/IRP concern. Cannot be compiled on the macOS dev host; written against
 * sibling backends/win sources.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h> /* SIO_IDEAL_SEND_BACKLOG_QUERY */
#include <windows.h>

#include "net_backend.h"

#include <cstdint>

namespace hk { namespace net {

namespace {

/* QPC ticks -> nanoseconds. Frequency is fixed after boot; query once. */
uint64_t qpc_now_ns()
{
    LARGE_INTEGER freq;
    LARGE_INTEGER ctr;
    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0) {
        return 0;
    }
    if (!QueryPerformanceCounter(&ctr)) {
        return 0;
    }
    /* (ctr / freq) seconds -> ns, computed to avoid overflow on large counters. */
    const long double sec = static_cast<long double>(ctr.QuadPart) /
                            static_cast<long double>(freq.QuadPart);
    return static_cast<uint64_t>(sec * 1.0e9L);
}

/* GetSystemTimePreciseAsFileTime -> ns since UNIX epoch. FILETIME is 100-ns ticks
 * since 1601-01-01; 11644473600 s separate that from the UNIX epoch. */
uint64_t precise_realtime_ns()
{
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    /* 100-ns ticks -> ns, then shift epoch. */
    const uint64_t hundred_ns_since_1601 = u.QuadPart;
    const uint64_t unix_offset_100ns = 116444736000000000ull;
    if (hundred_ns_since_1601 < unix_offset_100ns) {
        return 0;
    }
    return (hundred_ns_since_1601 - unix_offset_100ns) * 100ull;
}

} // namespace

bool backend_read_clock_pair(clock_sample* out)
{
    if (out == nullptr) {
        return false;
    }
    const uint64_t mono = qpc_now_ns();
    const uint64_t real = precise_realtime_ns();
    if (mono == 0 || real == 0) {
        return false;
    }
    out->mono_ns = mono;
    out->real_ns = real;
    return true;
}

bool backend_read_kernel_backlog(intptr_t fd, kernel_backlog* out)
{
    if (out == nullptr || fd == static_cast<intptr_t>(INVALID_SOCKET)) {
        return false;
    }
    const SOCKET s = static_cast<SOCKET>(fd);

    /* SIO_IDEAL_SEND_BACKLOG_QUERY reports the ideal send backlog (ISB) the stack
     * recommends — a proxy for how much the kernel is willing to buffer. It does
     * NOT directly return "unsent bytes" the way SIOCOUTQ does; the contradiction
     * 184 wants (app queue rising while the kernel is idle) is captured by pairing
     * the app-side ring depth (owned by the core) against a NON-growing ISB. We
     * report the ISB as the kernel-side number; the server interprets the pair. */
    ULONG isb = 0;
    DWORD bytes = 0;
    const int rc = WSAIoctl(s, SIO_IDEAL_SEND_BACKLOG_QUERY, nullptr, 0,
                            &isb, sizeof(isb), &bytes, nullptr, nullptr);
    if (rc != 0) {
        return false;
    }
    out->kernel_unsent_bytes = static_cast<uint32_t>(isb);
    out->link_congested = 0; /* Windows congestion state rides the 183 TCP_INFO path */
    return true;
}

/* -- 187 probe socket ---------------------------------------------------------
 * HK-UNCERTAIN(probe-echo): the server-side UDP echo responder these RTTs need
 * does not exist yet. Compiled only under HK_NET_PROBE_CHANNEL (default OFF).
 * The full Winsock UDP socket + WSARecv timeout + QPC-stamped round-trip is
 * written under /tdd once the server echo wire format is fixed; do NOT guess a
 * round-trip against an unspecified responder. Reports no-data today. */
probe_socket_t backend_probe_open(const char* server_ip, uint16_t server_port)
{
    (void)server_ip;
    (void)server_port;
    return nullptr;
}

bool backend_probe_rtt(probe_socket_t sock, uint32_t timeout_us, uint32_t* out_rtt_us)
{
    (void)sock;
    (void)timeout_us;
    if (out_rtt_us != nullptr) {
        *out_rtt_us = 0;
    }
    return false;
}

void backend_probe_close(probe_socket_t sock)
{
    (void)sock;
}

} } // namespace hk::net
