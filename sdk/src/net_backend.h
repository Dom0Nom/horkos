/*
 * Role: Internal per-platform dispatch seam for the CROSS-PLATFORM network probes
 *       (signals 182 clock-drift, 184 send-backlog, 187 probe-RTT). Declares the
 *       raw platform reads each `sdk/src/backends/<plat>/NetBackend*.cpp`
 *       implements; the cross-platform cores (`ClockDomainProbe.cpp`,
 *       `SendBacklogProbe.cpp`, `ProbeChannel.cpp`) own the platform-neutral
 *       aggregation and dispatch ONLY through this header. Mirrors `sdk_backend.h`.
 *       NO platform headers here (guardrail #1): the seam is fixed-width POD.
 * Target platforms: all (declaration only).
 * Interface: implemented per-platform under `sdk/src/backends/{win,posix}/`
 *       (NetBackendWin.cpp / NetBackendPosix.cpp); called by the cross-platform
 *       cores listed above.
 */

#ifndef HK_NET_BACKEND_H
#define HK_NET_BACKEND_H

#include <stdint.h>

namespace hk { namespace net {

/* -- 182 clock-domain raw read ------------------------------------------------
 * One paired sample of the two clock domains, both in nanoseconds. `mono_ns` is
 * the OS monotonic/raw clock (QueryPerformanceCounter on Windows,
 * CLOCK_MONOTONIC_RAW on POSIX); `real_ns` is the wall clock
 * (GetSystemTimePreciseAsFileTime / CLOCK_REALTIME). The core computes the
 * per-window rate ratio from a sequence of these; the NTP-step-vs-smooth-scale
 * classification is server-side. Returns true on a successful paired read. */
struct clock_sample {
    uint64_t mono_ns;
    uint64_t real_ns;
};
bool backend_read_clock_pair(clock_sample* out);

/* -- 184 send-backlog raw read ------------------------------------------------
 * Kernel unsent bytes for the game uplink socket (SIO_IDEAL_SEND_BACKLOG_QUERY on
 * Windows; ioctl(SIOCOUTQ) on Linux; getsockopt(SO_NWRITE) on macOS) plus an
 * OS-reported congestion flag where the platform exposes one (0 otherwise). The
 * app-side queue depth is owned by the core (it is not a platform read). `fd` is
 * the platform socket handle as an intptr-wide token (SOCKET on Windows, int fd on
 * POSIX) the SDK already holds for the game channel. Returns true on success;
 * leaves *out untouched and returns false when the read is unavailable so the core
 * emits no false backlog. */
struct kernel_backlog {
    uint32_t kernel_unsent_bytes;
    uint32_t link_congested; /* 0 = idle/unknown; 1 = OS reports congestion */
};
bool backend_read_kernel_backlog(intptr_t fd, kernel_backlog* out);

/* -- 187 probe-channel RTT ----------------------------------------------------
 * Open/close a dedicated low-rate UDP echo socket to the same server IP on a
 * separate ephemeral port and measure one RTT in microseconds. The handle is
 * opaque to the core. These are the ONLY entry points that touch a real network
 * round-trip; they are bounded by `timeout_us` and never block indefinitely.
 *
 * HK-UNCERTAIN(probe-echo): the server-side UDP echo responder these RTTs require
 * does not yet exist (impl-plan Sequencing §6 / Risks: Dependency 187). Until it
 * ships, the whole probe channel is built only under HK_NET_PROBE_CHANNEL (default
 * OFF) and these functions are documented stubs that report "no data". Do NOT flip
 * the flag ON until the paired server echo milestone lands. */
typedef void* probe_socket_t;
probe_socket_t backend_probe_open(const char* server_ip, uint16_t server_port);
bool           backend_probe_rtt(probe_socket_t sock, uint32_t timeout_us,
                                 uint32_t* out_rtt_us);
void           backend_probe_close(probe_socket_t sock);

} } /* namespace hk::net */

#endif /* HK_NET_BACKEND_H */
