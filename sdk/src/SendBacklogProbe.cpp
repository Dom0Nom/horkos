/*
 * sdk/src/SendBacklogProbe.cpp
 * Role: Signal 184 cross-platform core — held-uplink / send-backlog sensor. Pairs
 *       the app-side send-ring depth (owned by the SDK uplink, set via
 *       hk_net_set_uplink_state) with the kernel's unsent-byte count read through
 *       `net_backend.h`, plus an OS congestion flag and a scheduler-starvation
 *       cross-check (FP gate: a CPU-starved send thread must not read as a held
 *       uplink). Ships both numbers raw; the server decides. NO platform header
 *       here (guardrail #1).
 * Target platforms: cross (core).
 * Interface: implements the signal-184 half of `hk::net` (`net_timing.h`); uses
 *       `net_backend.h`. Consumed by `net_collect_all()`.
 */

#include "horkos/net_timing.h"
#include "net_backend.h"
#include "net_probes.h"

#include <cstdint>

namespace hk { namespace net {

namespace {

/* Uplink state the SDK's game-channel owner publishes each window. Default state
 * has no socket (fd == -1), so the probe reports app-queue 0 / kernel no-data
 * until the live uplink wires itself in (a later /tdd integration). This is the
 * seam by which the core gets the two numbers it can know without an OS call (the
 * app-side ring depth + the socket handle) without itself touching the OS. */
struct UplinkState {
    intptr_t fd;            /* platform socket token; -1 = no uplink yet */
    uint32_t app_queue_depth;
    uint32_t proc_starved;  /* 1 if the send thread is scheduler-starved this window */
};

UplinkState g_uplink = { static_cast<intptr_t>(-1), 0u, 0u };

} // namespace

/* Published by the SDK uplink owner once per window before net_collect_all(). The
 * core never derives these from an OS API itself — guardrail #1 keeps the socket
 * read in the backend; the app-ring depth and starvation flag are SDK-internal
 * bookkeeping, not OS reads. */
void hk_net_set_uplink_state(intptr_t fd, uint32_t app_queue_depth, uint32_t proc_starved)
{
    g_uplink.fd = fd;
    g_uplink.app_queue_depth = app_queue_depth;
    g_uplink.proc_starved = proc_starved;
}

hk_net_send_backlog probe_send_backlog(void)
{
    hk_net_send_backlog out;
    out.app_queue_depth = g_uplink.app_queue_depth;
    out.kernel_unsent_bytes = 0;
    out.link_congested = 0;
    out.proc_starved = g_uplink.proc_starved;

    if (g_uplink.fd == static_cast<intptr_t>(-1)) {
        /* No live uplink yet -> kernel side is no-data; app_queue_depth is
         * whatever the SDK published (0 by default). Never a positive. */
        return out;
    }

    kernel_backlog kb;
    if (backend_read_kernel_backlog(g_uplink.fd, &kb)) {
        out.kernel_unsent_bytes = kb.kernel_unsent_bytes;
        out.link_congested = kb.link_congested;
    }
    /* If the read failed, kernel_unsent_bytes stays 0 (no-data); the server sees
     * app_queue_depth without a kernel counterpart and treats it as inconclusive,
     * never a held-uplink verdict. */

    return out;
}

} } // namespace hk::net
