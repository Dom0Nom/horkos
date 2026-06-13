/*
 * Role: Signal 188 Windows half — route/interface-change-without-OS-event sensor.
 *       Registers NotifyRouteChange2 / NotifyIpInterfaceChange /
 *       NotifyUnicastIpAddressChange (iphlpapi) callbacks and snapshots the
 *       GetBestInterfaceEx result for the game destination each window. The
 *       positive is specifically (path identity changed) AND (no notification
 *       fired) — benign reroutes go through the OS stack and DO fire. The callbacks
 *       run on an OS worker thread, so the snapshot store is mutex-guarded and the
 *       callback never blocks (a THREADING concern, not an IRQL one; usermode,
 *       no kernel TU). All Win32 API confined to this
 *       backends/win/ TU (guardrail #1).
 * Target platforms: Windows.
 * Interface: implements `hk::net::probe_route_integrity` (Windows half) from
 *       `net_probes.h`. POSIX half: backends/posix/RouteWatchPosix.cpp.
 *
 * Cannot be compiled on the macOS dev host; written against
 * sibling backends/win sources.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h> /* NotifyRouteChange2 etc. */
#include <windows.h>

#include "horkos/net_timing.h"
#include "net_probes.h"

#include <cstdint>
#include <mutex>

namespace hk { namespace net {

namespace {

std::mutex             g_mtx;
HANDLE                 g_route_notify = nullptr;
HANDLE                 g_iface_notify = nullptr;
HANDLE                 g_addr_notify = nullptr;
bool                   g_os_event_since_snapshot = false; /* guarded by g_mtx */
uint64_t               g_last_identity = 0;
bool                   g_have_last = false;
SOCKADDR_INET          g_dest = {}; /* game destination, published by the SDK uplink */
bool                   g_have_dest = false;

uint64_t fnv1a(const uint8_t* data, unsigned len, uint64_t seed)
{
    uint64_t h = seed ? seed : 1469598103934665603ull;
    for (unsigned i = 0; i < len; ++i) {
        h ^= static_cast<uint64_t>(data[i]);
        h *= 1099511628211ull;
    }
    return h;
}

/* OS-worker-thread callbacks. They do the MINIMUM — flip a guarded flag — and
 * return immediately (no blocking allowed in an OS-worker callback). */
VOID CALLBACK on_route_change(PVOID, PMIB_IPFORWARD_ROW2, MIB_NOTIFICATION_TYPE)
{
    std::lock_guard<std::mutex> lk(g_mtx);
    g_os_event_since_snapshot = true;
}
VOID CALLBACK on_iface_change(PVOID, PMIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE)
{
    std::lock_guard<std::mutex> lk(g_mtx);
    g_os_event_since_snapshot = true;
}
VOID CALLBACK on_addr_change(PVOID, PMIB_UNICASTIPADDRESS_ROW, MIB_NOTIFICATION_TYPE)
{
    std::lock_guard<std::mutex> lk(g_mtx);
    g_os_event_since_snapshot = true;
}

/* Identity for the game destination: the best-interface index GetBestInterfaceEx
 * resolves for the destination, folded into a stable hash. A path swap changes it. */
uint64_t current_identity()
{
    if (!g_have_dest) {
        return 0;
    }
    DWORD best_if = 0;
    /* GetBestInterfaceEx takes a sockaddr*; SOCKADDR_INET aliases sockaddr. */
    const DWORD rc = GetBestInterfaceEx(
        reinterpret_cast<sockaddr*>(&g_dest), &best_if);
    if (rc != NO_ERROR) {
        return 0;
    }
    const uint8_t idx_bytes[4] = {
        static_cast<uint8_t>(best_if & 0xFF),
        static_cast<uint8_t>((best_if >> 8) & 0xFF),
        static_cast<uint8_t>((best_if >> 16) & 0xFF),
        static_cast<uint8_t>((best_if >> 24) & 0xFF),
    };
    return fnv1a(idx_bytes, 4, 0);
}

} // namespace

/* Publish the game destination and (lazily) register the OS notifications. Called
 * by the SDK uplink owner. Registration is idempotent. */
void hk_net_set_route_dest(const SOCKADDR_INET* dest)
{
    std::lock_guard<std::mutex> lk(g_mtx);
    if (dest != nullptr) {
        g_dest = *dest;
        g_have_dest = true;
    }
    if (g_route_notify == nullptr) {
        /* NotifyRouteChange2 family: AF_UNSPEC watches both v4 and v6. The handle
         * must be deregistered via CancelMibChangeNotify2 at teardown (see
         * hk_net_route_teardown). Return values are checked; a failed registration
         * leaves the handle null and the probe degrades to snapshot-only. */
        (void)NotifyRouteChange2(AF_UNSPEC, on_route_change, nullptr, FALSE,
                                 &g_route_notify);
        (void)NotifyIpInterfaceChange(AF_UNSPEC, on_iface_change, nullptr, FALSE,
                                      &g_iface_notify);
        (void)NotifyUnicastIpAddressChange(AF_UNSPEC, on_addr_change, nullptr, FALSE,
                                           &g_addr_notify);
    }
}

/* Deregister all notifications. MUST be called before unload so no OS-worker
 * callback fires into freed state (the usermode analogue of the kernel teardown
 * rule). CancelMibChangeNotify2 waits for in-flight callbacks to drain. */
void hk_net_route_teardown()
{
    HANDLE r, i, a;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        r = g_route_notify; g_route_notify = nullptr;
        i = g_iface_notify; g_iface_notify = nullptr;
        a = g_addr_notify;  g_addr_notify = nullptr;
    }
    /* Cancel OUTSIDE the lock: CancelMibChangeNotify2 blocks until in-flight
     * callbacks complete, and those callbacks take g_mtx — cancelling under the
     * lock would deadlock. */
    if (r != nullptr) { (void)CancelMibChangeNotify2(r); }
    if (i != nullptr) { (void)CancelMibChangeNotify2(i); }
    if (a != nullptr) { (void)CancelMibChangeNotify2(a); }
}

hk_net_route_integrity probe_route_integrity(void)
{
    hk_net_route_integrity out;
    out.route_identity_hash = 0;
    out.route_change_unattested = 0;
    out.reserved = 0;

    const uint64_t identity = current_identity();
    out.route_identity_hash = identity;

    std::lock_guard<std::mutex> lk(g_mtx);
    if (identity == 0) {
        g_os_event_since_snapshot = false;
        return out;
    }
    if (g_have_last && identity != g_last_identity && !g_os_event_since_snapshot) {
        out.route_change_unattested = 1;
    }
    g_last_identity = identity;
    g_have_last = true;
    g_os_event_since_snapshot = false;
    return out;
}

} } // namespace hk::net
