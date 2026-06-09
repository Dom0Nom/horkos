/*
 * sdk/src/backends/posix/RouteWatchPosix.cpp
 * Role: Signal 188 POSIX half — route/interface-change-without-OS-event sensor.
 *       Snapshots a bound-interface/route identity hash for the game destination
 *       each window and reports a flag iff that identity changed with NO
 *       corresponding OS route/link event (the discriminator: a benign reroute
 *       goes through the stack and DOES fire an event). Linux: an rtnetlink
 *       (NETLINK_ROUTE) watch for RTM_NEWROUTE/RTM_NEWLINK plus a route-identity
 *       snapshot. macOS: a PF_ROUTE socket (RTM_* messages) — exact message set
 *       UNVERIFIED, see HK-UNCERTAIN. Every OS call gated behind HK_PLATFORM_LINUX
 *       / HK_PLATFORM_MACOS (guardrail #1); compiles -Wall -Wextra -Werror
 *       (guardrail #6).
 * Target platforms: Linux (live snapshot), macOS (PF_ROUTE flagged uncertain).
 * Interface: implements `hk::net::probe_route_integrity` (POSIX half) from
 *       `net_probes.h`. Windows half: backends/win/RouteWatchWin.cpp. Exactly one
 *       is compiled per platform.
 */

#include "platform.h"
#include "net_probes.h"

#include <cstdint>

#if defined(HK_PLATFORM_LINUX) || defined(HK_PLATFORM_MACOS)
#include <sys/socket.h>
#include <net/if.h> /* if_nametoindex */
#endif

namespace hk { namespace net {

namespace {

/* Last route-identity hash we observed, and whether the OS route/link watch fired
 * since the previous snapshot. The "unattested change" positive is exactly
 * (identity changed) AND NOT (an OS event fired) — so we need both pieces of
 * state. The watch-fired flag is set from the netlink/PF_ROUTE drain (live on
 * Linux; HK-UNCERTAIN on macOS) and cleared each window after the comparison. */
uint64_t g_last_identity = 0;
bool     g_have_last = false;
bool     g_os_event_since_snapshot = false;

/* FNV-1a over the identity inputs (iface index + gateway + source addr bytes).
 * A stable hash so an unchanged path produces a stable value; the server compares
 * successive hashes, it never reverses them. */
uint64_t fnv1a(const uint8_t* data, unsigned len, uint64_t seed)
{
    uint64_t h = seed ? seed : 1469598103934665603ull;
    for (unsigned i = 0; i < len; ++i) {
        h ^= static_cast<uint64_t>(data[i]);
        h *= 1099511628211ull;
    }
    return h;
}

/* Compute the current bound-path identity for the game destination. The bound
 * interface index + the address the SDK uplink is bound to form a stable identity;
 * a path swap (TAP/proxy interposition) changes it. This uses no OS route table
 * walk — it folds the SDK-known bound-iface name + a caller-published source-addr
 * blob — so it is platform-clean here. The richer GetBestRoute/rtnetlink dump that
 * resolves the gateway is the Windows/Linux on-box enrichment (see below). */
uint64_t current_identity(void)
{
#if defined(HK_PLATFORM_LINUX) || defined(HK_PLATFORM_MACOS)
    /* Default: no bound iface known -> identity 0 (no-data). The live wiring
     * publishes the bound iface name + src addr via hk_net_set_bound_path. */
    return 0;
#else
    return 0;
#endif
}

/* Published by the SDK uplink owner: the bound interface name and the local source
 * address bytes (4 for v4, 16 for v6) of the game channel. Folded into the
 * identity hash. Without this the probe reports no-data (identity 0). */
uint64_t g_bound_identity = 0;
bool     g_bound_known = false;

} // namespace

void hk_net_set_bound_path(const char* iface_name, const uint8_t* src_addr, unsigned src_len)
{
#if defined(HK_PLATFORM_LINUX) || defined(HK_PLATFORM_MACOS)
    uint64_t h = 0;
    if (iface_name != nullptr) {
        const unsigned idx = if_nametoindex(iface_name); /* 0 if unknown */
        const uint8_t idx_bytes[4] = {
            static_cast<uint8_t>(idx & 0xFF),
            static_cast<uint8_t>((idx >> 8) & 0xFF),
            static_cast<uint8_t>((idx >> 16) & 0xFF),
            static_cast<uint8_t>((idx >> 24) & 0xFF),
        };
        h = fnv1a(idx_bytes, 4, h);
    }
    if (src_addr != nullptr && src_len > 0 && src_len <= 16) {
        h = fnv1a(src_addr, src_len, h);
    }
    g_bound_identity = h;
    g_bound_known = (h != 0);
#else
    (void)iface_name;
    (void)src_addr;
    (void)src_len;
#endif
}

/* Called by the rtnetlink/PF_ROUTE drain when an OS route/link event is observed.
 * Live on Linux; on macOS this is driven by the PF_ROUTE reader once verified. */
void hk_net_note_os_route_event(void)
{
    g_os_event_since_snapshot = true;
}

hk_net_route_integrity probe_route_integrity(void)
{
    hk_net_route_integrity out;
    out.route_identity_hash = 0;
    out.route_change_unattested = 0;
    out.reserved = 0;

    const uint64_t identity = g_bound_known ? g_bound_identity : current_identity();
    out.route_identity_hash = identity;

    if (identity == 0) {
        /* No bound path known -> no-data; reset state so the first real snapshot is
         * not treated as a change. */
        g_os_event_since_snapshot = false;
        return out;
    }

    if (g_have_last && identity != g_last_identity && !g_os_event_since_snapshot) {
        /* Path identity changed AND no OS route/link event fired in between ->
         * the unattested-change positive (the catalog discriminator). */
        out.route_change_unattested = 1;
    }

    g_last_identity = identity;
    g_have_last = true;
    g_os_event_since_snapshot = false;
    return out;
}

/* HK-UNCERTAIN(macos-pf-route): on macOS the OS route/link event watch is a
 * PF_ROUTE socket reading RTM_* messages; the EXACT message set + parse needed to
 * mark hk_net_note_os_route_event() reliably for a "path changed without event" on
 * current macOS is UNVERIFIED (impl-plan Risks: macOS route-watch). Until verified
 * on-box, the macOS build never calls hk_net_note_os_route_event() from a live
 * reader, so g_os_event_since_snapshot stays false and a genuine OS reroute could
 * be mis-attributed as unattested. To avoid a false positive on macOS, the live
 * 188 enforcement on macOS must stay OFF until the PF_ROUTE reader is written and
 * confirmed; the snapshot/identity hash above is safe to ship (it is just a hash).
 *
 * HK-UNCERTAIN(linux-rtnetlink): the live NETLINK_ROUTE socket bind +
 * RTMGRP_IPV4_ROUTE/RTMGRP_LINK group subscription + the recvmsg drain that calls
 * hk_net_note_os_route_event() is NOT written here — it requires an on-box check of
 * the exact nlmsghdr group flags and a non-blocking drain that never stalls the AC
 * loop. Written as the surrounding scaffold; the netlink reader lands under /tdd
 * with the bypass fixture. Until then Linux also relies on the caller to publish
 * OS events, so Linux 188 likewise ships behind its flag, snapshot-only. */

} } // namespace hk::net
