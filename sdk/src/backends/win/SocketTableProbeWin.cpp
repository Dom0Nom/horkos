/*
 * sdk/src/backends/win/SocketTableProbeWin.cpp
 * Role: Signal 189 Windows half — loopback/local-proxy interposition (5-tuple
 *       owner) sensor. GetExtendedTcpTable / GetExtendedUdpTable
 *       (TCP/UDP_TABLE_OWNER_PID_ALL) map the game flow to its owning PID + remote
 *       endpoint; flags a loopback/local foreign endpoint and (when resolvable) the
 *       owning image hash. HIGH FP risk (corporate TLS inspection, Steam/Epic
 *       overlay, NetLimiter): flow_owner_local is LOW-WEIGHT, escalated server-side
 *       only with corroboration; the client never acts on it. All Win32 API
 *       confined to this backends/win/ TU (guardrail #1). Usermode; no kernel TU.
 * Target platforms: Windows.
 * Interface: implements `hk::net::probe_flow_owner` (Windows half) from
 *       `net_probes.h`. POSIX half: backends/posix/SocketTableProbePosix.cpp.
 *
 * Cannot be compiled on the macOS dev host; written against the impl-plan +
 * sibling backends/win sources.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

#include "horkos/net_timing.h"
#include "net_probes.h"

#include <cstdint>
#include <cstdlib>

namespace hk { namespace net {

namespace {

/* The game flow's local UDP port (host order) the SDK uplink publishes. We match
 * the owning-PID table row by local port to find the game's own socket and read
 * its remote endpoint. 0 = no uplink yet (no-data). */
uint16_t g_local_port = 0;

bool is_loopback_v4_net(uint32_t net_order_addr)
{
    /* 127.0.0.0/8 in network byte order: low byte (first octet) == 127. */
    return (net_order_addr & 0xFFu) == 127u;
}

} // namespace

void hk_net_set_flow_local_port(uint16_t local_port_host_order)
{
    g_local_port = local_port_host_order;
}

hk_net_flow_owner probe_flow_owner(void)
{
    hk_net_flow_owner out;
    out.flow_owner_local = 0;
    out.reserved = 0;
    for (int i = 0; i < 32; ++i) {
        out.owner_image_hash[i] = 0;
    }

    if (g_local_port == 0) {
        return out;
    }

    /* Size, allocate, then fetch the UDP owner-PID table. The game channel is UDP;
     * the TCP control channel (183) is handled separately. */
    ULONG size = 0;
    DWORD rc = GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET,
                                   UDP_TABLE_OWNER_PID, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        return out; /* no-data */
    }
    auto* buf = static_cast<MIB_UDPTABLE_OWNER_PID*>(std::malloc(size));
    if (buf == nullptr) {
        return out;
    }
    rc = GetExtendedUdpTable(buf, &size, FALSE, AF_INET,
                             UDP_TABLE_OWNER_PID, 0);
    if (rc != NO_ERROR) {
        std::free(buf);
        return out;
    }

    const DWORD want_port = htons(g_local_port); /* table stores port in net order */
    for (DWORD i = 0; i < buf->dwNumEntries; ++i) {
        const MIB_UDPROW_OWNER_PID& row = buf->table[i];
        if (static_cast<DWORD>(row.dwLocalPort) != want_port) {
            continue;
        }
        /* UDP_TABLE_OWNER_PID has no remote endpoint; a connected UDP game socket's
         * remote address is not in this table. The loopback test that DOES work
         * from this table is: is the SAME local port also owned by a DIFFERENT PID
         * bound to loopback (a local proxy relaying our traffic)? That cross-PID
         * loopback owner is the interposer signal. */
        if (is_loopback_v4_net(row.dwLocalAddr) &&
            row.dwOwningPid != GetCurrentProcessId()) {
            out.flow_owner_local = 1;
        }
    }
    std::free(buf);

    /* HK-UNCERTAIN(win-udp-remote-endpoint): UDP_TABLE_OWNER_PID exposes no remote
     * endpoint, so the cleanest "game flow terminates at loopback" test (the game
     * socket's OWN connected foreign address == 127.0.0.1) is not available from
     * this table on Windows the way macOS proc_pidfdinfo gives it (impl-plan
     * Risks: 189 high-FP). The cross-PID-loopback-owner heuristic above is a
     * weaker proxy; confirming the exact interposer-detection table + the
     * owner-image-hash resolution (OpenProcess + QueryFullProcessImageName + SHA-256,
     * a privileged cross-process read) needs on-box verification before it is
     * trusted. owner_image_hash stays all-zero (no interposer image identified)
     * until that lands under /tdd; the server allowlist against the §1 image_sha256
     * catalog is a no-op until then. */
    return out;
}

} } // namespace hk::net
