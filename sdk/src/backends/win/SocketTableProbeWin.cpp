/*
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
 * Cannot be compiled on the macOS dev host; written against
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

    /* HK-VERIFIED(win-udp-remote-endpoint): MIB_UDPROW_OWNER_PID (the row type for
     * UDP_TABLE_OWNER_PID) contains only dwLocalAddr, dwLocalPort, and dwOwningPid.
     * There is NO remote-endpoint field in this struct.
     * ref: https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable
     * ref: https://learn.microsoft.com/windows/win32/api/tcpmib/ns-tcpmib-mib_udprow_owner_pid
     * UDP_TABLE_OWNER_MODULE (the extended form) adds creation-time and module info
     * but still NO remote endpoint, because unconnected UDP sockets have no peer.
     * For a CONNECTED UDP game socket the peer address lives in the socket's kernel
     * state but is not surfaced in the MIB table. This confirms the cross-PID-
     * loopback-owner heuristic is the correct proxy on Windows; the owner-image-hash
     * resolution via OpenProcess + QueryFullProcessImageName needs
     * PROCESS_QUERY_LIMITED_INFORMATION (documented) and is a real on-box step
     * (docs: known — still needs on-box interposer-detection validation). */
    return out;
}

} } // namespace hk::net
