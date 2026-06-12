/*
 * Role: Signal 189 POSIX half — flow-owner / loopback-interposer sensor. A local
 *       MITM proxy on the game 5-tuple makes the game's own socket connect to a
 *       LOOPBACK/local foreign address instead of the real server IP; that is the
 *       safe, self-observable primary signal and is implemented live here on macOS
 *       (proc_pidfdinfo / PROC_PIDFDSOCKETINFO reads the game socket's OWN foreign
 *       address). Mapping the interposer to a FOREIGN owning PID + image hash
 *       requires a system-wide socket-table walk (Linux sock_diag / macOS
 *       proc_listpids) and is left as a flagged stub (HK-UNCERTAIN). Every OS call
 *       gated behind HK_PLATFORM_LINUX / HK_PLATFORM_MACOS (guardrail #1); compiles
 *       -Wall -Wextra -Werror (guardrail #6).
 * Target platforms: Linux + macOS.
 * Interface: implements `hk::net::probe_flow_owner` (POSIX half) from
 *       `net_probes.h`. Windows half: backends/win/SocketTableProbeWin.cpp.
 */

#include "platform.h"
#include "net_probes.h"

#include <cstdint>

#if defined(HK_PLATFORM_MACOS)
#include <libproc.h>
#include <sys/proc_info.h>
#include <netinet/in.h>
#endif

#if defined(HK_PLATFORM_LINUX) || defined(HK_PLATFORM_MACOS)
#include <unistd.h> /* getpid */
#endif

namespace hk { namespace net {

namespace {

/* The game uplink socket fd the SDK owns; -1 = no uplink yet (no-data). Publishing
 * the fd lets us read its OWN foreign address without a system socket-table walk. */
intptr_t g_game_fd = -1;

void hk_net_clear(hk_net_flow_owner* o)
{
    o->flow_owner_local = 0;
    o->reserved = 0;
    for (int i = 0; i < 32; ++i) {
        o->owner_image_hash[i] = 0;
    }
}

#if defined(HK_PLATFORM_MACOS)
/* True iff an IPv4 address (network byte order) is in 127.0.0.0/8 (loopback). */
bool is_loopback_v4(uint32_t net_order_addr)
{
    const uint32_t host = ntohl(net_order_addr);
    return (host >> 24) == 127u;
}
#endif

} // namespace

void hk_net_set_game_socket(intptr_t fd)
{
    g_game_fd = fd;
}

hk_net_flow_owner probe_flow_owner(void)
{
    hk_net_flow_owner out;
    hk_net_clear(&out);

    if (g_game_fd < 0) {
        return out; /* no uplink -> no-data */
    }

#if defined(HK_PLATFORM_MACOS)
    const int fd = static_cast<int>(g_game_fd);
    struct socket_fdinfo si;
    for (unsigned i = 0; i < sizeof(si); ++i) {
        reinterpret_cast<unsigned char*>(&si)[i] = 0;
    }
    const int n = proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO, &si,
                                 PROC_PIDFDSOCKETINFO_SIZE);
    if (n < static_cast<int>(sizeof(si))) {
        /* Short/failed read -> no-data, never a positive. */
        return out;
    }

    const struct in_sockinfo* in = &si.psi.soi_proto.pri_in;
    if (in->insi_vflag & INI_IPV4) {
        const uint32_t faddr = in->insi_faddr.ina_46.i46a_addr4.s_addr;
        if (is_loopback_v4(faddr)) {
            /* The game flow terminates at loopback -> a local proxy interposes.
             * Low-weight contextual signal (corporate TLS inspection / overlays
             * also do this) — the server escalates only with corroboration; the
             * client never acts on it. */
            out.flow_owner_local = 1;
        }
    }
    /* IPv6 loopback (::1) check intentionally omitted until the IPv6 game-channel
     * path is exercised on-box; absence reads as no-data, never a positive. */
    return out;
#elif defined(HK_PLATFORM_LINUX)
    /* HK-UNCERTAIN(linux-sockdiag): resolving the game flow's owning PID and the
     * interposer image hash on Linux needs a sock_diag (NETLINK_INET_DIAG) query
     * or a /proc/net/{tcp,udp} + /proc/<pid>/fd inode-match walk. The exact
     * inet_diag_req_v2 / inet_diag_msg parse and the privileged /proc walk are
     * UNVERIFIED on the target (Steam Deck / self-hosted) kernels and must not be
     * guessed (guardrail #13). The safe loopback-foreign-address read has no clean
     * non-root userspace equivalent to the macOS proc_pidfdinfo self-read here, so
     * Linux 189 ships no-data until the sock_diag path is written + verified under
     * /tdd with the bypass fixture. Returning the cleared (no-data) result. */
    (void)g_game_fd;
    return out;
#else
    return out;
#endif
}

/* HK-UNCERTAIN(owner-image-hash): owner_image_hash (SHA-256 of the interposing
 * owner image, for the server's signed-known-good allowlist against the §1
 * image_sha256 catalog) requires first resolving the FOREIGN owning PID (the
 * proxy), then reading + hashing its backing image — a privileged cross-process
 * read. Neither the foreign-PID resolution (above) nor the image hash is
 * implemented; the field stays all-zero (= "no interposer image identified"). The
 * loopback flag alone is shipped today; the allowlist enrichment lands with the
 * sock_diag/proc-walk path under /tdd. */

} } // namespace hk::net
