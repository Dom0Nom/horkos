/*
 * Role: Signal 187 cross-platform core — dual-channel probe-RTT divergence sensor.
 *       Owns a dedicated low-rate UDP echo socket to the same server IP on a
 *       separate ephemeral port (raw socket I/O via `net_backend.h`), timestamps
 *       its RTT, and emits the (game_rtt, probe_rtt) pair so the server can spot a
 *       game-port-only throttle (which diverges the two) vs. symmetric path
 *       congestion (which hits both). NO platform header here (guardrail #1).
 * Target platforms: cross (core).
 * Interface: implements the signal-187 half of `hk::net` (`net_timing.h`); uses
 *       `net_backend.h`. Consumed by `net_collect_all()`.
 *
 * Build gating: the whole probe channel is compiled only under HK_NET_PROBE_CHANNEL
 * (default OFF in sdk/CMakeLists.txt). It opens an EXTRA socket and REQUIRES a
 * server-side UDP echo responder that does not yet exist. With the flag OFF this TU
 * still compiles and links — it returns the empty/no-data divergence result so the
 * aggregator builds everywhere — but performs NO network I/O.
 */

#include "horkos/net_timing.h"
#include "net_backend.h"
#include "net_probes.h"

#include <cstdint>

namespace hk { namespace net {

namespace {

/* Game-channel RTT the SDK uplink owner measures from its own send/ack loop and
 * publishes here (microseconds). The core never measures the GAME RTT itself; it
 * only owns the independent PROBE socket. 0 = not published this window. */
uint32_t g_game_rtt_us = 0;

/* Server endpoint for the probe socket, published alongside the game RTT. Empty
 * string disables the probe even when HK_NET_PROBE_CHANNEL is built. */
char     g_server_ip[64] = { 0 };
uint16_t g_server_port = 0;

/* Bounded probe RTT wait. The probe must never stall the AC sample loop. */
constexpr uint32_t kProbeTimeoutUs = 200000; /* 200 ms ceiling */

} // namespace

void hk_net_set_probe_target(const char* server_ip, uint16_t server_port, uint32_t game_rtt_us)
{
    g_game_rtt_us = game_rtt_us;
    g_server_port = server_port;
    /* Bounded copy (no <cstring> dependency in this TU); truncate to fit. */
    int i = 0;
    if (server_ip != nullptr) {
        for (; server_ip[i] != '\0' && i < static_cast<int>(sizeof(g_server_ip)) - 1; ++i) {
            g_server_ip[i] = server_ip[i];
        }
    }
    g_server_ip[i] = '\0';
}

hk_net_rtt_divergence probe_rtt_divergence(void)
{
    hk_net_rtt_divergence out;
    out.game_rtt_us = g_game_rtt_us;
    out.probe_rtt_us = 0; /* no-data until the probe channel both ships and echoes */
    out.same_port_class = 0;
    out.reserved = 0;

#ifdef HK_NET_PROBE_CHANNEL
    if (g_server_ip[0] == '\0' || g_server_port == 0) {
        return out;
    }

    /* HK-UNCERTAIN(probe-echo): the paired server-side UDP echo responder does not
     * yet exist. backend_probe_* therefore report no-data on every platform today;
     * this code path is exercised only so
     * the live wiring drops in without a structural change once the server echo
     * milestone lands. Until then probe_rtt_us stays 0 (no-data), never a
     * fabricated divergence. */
    probe_socket_t sock = backend_probe_open(g_server_ip, g_server_port);
    if (sock != nullptr) {
        uint32_t rtt = 0;
        if (backend_probe_rtt(sock, kProbeTimeoutUs, &rtt)) {
            out.probe_rtt_us = rtt;
        }
        backend_probe_close(sock);
    }
#else
    /* Flag OFF: no extra socket, no I/O. game_rtt_us still rides through (it is
     * SDK-measured, not probe-measured), probe_rtt_us == 0 == no-data. */
    (void)kProbeTimeoutUs;
#endif

    return out;
}

} } // namespace hk::net
