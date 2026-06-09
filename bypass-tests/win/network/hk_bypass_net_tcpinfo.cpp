/*
 * bypass-tests/win/network/hk_bypass_net_tcpinfo.cpp
 * Role: network-anomaly TCP_INFO merge-gate bypass test (signal 183) [disabled].
 *       When enabled: a selective UDP-drop lag-switch leaves kernel TCP_INFO healthy
 *       (low RTT/retrans on the TCP control channel) while the app perceives a UDP
 *       stall — the contradiction the ConnHealthProbe captures. A genuinely
 *       congested link raises TCP_INFO too (no contradiction). Compiled now for the
 *       merge gate (guardrail #12).
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: drives hk::net::probe_conn_health (TcpInfoProbeWin.cpp).
 */
#include <cstdio>
#ifndef HK_NET_BYPASS_ENABLED
int main(void) {
    std::printf("DISABLED: net_tcpinfo activates with the SIO_TCP_INFO read path + "
                "the selective-UDP-drop fixture.\n");
    return 0;
}
#else
int main(void) {
    std::printf("net_tcpinfo: SIO_TCP_INFO contradiction fixture not yet implemented.\n");
    return 1;
}
#endif
