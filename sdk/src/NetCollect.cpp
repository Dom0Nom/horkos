/*
 * Role: The `hk::net` aggregator — folds every available per-signal client probe
 *       (181/182/183/184/185/187/188/189; 186 is server-only) into one
 *       `hk_net_report` per upload window. Starts from the empty/no-data report so
 *       any sensor not built or not implemented on this platform contributes a
 *       neutral sub-result, never a false positive. Platform-neutral: every probe
 *       it calls hides its own OS access behind a backend (guardrail #1); this TU
 *       has NO platform header.
 * Target platforms: cross (core).
 * Interface: implements `hk_net_empty_report()` and `net_collect_all()` from
 *       `horkos/net_timing.h`; calls the per-signal entry points declared in
 *       `net_probes.h`. Consumed by `sdk/src/sdk.cpp` (`horkos_ac_start`).
 */

#include "horkos/net_timing.h"
#include "net_probes.h"

namespace hk { namespace net {

hk_net_report hk_net_empty_report(void)
{
    hk_net_report r;

    r.tx.tx_cadence_skew_ns = HK_NET_TX_SKEW_NO_DATA;
    r.tx.queue_depth_growth = 0;
    r.tx.adapter_is_tunnel = 0;

    r.clk.clock_ratio_ppm = 0;
    r.clk.step_detected = 0;

    r.conn.conn_rtt_us = 0;
    r.conn.conn_retrans = 0;
    r.conn.app_perceived_stall = 0;
    r.conn.reserved = 0;

    r.backlog.app_queue_depth = 0;
    r.backlog.kernel_unsent_bytes = 0;
    r.backlog.link_congested = 0;
    r.backlog.proc_starved = 0;

    r.input.input_frame_anomaly_flags = 0;

    r.rtt.game_rtt_us = 0;
    r.rtt.probe_rtt_us = 0;
    r.rtt.same_port_class = 0;
    r.rtt.reserved = 0;

    r.route.route_identity_hash = 0;
    r.route.route_change_unattested = 0;
    r.route.reserved = 0;

    r.owner.flow_owner_local = 0;
    r.owner.reserved = 0;
    for (int i = 0; i < 32; ++i) {
        r.owner.owner_image_hash[i] = 0;
    }

    return r;
}

hk_net_report net_collect_all(void)
{
    hk_net_report r = hk_net_empty_report();

    /* Each probe owns its no-data fallback, so the aggregator calls them all
     * unconditionally; platforms that do not implement a given signal return the
     * empty sub-result. */
    r.clk     = probe_clock_drift();      /* 182 */
    r.backlog = probe_send_backlog();     /* 184 */
    r.rtt     = probe_rtt_divergence();   /* 187 */
    r.tx      = probe_tx_cadence();       /* 181 */
    r.conn    = probe_conn_health();      /* 183 */
    r.input   = probe_input_frames();     /* 185 */
    r.route   = probe_route_integrity();  /* 188 */
    r.owner   = probe_flow_owner();       /* 189 */

    return r;
}

} } // namespace hk::net
