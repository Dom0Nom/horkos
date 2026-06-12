/*
 * Role: Internal per-signal probe entry points the `net_collect_all()` aggregator
 *       (NetCollect.cpp) calls. Each is implemented by exactly one core or backend
 *       TU and returns its signal's fixed POD sub-result in the "no data / clean"
 *       state when its sensor is unavailable or not built on this platform. NOT a
 *       public header (those POD types live in `horkos/net_timing.h`); NO platform
 *       headers here (guardrail #1).
 * Target platforms: all (declaration only).
 * Interface: declares the probe entry points implemented by
 *       ClockDomainProbe.cpp (182), SendBacklogProbe.cpp (184), ProbeChannel.cpp
 *       (187), and the per-platform backends under backends/{win,posix}/ (181/183/
 *       185/188/189). Consumed by NetCollect.cpp.
 */

#ifndef HK_NET_PROBES_H
#define HK_NET_PROBES_H

#include "horkos/net_timing.h"

namespace hk { namespace net {

/* Cross-platform cores. */
hk_net_clock_drift  probe_clock_drift(void);   /* 182 — ClockDomainProbe.cpp  */
hk_net_send_backlog probe_send_backlog(void);  /* 184 — SendBacklogProbe.cpp  */
hk_net_rtt_divergence probe_rtt_divergence(void); /* 187 — ProbeChannel.cpp   */

/* Per-platform backends (Windows reference + POSIX halves). Each returns the
 * empty/no-data sub-result on the platforms where it is not implemented, so the
 * aggregator can call all of them unconditionally. */
hk_net_tx_cadence            probe_tx_cadence(void);     /* 181 — Windows only */
hk_net_conn_health           probe_conn_health(void);    /* 183 — Win + POSIX */
hk_net_input_frame_coherence probe_input_frames(void);   /* 185 — Windows only */
hk_net_route_integrity       probe_route_integrity(void);/* 188 — Win + POSIX */
hk_net_flow_owner            probe_flow_owner(void);     /* 189 — Win + POSIX */

} } /* namespace hk::net */

#endif /* HK_NET_PROBES_H */
