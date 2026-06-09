/*
 * sdk/include/horkos/net_timing.h
 * Role: Public-internal interface declaring the `hk::net` network-layer-integrity
 *       sensor surface for catalog signals 181-189 (network-anomaly), minus the
 *       server-only 186. One sampler per signal returning a fixed POD result, plus
 *       a `net_collect_all()` aggregator that folds them into a single per-window
 *       `net_report`. Plain C99/C++ POD: NO platform headers here — every OS call
 *       lives in the per-platform `sdk/src/backends/{win,posix}/` implementations
 *       (guardrail #1). The client SHIPS these raw readings; ALL classification and
 *       ban authority is server-side.
 * Target platforms: all (declaration only).
 * Interface: this header IS the `hk::net` sensor surface; the backends under
 *       `sdk/src/backends/{win,posix}/` and the cross-platform cores
 *       (`sdk/src/ClockDomainProbe.cpp`, `SendBacklogProbe.cpp`, `ProbeChannel.cpp`)
 *       implement it; consumed by `sdk/src/sdk.cpp` (`horkos_ac_start`). Field names
 *       map 1:1 onto the `TickPayload` v4 fields in
 *       `server/telemetry/src/schema.rs` (the HTTP/JSON plane — NOT the C99 kernel
 *       ring in `event_schema.h`/`ioctl.h`; no IOCTL/`hk_event_type` change).
 */

#ifndef HORKOS_NET_TIMING_H
#define HORKOS_NET_TIMING_H

#include <stdint.h>

#ifdef __cplusplus
namespace hk {
namespace net {
#endif

/* Sentinel for signal 181 when the NIC/driver does not expose a hardware/kernel
 * TX timestamp: the server treats this skew as "no data", never as a positive. */
#define HK_NET_TX_SKEW_NO_DATA INT64_MIN

/* input_frame_anomaly_flags bit assignments (signal 185), mirrored server-side. */
#define HK_NET_INPUT_NONMONOTONIC   0x1u  /* OS-capture timestamp went backwards   */
#define HK_NET_INPUT_DUPLICATE_TS   0x2u  /* two frames share one capture timestamp*/
#define HK_NET_INPUT_BACKDATED      0x4u  /* frame timestamp predates the window   */
#define HK_NET_INPUT_SYNTHETIC_ORIG 0x8u  /* GetCurrentInputMessageSource: injected
                                           * (SOFT signal — scored, never a verdict)*/

typedef struct hk_net_tx_cadence {         /* signal 181 */
    int64_t  tx_cadence_skew_ns;           /* sustained (qpc_ts - hw_tx_ts) delta, ns;
                                            * HK_NET_TX_SKEW_NO_DATA == unsupported  */
    uint32_t queue_depth_growth;           /* monotone TX-lag growth over window (0=none) */
    uint32_t adapter_is_tunnel;            /* 1 if bound media is tunnel/virtual (FP gate) */
} hk_net_tx_cadence;

typedef struct hk_net_conn_health {        /* signal 183 */
    uint32_t conn_rtt_us;                  /* kernel SmoothedRtt / tcpi_rtt (us)     */
    uint32_t conn_retrans;                 /* RetransmitCount / tcpi_retrans (window)*/
    uint32_t app_perceived_stall;          /* 1 if the app saw a stall this window   */
    uint32_t reserved;
} hk_net_conn_health;

typedef struct hk_net_send_backlog {       /* signal 184 */
    uint32_t app_queue_depth;              /* unsent bytes in the app send ring      */
    uint32_t kernel_unsent_bytes;          /* SIOCOUTQ / SO_NWRITE / ideal-send-backlog */
    uint32_t link_congested;               /* OS-reported congestion (0 = link idle) */
    uint32_t proc_starved;                 /* 1 if scheduler-starved (FP gate)       */
} hk_net_send_backlog;

typedef struct hk_net_clock_drift {        /* signal 182 */
    int32_t  clock_ratio_ppm;              /* sustained monotonic/realtime drift, ppm*/
    uint32_t step_detected;                /* 1 if a discrete (NTP-like) step occurred*/
} hk_net_clock_drift;

typedef struct hk_net_rtt_divergence {     /* signal 187 */
    uint32_t game_rtt_us;
    uint32_t probe_rtt_us;                 /* independent probe-socket RTT, same server IP;
                                            * 0 when HK_NET_PROBE_CHANNEL is OFF      */
    uint32_t same_port_class;              /* 1 if probe shares port-range class (QoS FP)*/
    uint32_t reserved;
} hk_net_rtt_divergence;

typedef struct hk_net_route_integrity {    /* signal 188 */
    uint64_t route_identity_hash;          /* hash of bound-iface idx + gateway + src addr */
    uint32_t route_change_unattested;      /* 1 if path identity changed with NO OS event  */
    uint32_t reserved;
} hk_net_route_integrity;

typedef struct hk_net_flow_owner {         /* signal 189 */
    uint32_t flow_owner_local;             /* 1 if game flow terminates at loopback/local PID*/
    uint32_t reserved;
    uint8_t  owner_image_hash[32];         /* SHA-256 of the interposing owner image, if any */
} hk_net_flow_owner;

typedef struct hk_net_input_frame_coherence { /* signal 185 */
    uint32_t input_frame_anomaly_flags;    /* HK_NET_INPUT_* bitfield                 */
} hk_net_input_frame_coherence;

/* Aggregate -> one network sub-payload per upload window. Signal 186
 * (arrival-cadence) is server-only and absent here. */
typedef struct hk_net_report {
    hk_net_tx_cadence            tx;       /* 181 */
    hk_net_clock_drift           clk;      /* 182 */
    hk_net_conn_health           conn;     /* 183 */
    hk_net_send_backlog          backlog;  /* 184 */
    hk_net_input_frame_coherence input;    /* 185 */
    hk_net_rtt_divergence        rtt;      /* 187 */
    hk_net_route_integrity       route;    /* 188 */
    hk_net_flow_owner            owner;    /* 189 */
} hk_net_report;

/* Zero-initialised report with every signal in its "no data / clean" state:
 * tx skew = HK_NET_TX_SKEW_NO_DATA, all flags 0, hashes 0. The aggregator starts
 * here so an unbuilt/disabled sensor never contributes a false positive. */
hk_net_report hk_net_empty_report(void);

/* Collect every available client probe into one report. Each unavailable sensor
 * leaves its sub-struct in the empty/no-data state. Read-only; never blocks on a
 * network round-trip beyond the bounded probe-socket RTT (signal 187, and only
 * when HK_NET_PROBE_CHANNEL is built). */
hk_net_report net_collect_all(void);

#ifdef __cplusplus
} /* namespace net */
} /* namespace hk */
#endif

#endif /* HORKOS_NET_TIMING_H */
