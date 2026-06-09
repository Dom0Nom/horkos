/*
 * tests/unit/test_net_collect.cpp
 * Role: Host unit test for the network-anomaly cross-platform cores + aggregator
 *       (sdk/src/ClockDomainProbe.cpp signal 182, SendBacklogProbe.cpp 184,
 *       ProbeChannel.cpp 187, NetCollect.cpp aggregator). The cores dispatch their
 *       OS reads through the `net_backend.h` seam and the per-platform probe entry
 *       points in `net_probes.h`; this test supplies FAKE implementations of both
 *       seams in-TU, so the platform-free cores link and run host-side with NO
 *       platform header and NO OS call (guardrail #4). Proves: the clock-drift core
 *       converts a known monotonic/realtime rate ratio into the expected ppm and
 *       flags a discrete step; the backlog core pairs app-queue vs kernel-unsent;
 *       the empty report carries the 181 no-data sentinel; the aggregator folds
 *       every sub-result without fabricating a positive.
 * Target platforms: host (CI). The Windows/POSIX OS-read backends are NOT built
 *       here — their probe symbols are faked below (guardrail #4).
 */

#include "horkos/net_timing.h"
#include "net_backend.h"
#include "net_probes.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

// ---------------------------------------------------------------------------
// Fake `net_backend.h` seam. The clock core pulls a sequence of paired reads;
// we serve a programmed queue so a known rate ratio + step are reproducible.
// ---------------------------------------------------------------------------
namespace {

std::vector<hk::net::clock_sample> g_clock_queue;
size_t                             g_clock_idx = 0;

hk::net::kernel_backlog g_backlog = {0u, 0u};
bool                    g_backlog_ok = false;

} // namespace

namespace hk { namespace net {

bool backend_read_clock_pair(clock_sample* out)
{
    if (out == nullptr || g_clock_idx >= g_clock_queue.size()) {
        return false;
    }
    *out = g_clock_queue[g_clock_idx++];
    return true;
}

bool backend_read_kernel_backlog(intptr_t fd, kernel_backlog* out)
{
    (void)fd;
    if (out == nullptr || !g_backlog_ok) {
        return false;
    }
    *out = g_backlog;
    return true;
}

probe_socket_t backend_probe_open(const char*, uint16_t) { return nullptr; }
bool backend_probe_rtt(probe_socket_t, uint32_t, uint32_t* r)
{
    if (r != nullptr) { *r = 0; }
    return false;
}
void backend_probe_close(probe_socket_t) {}

// Fake per-platform probe entry points (181/183/185/188/189) — host build has no
// OS-read backend, so they return the empty/no-data sub-result, exactly as the
// real backends do on a platform where they are unavailable.
hk_net_tx_cadence probe_tx_cadence(void)
{
    hk_net_tx_cadence o;
    o.tx_cadence_skew_ns = HK_NET_TX_SKEW_NO_DATA;
    o.queue_depth_growth = 0;
    o.adapter_is_tunnel = 0;
    return o;
}
hk_net_conn_health probe_conn_health(void)
{
    hk_net_conn_health o = {0u, 0u, 0u, 0u};
    return o;
}
hk_net_input_frame_coherence probe_input_frames(void)
{
    hk_net_input_frame_coherence o = {0u};
    return o;
}
hk_net_route_integrity probe_route_integrity(void)
{
    hk_net_route_integrity o = {0ull, 0u, 0u};
    return o;
}
hk_net_flow_owner probe_flow_owner(void)
{
    hk_net_flow_owner o;
    o.flow_owner_local = 0;
    o.reserved = 0;
    for (int i = 0; i < 32; ++i) { o.owner_image_hash[i] = 0; }
    return o;
}

// The send-backlog core publishes uplink state through this symbol (defined in
// SendBacklogProbe.cpp); declare it so the test can drive it.
void hk_net_set_uplink_state(intptr_t fd, uint32_t app_queue_depth, uint32_t proc_starved);

} } // namespace hk::net

using namespace hk::net;

namespace {

clock_sample mk(uint64_t mono, uint64_t real)
{
    clock_sample s;
    s.mono_ns = mono;
    s.real_ns = real;
    return s;
}

void reset_clock(std::vector<clock_sample> q)
{
    g_clock_queue = std::move(q);
    g_clock_idx = 0;
}

} // namespace

TEST(NetClockDrift, NoDriftYieldsNearZeroPpm)
{
    // Both clocks advance 1:1 over 8 samples spaced 10ms.
    std::vector<clock_sample> q;
    for (int i = 0; i < 8; ++i) {
        const uint64_t t = static_cast<uint64_t>(i) * 10'000'000ull;
        q.push_back(mk(t, t));
    }
    reset_clock(q);
    const hk_net_clock_drift d = probe_clock_drift();
    EXPECT_NEAR(d.clock_ratio_ppm, 0, 2);
    EXPECT_EQ(d.step_detected, 0u);
}

TEST(NetClockDrift, ScaledClockYieldsExpectedPpm)
{
    // Realtime runs 1000 ppm FAST relative to monotonic: real_span/mono_span = 1.001.
    std::vector<clock_sample> q;
    uint64_t mono = 0, real = 0;
    for (int i = 0; i < 8; ++i) {
        q.push_back(mk(mono, real));
        mono += 10'000'000ull;          // 10 ms monotonic
        real += 10'010'000ull;          // 10.01 ms realtime -> +1000 ppm
    }
    reset_clock(q);
    const hk_net_clock_drift d = probe_clock_drift();
    EXPECT_NEAR(d.clock_ratio_ppm, 1000, 5);
}

TEST(NetClockDrift, DiscreteStepIsFlagged)
{
    // Smooth 1:1 except one interval where realtime jumps (an NTP-like step).
    std::vector<clock_sample> q;
    uint64_t mono = 0, real = 0;
    for (int i = 0; i < 8; ++i) {
        q.push_back(mk(mono, real));
        mono += 10'000'000ull;
        real += (i == 4) ? 30'000'000ull : 10'000'000ull; // 3x jump at one interval
    }
    reset_clock(q);
    const hk_net_clock_drift d = probe_clock_drift();
    EXPECT_EQ(d.step_detected, 1u);
}

TEST(NetClockDrift, InsufficientSamplesIsNoData)
{
    reset_clock({mk(0, 0)}); // only one usable read
    const hk_net_clock_drift d = probe_clock_drift();
    EXPECT_EQ(d.clock_ratio_ppm, 0);
    EXPECT_EQ(d.step_detected, 0u);
}

TEST(NetBacklog, NoUplinkIsNoData)
{
    hk_net_set_uplink_state(static_cast<intptr_t>(-1), 0, 0);
    g_backlog_ok = false;
    const hk_net_send_backlog b = probe_send_backlog();
    EXPECT_EQ(b.app_queue_depth, 0u);
    EXPECT_EQ(b.kernel_unsent_bytes, 0u);
}

TEST(NetBacklog, HeldUplinkPairsAppQueueAgainstIdleKernel)
{
    // App ring rising while the kernel reports ~0 unsent and no congestion: the
    // held-uplink contradiction the server scores (the core only pairs the two).
    hk_net_set_uplink_state(static_cast<intptr_t>(5), /*app_queue=*/8192, /*starved=*/0);
    g_backlog = {0u, 0u};
    g_backlog_ok = true;
    const hk_net_send_backlog b = probe_send_backlog();
    EXPECT_EQ(b.app_queue_depth, 8192u);
    EXPECT_EQ(b.kernel_unsent_bytes, 0u);
    EXPECT_EQ(b.link_congested, 0u);
    EXPECT_EQ(b.proc_starved, 0u);
}

TEST(NetEmptyReport, CarriesTxNoDataSentinel)
{
    const hk_net_report r = hk_net_empty_report();
    EXPECT_EQ(r.tx.tx_cadence_skew_ns, HK_NET_TX_SKEW_NO_DATA);
    EXPECT_EQ(r.clk.clock_ratio_ppm, 0);
    EXPECT_EQ(r.input.input_frame_anomaly_flags, 0u);
    EXPECT_EQ(r.route.route_change_unattested, 0u);
    EXPECT_EQ(r.owner.flow_owner_local, 0u);
    for (int i = 0; i < 32; ++i) {
        EXPECT_EQ(r.owner.owner_image_hash[i], 0u);
    }
}

TEST(NetCollectAll, FoldsEveryProbeWithoutFabricatingPositive)
{
    // 1:1 clocks, no uplink -> the aggregate carries the no-data sub-results from
    // the faked platform probes and the computed (near-zero) clock drift; no flag.
    std::vector<clock_sample> q;
    for (int i = 0; i < 4; ++i) {
        const uint64_t t = static_cast<uint64_t>(i) * 10'000'000ull;
        q.push_back(mk(t, t));
    }
    reset_clock(q);
    hk_net_set_uplink_state(static_cast<intptr_t>(-1), 0, 0);
    g_backlog_ok = false;

    const hk_net_report r = net_collect_all();
    EXPECT_EQ(r.tx.tx_cadence_skew_ns, HK_NET_TX_SKEW_NO_DATA);
    EXPECT_NEAR(r.clk.clock_ratio_ppm, 0, 2);
    EXPECT_EQ(r.route.route_change_unattested, 0u);
    EXPECT_EQ(r.owner.flow_owner_local, 0u);
    EXPECT_EQ(r.input.input_frame_anomaly_flags, 0u);
}
