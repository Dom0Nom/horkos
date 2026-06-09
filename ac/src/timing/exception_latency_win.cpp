/*
 * ac/src/timing/exception_latency_win.cpp
 * Role: Signal 159 — INT3-decoy dispatch-latency histogram sensor. Plants a known 0xCC
 *       at a deliberately-executed decoy address (a writable+executable AC-owned page),
 *       times the round-trip into the AC's first-chain VEH with QueryPerformanceCounter
 *       (+ rdtscp), and builds a latency histogram compared against a per-machine
 *       baseline captured at startup before any third-party module loads. The server
 *       flags multi-modal / step-change shifts AFTER baseline (crash reporters / WER /
 *       .NET / AV add benign latency, so calibration is mandatory).
 * Target platform: Windows. Active body behind HK_PLATFORM_WINDOWS; off-Windows no-op.
 * Interface: implements ac/include/horkos/timing/exc_latency.h. Uses the shared
 *       first-chain VEH (fault_attribution.h / decoy_shared.h) and the pure
 *       histogram_mode_count core.
 *
 * SAFETY (plan §159, guardrail #9): the decoy executes intentionally; the planted byte
 * lives in an AC-owned RWX page and is NEVER in the GAME hot loop. The VEH re-continues
 * with DBG_CONTINUE (EXCEPTION_CONTINUE_EXECUTION here) after observing.
 */

#include "horkos/timing/exc_latency.h"
#include "horkos/timing/fault_attribution.h"
#include "horkos/timing/timing_signals.h"

#include <cstring>

namespace hk {
namespace timing {

#if defined(HK_PLATFORM_WINDOWS)

} // namespace timing
} // namespace hk

#include <windows.h>

#include "decoy_shared.h"

namespace hk {
namespace timing {

namespace {

uint32_t  g_baseline_modes = 0u;
bool      g_baseline_captured = false;

/* Bucket a QPC-delta latency into one of HK_TIMING_HIST_BUCKETS. The bucket width is a
 * fixed small power-of-two of QPC ticks; the server cares about modality/tail shape,
 * not absolute units, so a fixed linear bucketing is sufficient and stable. */
uint32_t bucket_of(uint64_t qpc_delta) {
    const uint64_t b = qpc_delta >> 4; /* ~16-tick buckets */
    return (b >= HK_TIMING_HIST_BUCKETS) ? (HK_TIMING_HIST_BUCKETS - 1u)
                                         : static_cast<uint32_t>(b);
}

/* Time ONE decoy dispatch round-trip and bucket it. Returns false if the round-trip
 * could not be measured.
 *
 * HK-UNCERTAIN(int3-decoy-exec): deliberately executing a planted 0xCC in an AC-owned
 * RWX page and recovering through the first-chain VEH (which must turn the breakpoint
 * exception into a clean continue without single-stepping over the byte) is delicate:
 * the VEH must distinguish THIS decoy 0xCC from a real breakpoint, advance RIP past the
 * byte (or restore it), and continue — and the exact safe sequence (restore byte vs.
 * RIP+1, interaction with a present debugger that swallows the 0xCC) must be validated
 * on-box. Per guardrail #13 the actual execute-and-recover is NOT performed here; this
 * sampler measures the dispatch latency of the GUARD-PAGE decoy path (already armed and
 * proven by signal 154) as the round-trip proxy, and leaves the literal-0xCC variant as
 * a documented stub. The histogram it builds is real dispatch-latency data; the 0xCC
 * variant is an enhancement gated on the on-box validation above. */
bool time_one_roundtrip(uint64_t* out_delta) {
    void* decoy = ::hk::timing::hk_timing_decoy_page();
    if (decoy == nullptr) {
        return false;
    }
    LARGE_INTEGER t0;
    QueryPerformanceCounter(&t0);

    /* Touch the guarded decoy page to provoke a dispatch into the first-chain VEH; the
     * VEH timestamps the fault. We then read the elapsed QPC from before the access to
     * the VEH's recorded fault time as the dispatch latency. */
    const long long faults_before = ::hk::timing::hk_timing_decoy_fault_count();
    /* Volatile read of the first byte triggers the guard fault (read auto-clears it;
     * the 161 path re-arms). */
    volatile unsigned char probe = *reinterpret_cast<volatile unsigned char*>(decoy);
    (void)probe;
    const long long fault_qpc = ::hk::timing::hk_timing_decoy_last_fault_qpc();
    const long long faults_after = ::hk::timing::hk_timing_decoy_fault_count();

    if (faults_after <= faults_before || fault_qpc <= 0) {
        /* No new fault recorded — re-arm and report this round-trip unmeasured. */
        ::hk::timing::hk_timing_decoy_rearm();
        return false;
    }
    /* Dispatch latency = (VEH fault timestamp) - (pre-access timestamp). */
    const long long delta = fault_qpc - t0.QuadPart;
    ::hk::timing::hk_timing_decoy_rearm();
    if (delta <= 0) {
        return false;
    }
    *out_delta = static_cast<uint64_t>(delta);
    return true;
}

uint32_t build_histogram(uint32_t hist[HK_TIMING_HIST_BUCKETS], uint32_t samples) {
    std::memset(hist, 0, sizeof(uint32_t) * HK_TIMING_HIST_BUCKETS);
    uint32_t measured = 0u;
    for (uint32_t i = 0u; i < samples; ++i) {
        uint64_t d = 0u;
        if (time_one_roundtrip(&d)) {
            hist[bucket_of(d)] += 1u;
            ++measured;
        }
    }
    return measured;
}

} // namespace

bool timing_exc_latency_baseline() noexcept {
    if (!::hk::timing::hk_timing_decoy_is_armed()) {
        return false; /* the shared VEH/decoy must be armed first */
    }
    uint32_t hist[HK_TIMING_HIST_BUCKETS];
    const uint32_t measured = build_histogram(hist, /*samples=*/64u);
    if (measured == 0u) {
        return false;
    }
    /* min_count = 2 is the noise floor for a 64-sample baseline. */
    g_baseline_modes = histogram_mode_count(hist, HK_TIMING_HIST_BUCKETS, 2u);
    g_baseline_captured = true;
    return true;
}

bool timing_sample_exc_latency(timing_exc_latency* out) noexcept {
    if (out == nullptr) {
        return false;
    }
    std::memset(out, 0, sizeof(*out));
    if (!::hk::timing::hk_timing_decoy_is_armed()) {
        return false;
    }
    const uint32_t measured = build_histogram(out->hist, /*samples=*/64u);
    if (measured == 0u) {
        return false;
    }
    out->live_modes = histogram_mode_count(out->hist, HK_TIMING_HIST_BUCKETS, 2u);
    out->baseline_modes = g_baseline_captured ? g_baseline_modes : 0u;
    return true;
}

#else /* non-Windows: not-implemented no-ops. */

bool timing_exc_latency_baseline() noexcept { return false; }

bool timing_sample_exc_latency(timing_exc_latency* out) noexcept {
    if (out != nullptr) {
        std::memset(out, 0, sizeof(*out));
    }
    return false;
}

#endif /* HK_PLATFORM_WINDOWS */

} // namespace timing
} // namespace hk
