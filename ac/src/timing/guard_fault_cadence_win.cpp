/*
 * Role: Signal 161 — guard-fault inter-arrival cadence sensor. Re-arms PAGE_GUARD via
 *       the shared decoy (the read auto-clears PAGE_GUARD; re-arm to keep observing),
 *       timestamps each STATUS_GUARD_PAGE_VIOLATION with QueryPerformanceCounter, and
 *       builds the inter-arrival distribution + faults-per-invocation. A tight,
 *       high-count, uniform-cadence burst is the single-step fingerprint; correlate
 *       with EFLAGS.TF / DR6 read in the same VEH.
 * Target platform: Windows. Active body behind HK_PLATFORM_WINDOWS; off-Windows no-op.
 * Interface: implements ac/include/horkos/timing/guard_cadence.h. Uses the shared
 *       first-chain VEH (decoy_shared.h) and the pure cadence_is_uniform_burst core.
 *
 * SAFETY (plan §161): same VEH re-entrancy discipline as 154; the re-arm count is
 * bounded to avoid livelock under heavy contention; report the histogram, never ban.
 */

#include "horkos/timing/guard_cadence.h"
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

/* Bound on faults provoked per pass so a pathological stepping cadence cannot livelock
 * the sampler re-arming forever. */
constexpr uint32_t kMaxFaultsPerPass = 256u;

/* Bucket a QPC inter-arrival delta. Fixed linear bucketing — the server reads the
 * SHAPE (one concentrated bucket = uniform cadence), not absolute units. */
uint32_t bucket_of(uint64_t qpc_delta) {
    const uint64_t b = qpc_delta >> 6; /* ~64-tick buckets */
    return (b >= HK_TIMING_HIST_BUCKETS) ? (HK_TIMING_HIST_BUCKETS - 1u)
                                         : static_cast<uint32_t>(b);
}

} // namespace

bool timing_sample_guard_cadence(timing_guard_cadence* out) noexcept {
    if (out == nullptr) {
        return false;
    }
    std::memset(out, 0, sizeof(*out));
    if (!::hk::timing::hk_timing_decoy_is_armed()) {
        return false;
    }

    void* decoy = ::hk::timing::hk_timing_decoy_page();
    if (decoy == nullptr) {
        return false;
    }

    long long prev_qpc = 0;
    uint32_t faults = 0u;
    uint32_t tf_or_dr6 = 0u;

    for (uint32_t i = 0u; i < kMaxFaultsPerPass; ++i) {
        const long long before = ::hk::timing::hk_timing_decoy_fault_count();
        /* Provoke one guard fault by reading the decoy; the first-chain VEH timestamps
         * it. The read auto-clears PAGE_GUARD, so re-arm before the next iteration. */
        volatile unsigned char probe = *reinterpret_cast<volatile unsigned char*>(decoy);
        (void)probe;
        const long long after = ::hk::timing::hk_timing_decoy_fault_count();
        const long long this_qpc = ::hk::timing::hk_timing_decoy_last_fault_qpc();

        if (after <= before || this_qpc <= 0) {
            ::hk::timing::hk_timing_decoy_rearm();
            continue;
        }
        if (::hk::timing::hk_timing_decoy_last_tf() != 0) {
            tf_or_dr6 = 1u; /* TF set in the same VEH — stepping correlation */
        }
        if (prev_qpc != 0) {
            const long long delta = this_qpc - prev_qpc;
            if (delta > 0) {
                out->inter_arrival[bucket_of(static_cast<uint64_t>(delta))] += 1u;
            }
        }
        prev_qpc = this_qpc;
        ++faults;
        ::hk::timing::hk_timing_decoy_rearm();
    }

    if (faults == 0u) {
        return false;
    }
    out->fault_count = faults;
    out->eflags_tf_or_dr6 = tf_or_dr6;
    /* min_faults=16, concentration>=80% => a tight uniform-cadence burst. */
    out->uniform_cadence = cadence_is_uniform_burst(
        out->inter_arrival, HK_TIMING_HIST_BUCKETS, faults,
        /*min_faults=*/16u, /*concentration_pct=*/80u) ? 1u : 0u;
    return true;
}

#else /* non-Windows: not-implemented no-op. */

bool timing_sample_guard_cadence(timing_guard_cadence* out) noexcept {
    if (out != nullptr) {
        std::memset(out, 0, sizeof(*out));
    }
    return false;
}

#endif /* HK_PLATFORM_WINDOWS */

} // namespace timing
} // namespace hk
