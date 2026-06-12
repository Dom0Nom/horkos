/*
 * Role: The timing-domain aggregator. Zero-initializes a timing_report, runs each
 *       available per-signal sampler (154/156/157/159/161/162) and folds the kernel
 *       ring (155), setting the matching SensorOk bit per sampler that produced a
 *       usable result. Pure glue — every OS call lives in the per-signal TUs behind
 *       their platform guard; a sampler that cannot run on this host leaves its bit
 *       clear so the server never reads a zeroed result as "clean".
 * Target platforms: all (cross-platform orchestration; the Windows-only samplers
 *       compile to no-ops off-Windows and report not-collected).
 * Interface: implements timing_collect_all() in ac/include/horkos/timing/timing_signals.h.
 */

#include "horkos/timing/timing_signals.h"
#include "horkos/timing/fault_attribution.h"
#include "horkos/timing/watchdog.h"
#include "horkos/timing/clock_consistency.h"
#include "horkos/timing/exc_latency.h"
#include "horkos/timing/guard_cadence.h"
#include "horkos/timing/cpuid_fan.h"

#include <cstring>

namespace hk {
namespace timing {

uint32_t timing_collect_all(timing_report* out) noexcept {
    if (out == nullptr) {
        return HK_TIMING_OK_NONE;
    }
    std::memset(out, 0, sizeof(*out));
    uint32_t ok = HK_TIMING_OK_NONE;

    /* 154 — VEH fault attribution. The shared first-chain VEH + decoy are armed/torn
     * down by the orchestrator (arm/teardown), not per-pass; here we only read the
     * last captured attribution. */
    if (timing_sample_veh_attrib(&out->veh)) {
        ok |= HK_TIMING_OK_VEH;
    }

    /* 156 — sibling-thread RDTSCP watchdog. A discarded window returns false and the
     * bit stays clear (the result is not shipped as evidence). */
    if (timing_sample_watchdog(&out->wdog)) {
        ok |= HK_TIMING_OK_WATCHDOG;
    }

    /* 157 — KUSER_SHARED_DATA vs API clock consistency. The Wine/Proton/VM context is
     * passed through as already-tagged; the sampler does not re-detect it.
     * HK-TODO(vm-tag): wire the real wine/VM tag from the context probe once that
     * cross-domain seam exists; pass 0 (untagged) until then so the server applies
     * its own VM suppression. */
    if (timing_sample_clock_consistency(&out->clock, /*wine_vm_ctx_tag=*/0u)) {
        ok |= HK_TIMING_OK_CLOCK;
    }

    /* 159 — INT3-decoy dispatch latency histogram (needs the shared VEH armed). */
    if (timing_sample_exc_latency(&out->exc)) {
        ok |= HK_TIMING_OK_EXC;
    }

    /* 161 — guard-fault inter-arrival cadence (shares the decoy machinery). */
    if (timing_sample_guard_cadence(&out->guard)) {
        ok |= HK_TIMING_OK_GUARD;
    }

    /* 162 — CPUID leaf-fan latency. Returns false on non-x86 (bit stays clear). */
    if (timing_sample_cpuid_fan(&out->cpuid)) {
        ok |= HK_TIMING_OK_CPUID;
    }

    /* 155 — kernel APERF/MPERF-vs-RDTSC skew, folded from the driver ring. */
    if (timing_collect_kernel(&out->kern)) {
        ok |= HK_TIMING_OK_KERNEL;
    }

    out->sensors_ok = ok;
    return ok;
}

} // namespace timing
} // namespace hk
