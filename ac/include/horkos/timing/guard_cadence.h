/*
 * ac/include/horkos/timing/guard_cadence.h
 * Role: Signal-161 guard-fault inter-arrival cadence sampler. Declares the sampler
 *       that re-arms PAGE_GUARD inside the guard VEH, timestamps each
 *       STATUS_GUARD_PAGE_VIOLATION, and builds the inter-arrival distribution +
 *       EFLAGS.TF/DR6 correlation. A tight uniform-cadence burst is the single-step
 *       fingerprint.
 * Target platform: Windows (shares the first-chain VEH + decoy machinery from
 *       fault_attribution.h; behind HK_PLATFORM_WINDOWS).
 * Interface: implemented by ac/src/timing/guard_fault_cadence_win.cpp; aggregated via
 *       timing_signals.h. Uses the pure cadence_is_uniform_burst core.
 */

#pragma once

#include <cstdint>

#include "horkos/timing/timing_signals.h"

namespace hk {
namespace timing {

/* Signal 161: build the guard-fault inter-arrival histogram for this pass, set the
 * uniform-cadence flag (cadence_is_uniform_burst) and the TF/DR6 correlation bit.
 * Returns true if usable data was captured (decoy armed + at least one fault). The
 * re-arm count inside the guard VEH is bounded to avoid livelock under contention. */
bool timing_sample_guard_cadence(timing_guard_cadence* out) noexcept;

} // namespace timing
} // namespace hk
