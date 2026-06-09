/*
 * ac/include/horkos/timing/exc_latency.h
 * Role: Signal-159 INT3-decoy dispatch-latency histogram sampler. Declares the
 *       per-machine baseline capture + the live histogram sampler that times the
 *       round-trip from a planted decoy 0xCC to the AC's first-chain VEH.
 * Target platform: Windows (uses the shared first-chain VEH from fault_attribution.h
 *       + a writable+executable AC-owned decoy page; behind HK_PLATFORM_WINDOWS).
 * Interface: implemented by ac/src/timing/exception_latency_win.cpp; aggregated via
 *       timing_signals.h. Uses the pure histogram_mode_count core.
 */

#pragma once

#include <cstdint>

#include "horkos/timing/timing_signals.h"

namespace hk {
namespace timing {

/* Capture the per-machine STARTUP baseline dispatch-latency histogram, BEFORE any
 * third-party module loads (calibration is mandatory — crash reporters / WER / AV add
 * benign latency). Call once early in arm; the live sampler compares against it.
 * Returns true if a baseline was captured. */
bool timing_exc_latency_baseline() noexcept;

/* Signal 159: build the live dispatch-latency histogram and fold in the baseline vs
 * live mode counts (histogram_mode_count). Returns true if a usable histogram was
 * built (decoy armed, at least one round-trip timed). The shared first-chain VEH must
 * be armed (timing_veh_arm) first; the VEH re-continues with DBG_CONTINUE. */
bool timing_sample_exc_latency(timing_exc_latency* out) noexcept;

} // namespace timing
} // namespace hk
