/*
 * ac/include/horkos/timing/clock_consistency.h
 * Role: Signal-157 KUSER_SHARED_DATA vs time-API ratio sampler. Declares the
 *       shared-page-vs-API clock-consistency sampler that reads the documented
 *       read-only user-mode page at 0x7FFE0000 and compares advance ratios against
 *       GetTickCount64 / QPC / GetSystemTimePreciseAsFileTime over the same window.
 * Target platform: Windows only (the fixed KUSER_SHARED_DATA mapping is Win-specific;
 *       the entire .cpp body is behind HK_PLATFORM_WINDOWS).
 * Interface: implemented by ac/src/timing/shared_data_clock_win.cpp; aggregated via
 *       timing_signals.h.
 */

#pragma once

#include <cstdint>

#include "horkos/timing/timing_signals.h"

namespace hk {
namespace timing {

/* Signal 157: sample the shared-page deltas and the API deltas over one window into
 * *out, with the parts-per-million directional drift folded in. `wine_vm_ctx_tag`
 * carries the already-determined Wine/Proton/VM context (1 = tagged) so the server
 * suppresses the expected drift there; the sampler does not re-detect it. Returns
 * true on a usable window (non-zero API deltas), false otherwise. */
bool timing_sample_clock_consistency(timing_clock_consistency* out,
                                     uint32_t wine_vm_ctx_tag) noexcept;

} // namespace timing
} // namespace hk
