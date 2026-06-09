/*
 * ac/include/horkos/timing/fault_attribution.h
 * Role: Signal-154 VEH fault-attribution sampler + the self-armed decoy PAGE_GUARD
 *       arming/teardown. Declares the install/sample/teardown surface; the body reads
 *       the first-chain VEH's CONTEXT.Dr6/Dr7 and resolves the dispatch-frame return
 *       address to an owning image, attributing the fault RESOLVER.
 * Target platform: Windows (the VEH + PAGE_GUARD machinery is Win-only and behind
 *       HK_PLATFORM_WINDOWS in the .cpp; on other hosts the sampler is a
 *       "not-implemented" no-op that leaves its sensors_ok bit clear).
 * Interface: implemented by ac/src/timing/veh_fault_attribution_win.cpp; aggregated
 *       via timing_signals.h. The shared first-chain VEH install/teardown helper here
 *       is reused by signals 159 and 161 (same decoy machinery).
 */

#pragma once

#include <cstdint>

#include "horkos/timing/timing_signals.h"

namespace hk {
namespace timing {

/* Install the AC's first-in-chain Vectored Exception Handler and arm the self-owned
 * decoy PAGE_GUARD region the 154/159/161 samplers observe. Idempotent; returns true
 * if the handler is installed (or already was). On non-Windows hosts returns false
 * (sampler stays a no-op). MUST be paired with timing_veh_teardown() before unload —
 * a dangling first-chain VEH after the AC image is freed faults the dispatcher. */
bool timing_veh_arm() noexcept;

/* Remove the first-chain VEH and disarm/free the decoy region. Safe to call when not
 * armed. */
void timing_veh_teardown() noexcept;

/* Signal 154: sample the most recent first-chain decoy fault attribution into *out.
 * Returns true if a usable attribution was captured this pass (sets HK_TIMING_OK_VEH
 * upstream), false if nothing faulted the decoy or the machinery is unavailable.
 * The handler itself is allocation-free and re-entrancy-safe (plan §154 safety); this
 * reader only copies the last captured snapshot — it never runs in VEH context. */
bool timing_sample_veh_attrib(timing_veh_attrib* out) noexcept;

} // namespace timing
} // namespace hk
