/*
 * Role: Signal-162 CPUID per-leaf latency-fan sampler. Declares the cross-arch
 *       sampler that times __cpuidex across a fixed leaf sweep with RDTSCP+LFENCE
 *       fences and emits a per-leaf latency vector. Bare-metal baselines are near-flat;
 *       selectively-emulated VMM leaves spike.
 * Target platform: cross (x86 only). The core is cross-arch-declared but the sweep is
 *       #if defined(HK_ARCH_X86_64)-gated inside the .cpp; on ARM macOS the sampler
 *       returns false (HK_TIMING_OK_CPUID stays clear).
 * Interface: implemented by ac/src/timing/cpuid_leaf_fan_win.cpp (named _win for the
 *       primary target but compiled cross-platform); aggregated via timing_signals.h.
 *       Uses the pure cpuid_fan_spread core. Strictly a VM-context tag combined with
 *       signal 155 + hv-present server-side — never standalone (VBS on Win11 fans too).
 */

#pragma once

#include <cstdint>

#include "horkos/timing/timing_signals.h"

namespace hk {
namespace timing {

/* Signal 162: time the fixed leaf sweep into *out (per-leaf cycles + the swept leaf
 * ids + the flat baseline). Returns true on x86 where the sweep ran; false on non-x86
 * (HK_TIMING_OK_CPUID stays clear, server reads it as not-collected, never "flat"). */
bool timing_sample_cpuid_fan(timing_cpuid_fan* out) noexcept;

} // namespace timing
} // namespace hk
