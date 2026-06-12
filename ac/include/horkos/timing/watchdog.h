/*
 * Role: Signal-156 sibling-thread RDTSCP watchdog. Declares the cross-platform
 *       dual-clock sampler: an in-section __rdtscp vs a watchdog-thread __rdtscp read
 *       from a lock-free atomic slot, with the IA32_TSC_AUX core-id cross-check. The
 *       clock + affinity intrinsics route through platform/ (guardrail #1).
 * Target platform: cross (Windows/Linux hard-pin the watchdog; macOS best-effort,
 *       weighted lower server-side per the plan FLAG).
 * Interface: implemented by ac/src/timing/sibling_watchdog.cpp; aggregated via
 *       timing_signals.h. Uses hk::platform::{rdtscp_aux, pin_thread_to_core}.
 */

#pragma once

#include <cstdint>

#include "horkos/timing/timing_signals.h"

namespace hk {
namespace timing {

/* Start the watchdog thread (pinned best-effort to a sibling core) that keeps a
 * lock-free atomic TSC slot fresh. Idempotent; returns true if the watchdog is
 * running. Must be paired with timing_watchdog_stop() before unload. */
bool timing_watchdog_start() noexcept;

/* Stop and join the watchdog thread. Safe to call when not running. */
void timing_watchdog_stop() noexcept;

/* Signal 156: take one paired sample (in-section + sibling slot), fill *out with the
 * two deltas, the two aux core ids, the context-switch flag, and the clamped
 * divergence percent. Returns true if the window was usable (no ctx switch, no known
 * core migration); false discards the window (sensors_ok bit stays clear). */
bool timing_sample_watchdog(timing_watchdog* out) noexcept;

} // namespace timing
} // namespace hk
