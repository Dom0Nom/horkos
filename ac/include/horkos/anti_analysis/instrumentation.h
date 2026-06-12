/*
 * Role: Signal 194 (dynamic-instrumentation / DBI residency fingerprint)
 *       interface. Declares the per-signal sampler (the C entry point lives in
 *       anti_analysis_signals.h) and the PURE, platform-free decision core that
 *       combines the three sampled observables into a confidence tier. The core
 *       takes already-sampled facts and returns the raw tier the sensor ships;
 *       it has NO platform API and NO I/O, so it is host-unit-tested
 *       (tests/unit/test_anti_analysis_logic.cpp) — the "factor the decision
 *       logic out of the sensor TU into a pure function" requirement (guardrail
 *       #14). The core does not decide a ban: client emits, server decides (and
 *       may override the tier with its allowlists).
 * Target platforms: cross. The pure core compiles everywhere; the sampler body
 *       in InstrumentationResidency.cpp is HK_PLATFORM_*-gated internally
 *       (guardrail #1).
 * Interface: implemented by ac/src/anti_analysis/InstrumentationResidency.cpp
 *       (sampler) + ac/src/anti_analysis/anti_analysis_logic.cpp (pure core);
 *       aggregated via anti_analysis_signals.h.
 */

#pragma once

#include <cstdint>

#include "horkos/anti_analysis/anti_analysis_signals.h"

namespace hk {
namespace anti_analysis {

/* -------------------------------------------------------------------------
 * Signal 194 confidence tiers. The catalog mandates COMBINATION — a single
 * observable is informational only; only the combination escalates.
 * ------------------------------------------------------------------------- */
enum InstrumentationTier : uint32_t {
    HK_AA_INSTR_TIER_NONE = 0u, /* no instrumentation observable present        */
    HK_AA_INSTR_TIER_INFO = 1u, /* exactly one observable — informational only  */
    HK_AA_INSTR_TIER_HIGH = 2u, /* combined observables — high confidence       */
};

/* 194 confidence-tier combiner (PURE). Inputs are the already-sampled
 * observables:
 *   - `unbacked_rx_threads`: count of thread starts in anon-RX, not module-backed.
 *   - `runtime_export_match`: count of modules exporting a framework symbol name.
 *   - `control_port_listener`: 1 if the framework's default control port is
 *     listening in the process tree.
 *   - `jit_module_present`: 1 if a known-JIT module is loaded. This is FP CONTEXT
 *     only (JIT runtimes also create anon-RX threads) and NEVER raises the tier
 *     on its own — it is reported so the server can allowlist, not scored here.
 * Returns HK_AA_INSTR_TIER_HIGH only when at least two DISTINCT observables are
 * present (combination); a single observable is HK_AA_INSTR_TIER_INFO; none is
 * HK_AA_INSTR_TIER_NONE. */
uint32_t instrumentation_confidence_tier(uint32_t unbacked_rx_threads,
                                         uint32_t runtime_export_match,
                                         uint32_t control_port_listener,
                                         uint32_t jit_module_present) noexcept;

} // namespace anti_analysis
} // namespace hk
