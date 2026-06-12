/*
 * Role: The PURE timing classifier cores declared in timing_signals.h (modality,
 *       cadence, divergence, drift, leaf-fan spread). No platform API, no I/O — these
 *       are the platform-free functions the sampler TUs call, factored out so the
 *       divergence/modality/cadence math is unit-tested host-side without a debugger,
 *       a VM, or any OS hook (tests/unit/test_timing_logic.cpp). NONE decides a ban.
 * Target platforms: all (host-buildable; pure arithmetic over sampled scalars/vectors).
 * Interface: implements the pure cores of ac/include/horkos/timing/timing_signals.h.
 */

#include "horkos/timing/timing_signals.h"

namespace hk {
namespace timing {

uint32_t watchdog_divergence_pct(uint64_t in_section_tsc_delta,
                                 uint64_t watchdog_tsc_delta) noexcept {
    if (in_section_tsc_delta == 0u) {
        return 0u; /* degenerate window — no evidence, never a divide-by-zero spike */
    }
    const uint64_t diff = (watchdog_tsc_delta > in_section_tsc_delta)
                              ? (watchdog_tsc_delta - in_section_tsc_delta)
                              : (in_section_tsc_delta - watchdog_tsc_delta);
    /* Percent, clamped to 1000 so a pathological window cannot overflow the u32
     * field or smear the server's bucketing. */
    const uint64_t pct = (diff * 100u) / in_section_tsc_delta;
    return (pct > 1000u) ? 1000u : static_cast<uint32_t>(pct);
}

bool watchdog_window_usable(uint32_t ctx_switch_seen,
                            uint32_t aux_core_in,
                            uint32_t aux_core_watch) noexcept {
    if (ctx_switch_seen != 0u) {
        return false; /* a scheduler switch corrupts the in-section TSC delta */
    }
    /* aux==0 means "core id unknown" (non-x86 / no TSC_AUX) — that alone must NOT
     * discard the window. Only a KNOWN migration (both non-zero and differing)
     * invalidates the sibling comparison. */
    if (aux_core_in != 0u && aux_core_watch != 0u && aux_core_in != aux_core_watch) {
        return false;
    }
    return true;
}

uint32_t clock_ratio_drift_ppm(uint64_t shared_dt, uint64_t api_dt) noexcept {
    if (api_dt == 0u) {
        return 0u; /* no API advance to ratio against — no evidence */
    }
    /* Magnitude of the directional drift in parts-per-million: |shared - api|/api.
     * Sign is folded away; the server requires the drift to be SUSTAINED across
     * windows before weighting it. Clamp to 1e6 (100%) to bound the field. */
    const uint64_t diff = (shared_dt > api_dt) ? (shared_dt - api_dt) : (api_dt - shared_dt);
    const uint64_t ppm = (diff * 1000000u) / api_dt;
    return (ppm > 1000000u) ? 1000000u : static_cast<uint32_t>(ppm);
}

uint32_t histogram_mode_count(const uint32_t* hist, uint32_t buckets,
                              uint32_t min_count) noexcept {
    if (hist == nullptr || buckets == 0u) {
        return 0u;
    }
    uint32_t modes = 0u;
    for (uint32_t i = 0u; i < buckets; ++i) {
        if (hist[i] < min_count) {
            continue; /* below the noise floor — not a peak */
        }
        const bool left_ok  = (i == 0u) || (hist[i] > hist[i - 1u]);
        const bool right_ok = (i + 1u == buckets) || (hist[i] > hist[i + 1u]);
        if (left_ok && right_ok) {
            ++modes;
        }
    }
    return modes;
}

bool cadence_is_uniform_burst(const uint32_t* inter_arrival, uint32_t buckets,
                              uint32_t fault_count, uint32_t min_faults,
                              uint32_t concentration_pct) noexcept {
    if (inter_arrival == nullptr || buckets == 0u || fault_count < min_faults) {
        return false;
    }
    uint64_t total = 0u;
    uint32_t peak = 0u;
    for (uint32_t i = 0u; i < buckets; ++i) {
        total += inter_arrival[i];
        if (inter_arrival[i] > peak) {
            peak = inter_arrival[i];
        }
    }
    if (total == 0u) {
        return false;
    }
    /* A uniform stepping cadence concentrates inter-arrivals in ONE bucket: the
     * single-step fingerprint. Compare the peak bucket's share against the
     * threshold percent. */
    const uint64_t peak_share_pct = (static_cast<uint64_t>(peak) * 100u) / total;
    return peak_share_pct >= static_cast<uint64_t>(concentration_pct);
}

uint32_t cpuid_fan_spread(const uint32_t* leaf_latency, const uint32_t* leaf_id,
                          uint32_t leaves) noexcept {
    if (leaf_latency == nullptr || leaf_id == nullptr || leaves == 0u) {
        return 0u;
    }
    uint32_t lo = 0u;
    uint32_t hi = 0u;
    uint32_t populated = 0u;
    for (uint32_t i = 0u; i < leaves; ++i) {
        if (leaf_id[i] == 0u) {
            continue; /* unpopulated slot (leaf 0 is the basic-info leaf, never swept
                         into a non-zero slot here; a 0 id marks an empty entry) */
        }
        const uint32_t v = leaf_latency[i];
        if (populated == 0u) {
            lo = v;
            hi = v;
        } else {
            if (v < lo) lo = v;
            if (v > hi) hi = v;
        }
        ++populated;
    }
    if (populated < 2u) {
        return 0u; /* need at least two leaves to measure a spread */
    }
    return hi - lo;
}

} // namespace timing
} // namespace hk
