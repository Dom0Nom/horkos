/*
 * Role: Signal 182 cross-platform core — monotonic-vs-realtime clock-domain drift
 *       sensor. Computes the per-window rate ratio of the two clock domains from a
 *       sequence of paired reads dispatched through `net_backend.h`, and emits the
 *       ratio (ppm) plus a coarse `step_detected` flag. The authoritative
 *       NTP-step-vs-smooth-scale discrimination is server-side (catalog FP gate);
 *       the client ships the raw ratio only. NO platform header here (guardrail #1)
 *       — all OS reads go through the backend seam.
 * Target platforms: cross (core).
 * Interface: implements the signal-182 half of `hk::net` (`net_timing.h`); uses
 *       `net_backend.h`. Consumed by the `net_collect_all()` aggregator.
 */

#include "horkos/net_timing.h"
#include "net_backend.h"
#include "net_probes.h"

#include <cstdint>
#include <cstdlib>

namespace hk { namespace net {

namespace {

/* Bounded sample budget per window. Two endpoint reads suffice for a rate ratio;
 * a small interior set lets us spot a discrete step without unbounded work. */
constexpr int kSamples = 8;

/* A clock STEP (NTP slew applied as a discrete jump) shows up as one inter-sample
 * realtime delta that diverges sharply from the monotonic delta over the same
 * interval. We flag it coarsely here; the server makes the verdict. The threshold
 * is a conservative client-side gate to set the flag, NOT a ban decision. */
constexpr double kStepRelThreshold = 0.05; /* 5% per-interval divergence */

} // namespace

hk_net_clock_drift probe_clock_drift(void)
{
    hk_net_clock_drift out;
    out.clock_ratio_ppm = 0;
    out.step_detected = 0;

    clock_sample s[kSamples];
    int n = 0;
    for (int i = 0; i < kSamples; ++i) {
        clock_sample cur;
        if (!backend_read_clock_pair(&cur)) {
            break;
        }
        s[n++] = cur;
    }

    /* Need both endpoints to form a ratio. Fewer than two usable reads -> no data
     * (ratio stays 0, which the server reads as "no drift signal"). */
    if (n < 2) {
        return out;
    }

    const uint64_t mono_span = (s[n - 1].mono_ns >= s[0].mono_ns)
                                   ? (s[n - 1].mono_ns - s[0].mono_ns)
                                   : 0;
    const uint64_t real_span = (s[n - 1].real_ns >= s[0].real_ns)
                                   ? (s[n - 1].real_ns - s[0].real_ns)
                                   : 0;

    /* A non-advancing monotonic clock is unusable; bail without a false ratio. */
    if (mono_span == 0) {
        return out;
    }

    /* ratio = realtime rate / monotonic rate. ppm drift = (ratio - 1) * 1e6.
     * Clamp into int32 to avoid overflow on a pathological reading. */
    const double ratio = static_cast<double>(real_span) / static_cast<double>(mono_span);
    double ppm = (ratio - 1.0) * 1.0e6;
    if (ppm > 2.0e9) {
        ppm = 2.0e9;
    } else if (ppm < -2.0e9) {
        ppm = -2.0e9;
    }
    out.clock_ratio_ppm = static_cast<int32_t>(ppm);

    /* Coarse step detection: scan interior intervals for one whose realtime delta
     * diverges from its monotonic delta by more than the relative threshold. */
    for (int i = 1; i < n; ++i) {
        const uint64_t dm = (s[i].mono_ns >= s[i - 1].mono_ns)
                                ? (s[i].mono_ns - s[i - 1].mono_ns)
                                : 0;
        const uint64_t dr = (s[i].real_ns >= s[i - 1].real_ns)
                                ? (s[i].real_ns - s[i - 1].real_ns)
                                : 0;
        if (dm == 0) {
            continue;
        }
        const double local = static_cast<double>(dr) / static_cast<double>(dm);
        if (local > 1.0 + kStepRelThreshold || local < 1.0 - kStepRelThreshold) {
            out.step_detected = 1;
            break;
        }
    }

    return out;
}

} } // namespace hk::net
