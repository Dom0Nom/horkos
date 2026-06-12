/*
 * Role: Platform-neutral per-tick aim-feature accumulator. Folds the raw HID
 *       samples the platform backends drained this tick (hk_hid_sample[]) into
 *       the 163/165/171 fields of the fixed feature block (hk_aim_features):
 *       report count, summed raw integer deltas, newest hardware timestamp,
 *       inter-arrival mean/variance, render-frame-locked interval count, and the
 *       injected-event fraction (Q0.8). No platform API — the OS reads happen in
 *       the backends; this TU only does arithmetic over the platform-free sample
 *       struct, so the host unit test links it with no platform TU.
 * Target platforms: all (no platform headers).
 * Interface: implements hk::sdk::aim::fold_tick from AimSampler.h. Kernel-free,
 *       shares no TU with kernel/ (guardrail #4). Read-only: it derives features
 *       from already-captured samples and NEVER thresholds or convicts — every
 *       verdict is server-side (catalog mandate).
 */

#include "AimSampler.h"

namespace hk { namespace sdk { namespace aim {

void fold_tick(const hk_hid_sample* samples, uint32_t count,
               uint64_t frame_period_ns, hk_aim_features* out)
{
    if (out == nullptr) {
        return;
    }

    /* 163: report count + summed raw integer deltas + newest hardware ts.
     * These three are the provenance the server reconciles against the applied
     * angle delta; they are summed even when count==0 (then all stay zero). */
    out->hid_report_count = count;
    out->hid_raw_dx = 0;
    out->hid_raw_dy = 0;
    out->hid_newest_ts_ns = 0;

    if (samples == nullptr || count == 0) {
        /* Nothing drained this tick: leave 163/165/171 at their zero defaults.
         * The server reads "no HID this tick" rather than a fabricated cadence. */
        out->hid_interval_mean_ns = 0;
        out->hid_interval_var_ns = 0;
        out->hid_interval_framelock_count = 0;
        out->injected_event_fraction_q8 = 0;
        return;
    }

    uint32_t injected_count = 0;
    for (uint32_t i = 0; i < count; ++i) {
        out->hid_raw_dx += samples[i].raw_dx;
        out->hid_raw_dy += samples[i].raw_dy;
        if (samples[i].ts_ns > out->hid_newest_ts_ns) {
            out->hid_newest_ts_ns = samples[i].ts_ns;
        }
        if (samples[i].injected != 0) {
            ++injected_count;
        }
    }

    /* 171: injected fraction in Q0.8. (injected/count) * 256, rounded. The
     * server segregates cohorts on this fraction; it is never a client verdict. */
    {
        /* count >= 1 here. Cap at 255 so a fraction of exactly 1.0 still fits
         * the Q0.8 byte (256 would overflow to 0). */
        uint32_t q8 = (injected_count * 256u + count / 2u) / count;
        if (q8 > 255u) {
            q8 = 255u;
        }
        out->injected_event_fraction_q8 = static_cast<uint16_t>(q8);
    }

    /* 165: inter-arrival mean/variance + render-frame-locked interval count.
     * Intervals are consecutive ts deltas, so there are (count-1) of them. With a
     * single sample there are no intervals — moments stay zero. */
    if (count < 2) {
        out->hid_interval_mean_ns = 0;
        out->hid_interval_var_ns = 0;
        out->hid_interval_framelock_count = 0;
        return;
    }

    const uint32_t n_intervals = count - 1;

    /* Mean of the inter-arrival deltas. Samples are delivered in capture order;
     * a non-monotone pair (clock hiccup / reordering) contributes a 0 interval
     * rather than an underflowed huge value — degenerate-window safety. */
    uint64_t sum = 0;
    for (uint32_t i = 1; i < count; ++i) {
        uint64_t d = (samples[i].ts_ns >= samples[i - 1].ts_ns)
                         ? (samples[i].ts_ns - samples[i - 1].ts_ns)
                         : 0;
        sum += d;
    }
    const uint64_t mean = sum / n_intervals;
    out->hid_interval_mean_ns = mean;

    /* Population variance (integer; saturates into u64). Each squared deviation
     * is bounded by the interval magnitude, well within u64 for sane cadences. */
    uint64_t var_acc = 0;
    uint32_t framelock = 0;
    for (uint32_t i = 1; i < count; ++i) {
        uint64_t d = (samples[i].ts_ns >= samples[i - 1].ts_ns)
                         ? (samples[i].ts_ns - samples[i - 1].ts_ns)
                         : 0;
        int64_t dev = static_cast<int64_t>(d) - static_cast<int64_t>(mean);
        var_acc += static_cast<uint64_t>(dev * dev);

        /* Framelock: an interval equal to the render-frame period is the tell of
         * a synthetic report emitted on the render cadence rather than the HID
         * poll cadence. Exact equality only when a real frame period is supplied;
         * the server keeps the device nominal-rate prior and the tolerance band. */
        if (frame_period_ns != 0 && d == frame_period_ns) {
            ++framelock;
        }
    }
    out->hid_interval_var_ns = var_acc / n_intervals;
    out->hid_interval_framelock_count = framelock;
}

} } } // namespace hk::sdk::aim
