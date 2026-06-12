/*
 * Role: Pure, platform-free pointer-delta feature extractor (catalog signal 142),
 *       shared by the three platform halves (PointerDeltaStatsWin.cpp /
 *       PointerDeltaStatsPosix.cpp / PointerDeltaStatsMac.mm). Accumulates raw
 *       per-event (dx, dy) integer deltas into a bounded window and folds them into the
 *       fixed HK_POINTER_FEAT_DIM (24) aggregate feature vector: distribution moments,
 *       lag autocorrelation, and the GCD-of-deltas (CPI-lattice) statistics. The raw
 *       deltas live ONLY inside this accumulator and are discarded once folded — the
 *       emitted hk_event_pointer_features contains aggregates ONLY, never a raw sample
 *       (privacy invariant; data-categories §5). This is a FEATURE producer; it never
 *       computes a verdict (the server conditions the ONNX model on hid_usage_class).
 * Target platforms: all (header-only, no platform headers; reused by .cpp and .mm).
 * Interface: PointerFeatureWindow accumulator + fold_pointer_features(). No emit of any
 *       raw lLastX/lLastY / REL_X/REL_Y / IOHIDValue sample is possible through this
 *       type — there is no accessor for the stored deltas.
 */

#pragma once

#include <cstdint>
#include <cmath>
#include <vector>

#include "horkos/device_trust_schema.h"

namespace hk { namespace sdk { namespace common {

/* Bounded per-session accumulator. Holds at most `cap` recent integer deltas; once
 * full it overwrites oldest (ring) so the window is bounded and a long session does
 * not grow memory. The stored deltas are PRIVATE — there is intentionally no getter,
 * so no caller can ship a raw sample. */
class PointerFeatureWindow {
public:
    explicit PointerFeatureWindow(size_t cap = 4096) : cap_(cap == 0 ? 1 : cap) {}

    void add(int32_t dx, int32_t dy) {
        if (dx_.size() < cap_) {
            dx_.push_back(dx);
            dy_.push_back(dy);
        } else {
            dx_[head_] = dx;
            dy_[head_] = dy;
            head_ = (head_ + 1) % cap_;
        }
    }

    size_t count() const { return dx_.size(); }
    void clear() { dx_.clear(); dy_.clear(); head_ = 0; }

    const std::vector<int32_t> &dx_internal() const { return dx_; }
    const std::vector<int32_t> &dy_internal() const { return dy_; }

private:
    std::vector<int32_t> dx_;
    std::vector<int32_t> dy_;
    size_t cap_;
    size_t head_ = 0;
};

/* gcd over non-negative ints; gcd(0,a)=a so the running fold over magnitudes works. */
inline uint32_t feat_gcd(uint32_t a, uint32_t b) {
    while (b != 0) {
        const uint32_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

/* Fold one axis (deltas) into a 9-slot feature group at out[base..base+8]:
 *   0 mean, 1 std, 2 abs-mean, 3 max-abs, 4 zero-fraction,
 *   5 lag-1 autocorrelation, 6 GCD-of-|delta| (CPI lattice quantum),
 *   7 fraction-quantized-to-GCD, 8 sign-change fraction.
 * All float; deterministic. A degenerate (uniform / integer-curve / single-step)
 * stream produces a characteristic vector (e.g. std==0 single step; GCD large +
 * fraction-quantized==1 for a lattice) that the server flags as non-physical, while a
 * real-sensor stream's noise profile does not — the catalog physicality gate. */
inline void fold_axis(const std::vector<int32_t> &d, float *out, size_t base) {
    const size_t n = d.size();
    for (size_t i = 0; i < 9; ++i) {
        out[base + i] = 0.0f;
    }
    if (n == 0) {
        return;
    }
    double sum = 0.0, abssum = 0.0;
    uint32_t maxabs = 0, zeros = 0, gcd = 0, signchg = 0;
    for (size_t i = 0; i < n; ++i) {
        const int32_t v = d[i];
        sum += v;
        const uint32_t av = (uint32_t)(v < 0 ? -(int64_t)v : v);
        abssum += av;
        if (av > maxabs) maxabs = av;
        if (v == 0) ++zeros;
        gcd = feat_gcd(gcd, av);
        if (i > 0 && ((d[i] < 0) != (d[i - 1] < 0)) && d[i] != 0 && d[i - 1] != 0) {
            ++signchg;
        }
    }
    const double mean = sum / (double)n;
    double var = 0.0;
    for (size_t i = 0; i < n; ++i) {
        const double dv = (double)d[i] - mean;
        var += dv * dv;
    }
    var /= (double)n;
    const double sd = std::sqrt(var);

    /* Lag-1 autocorrelation (population), guarded against zero variance. */
    double ac1 = 0.0;
    if (var > 0.0 && n > 1) {
        double cov = 0.0;
        for (size_t i = 1; i < n; ++i) {
            cov += ((double)d[i] - mean) * ((double)d[i - 1] - mean);
        }
        cov /= (double)(n - 1);
        ac1 = cov / var;
    }

    /* Fraction of samples exactly divisible by the GCD quantum (1.0 for a perfect
     * integer lattice; a noisy real sensor's GCD collapses to 1 with fraction 1.0,
     * so the discriminator is GCD MAGNITUDE combined with std, not this alone). */
    double quant = 0.0;
    if (gcd > 0) {
        uint32_t hits = 0;
        for (size_t i = 0; i < n; ++i) {
            const uint32_t av = (uint32_t)(d[i] < 0 ? -(int64_t)d[i] : d[i]);
            if (av % gcd == 0) ++hits;
        }
        quant = (double)hits / (double)n;
    }

    out[base + 0] = (float)mean;
    out[base + 1] = (float)sd;
    out[base + 2] = (float)(abssum / (double)n);
    out[base + 3] = (float)maxabs;
    out[base + 4] = (float)((double)zeros / (double)n);
    out[base + 5] = (float)ac1;
    out[base + 6] = (float)gcd;
    out[base + 7] = (float)quant;
    out[base + 8] = (float)((double)signchg / (double)n);
}

/* Fold the window into the 24-dim feature vector: dx group (0..8), dy group (9..17),
 * then 6 cross/joint slots (18..23): sample_count(normalized), speed mean/std,
 * straightness (|sum|/path-len), dx/dy correlation, diagonal-lattice GCD. The emitted
 * struct carries aggregates ONLY — no raw delta crosses this boundary. Returns false
 * if the window is empty (caller skips the emit). */
inline bool fold_pointer_features(const PointerFeatureWindow &win,
                                  uint32_t hid_usage_class, uint64_t hdevice_token,
                                  hk_event_pointer_features &out) {
    const std::vector<int32_t> &dx = win.dx_internal();
    const std::vector<int32_t> &dy = win.dy_internal();
    const size_t n = dx.size();
    out.schema_version = HK_DEVICE_TRUST_SCHEMA_VERSION;
    out.hid_usage_class = hid_usage_class;
    out.hdevice_token = hdevice_token;
    for (uint32_t i = 0; i < HK_POINTER_FEAT_DIM; ++i) {
        out.feat[i] = 0.0f;
    }
    if (n == 0) {
        return false;
    }

    fold_axis(dx, out.feat, 0);
    fold_axis(dy, out.feat, 9);

    double speed_sum = 0.0, path = 0.0, sumx = 0.0, sumy = 0.0;
    double cxy = 0.0, vx = 0.0, vy = 0.0;
    const double mx = out.feat[0], my = out.feat[9];
    uint32_t dgcd = 0;
    for (size_t i = 0; i < n; ++i) {
        const double sp = std::sqrt((double)dx[i] * dx[i] + (double)dy[i] * dy[i]);
        speed_sum += sp;
        path += sp;
        sumx += dx[i];
        sumy += dy[i];
        cxy += ((double)dx[i] - mx) * ((double)dy[i] - my);
        vx += ((double)dx[i] - mx) * ((double)dx[i] - mx);
        vy += ((double)dy[i] - my) * ((double)dy[i] - my);
        const uint32_t ax = (uint32_t)(dx[i] < 0 ? -(int64_t)dx[i] : dx[i]);
        const uint32_t ay = (uint32_t)(dy[i] < 0 ? -(int64_t)dy[i] : dy[i]);
        dgcd = feat_gcd(dgcd, feat_gcd(ax, ay));
    }
    const double net = std::sqrt(sumx * sumx + sumy * sumy);
    out.feat[18] = (float)n;
    out.feat[19] = (float)(speed_sum / (double)n);
    out.feat[20] = (float)(n > 1 ? std::sqrt((speed_sum * speed_sum) / (double)n) : 0.0);
    out.feat[21] = (float)(path > 0.0 ? net / path : 0.0); /* straightness */
    out.feat[22] = (float)((vx > 0.0 && vy > 0.0) ? cxy / std::sqrt(vx * vy) : 0.0);
    out.feat[23] = (float)dgcd; /* joint dx/dy lattice quantum */
    return true;
}

} } } // namespace hk::sdk::common
