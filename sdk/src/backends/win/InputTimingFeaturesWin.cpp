/*
 * Role: Signal 58 (win-input-automation). WM_INPUT inter-arrival timing-feature
 *       extractor. Timestamps each WM_INPUT at receipt with QueryPerformanceCounter,
 *       buckets inter-arrival deltas per hDevice, and over a sliding window emits the
 *       period_hist / cov_x10000 / regularity_x10000 feature block. FEATURES ONLY —
 *       it ships hk_input_timing_features, NEVER a verdict (catalog: "timing alone is
 *       too noisy ... ship features to the server model, never a client-side ban").
 *       1000-8000 Hz mice and frame-locked input genuinely produce regular deltas;
 *       that disambiguation is SERVER-side and explicitly out of scope here (plan R2).
 * Target platforms: Windows userspace. Guardrail #1: QueryPerformanceCounter is the
 *       only platform call; the feature math is the pure compute_timing_features in
 *       InputSensorWin.h (host-tested), so no thresholding ever leaks client-side.
 * Interface: implements hk::sdk::win::sense_input_timing.
 */

#include "InputSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace win {

int sense_input_timing(const RawInputInventory& inv,
                       std::vector<hk_input_timing_features>& out)
{
    /* HK-TODO(sdk-integration): the per-device inter-arrival deltas come from the
     * game's OWN WM_INPUT receipt timestamps (QueryPerformanceCounter at message
     * receipt), accumulated O(1) per message on the input thread; this per-tick
     * serialize runs on the AC tick thread (never the input thread). Once the SDK
     * delivers the per-hDevice delta buffer, the folding is:
     *
     *   hk_input_timing_features t{};
     *   t.schema_version = HK_INPUT_SCHEMA_VERSION;
     *   t.signal         = HK_INPUT_SIG_TIMING_ENTROPY;
     *   t.hdevice_token  = dev.hdevice_token;      // opaque, never the raw HANDLE
     *   t.transport_flags = dev.transport_flags;
     *   compute_timing_features(deltas_ns, count, kBucketNs, t);  // pure, deterministic
     *   out.push_back(t);                          // server model decides; no verdict here
     *
     * There is deliberately NO threshold/verdict in this sensor: compute_timing_features
     * fills only the histogram + CoV + regularity feature, and the struct carries no
     * verdict field (the type is hk_input_timing_features, not hk_input_finding). With
     * no live WM_INPUT delta stream this tick, emit nothing. */
    (void)inv;
    (void)out;
    (void)&compute_timing_features; /* keep the pure core referenced from this TU */
    return 0; /* no SDK-delivered inter-arrival stream this tick: nothing observed */
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
