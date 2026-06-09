/*
 * sdk/src/backends/win/input/PointerDeltaStatsWin.cpp
 * Role: Signal 142 (Windows half) — pointer-delta statistical-feature extractor.
 *       Accumulates RAWMOUSE.lLastX/lLastY relative deltas from the game's own
 *       WM_INPUT stream into a bounded window and folds them into the
 *       hk_event_pointer_features aggregate vector (moments / autocorrelation /
 *       GCD-of-deltas CPI-lattice stats) via the shared platform-free fold. NEVER
 *       ships raw movement — only the 24-dim aggregate + the resolved HID usage class
 *       (privacy invariant; data-categories §5).
 * Target platforms: Windows userspace.
 * Interface: implements hk::sdk::win::sense_pointer_stats from input/DeviceTrustWin.h;
 *       emits hk_event_pointer_features. The per-session window persists across ticks
 *       in this TU; the WM_INPUT feed integration is the SDK tick's responsibility.
 */

#include "common/PointerFeatureFold.h"
#include "input/DeviceTrustWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

#include <vector>

namespace hk { namespace sdk { namespace win {

namespace {

/* Per-session relative-delta accumulator. Fed by the SDK's WM_INPUT handler via
 * pointer_window_add() below; folded + cleared each report tick. Only MOUSE_MOVE_-
 * RELATIVE deltas are accumulated (absolute/virtual-desktop frames are skipped — they
 * are not CPI-lattice samples). */
common::PointerFeatureWindow g_window;
uint64_t g_hdevice_token = 0;
uint32_t g_usage_class = HK_PCLASS_MOUSE;

} // namespace

/* Called from the SDK WM_INPUT handler for each relative-motion RAWMOUSE event. Stores
 * the integer delta only; the raw value never leaves g_window (no getter ships it). */
void pointer_window_add(uint64_t hdevice_token, uint32_t usage_class,
                        int32_t dx, int32_t dy)
{
    g_hdevice_token = hdevice_token;
    g_usage_class = usage_class;
    g_window.add(dx, dy);
}

int sense_pointer_stats(std::vector<hk_event_pointer_features> &out)
{
    if (g_window.count() == 0) {
        return 0; /* nothing sampled this tick */
    }
    hk_event_pointer_features rec{};
    const bool ok = common::fold_pointer_features(g_window, g_usage_class,
                                                  g_hdevice_token, rec);
    g_window.clear(); /* discard raw deltas after folding (privacy invariant) */
    if (!ok) {
        return 0;
    }
    out.push_back(rec);
    return 1;
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
