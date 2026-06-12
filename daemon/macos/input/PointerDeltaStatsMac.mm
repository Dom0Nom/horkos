/*
 * Role: Signal 142 (macOS half) — pointer-delta statistical-feature extractor.
 *       Accumulates IOHIDValueGetIntegerValue relative deltas (GD_X/GD_Y from the
 *       IOHIDManager input-value callback) into a bounded window and folds them into
 *       the hk_event_pointer_features aggregate vector via the shared platform-free
 *       fold — the same moments as the Windows and Linux halves. NEVER ships raw
 *       movement; only the 24-dim aggregate + the resolved HID usage class (privacy
 *       invariant; data-categories §5).
 * Target platforms: macOS (userspace daemon).
 * Interface: implements hk::daemon::mac::sense_pointer_stats from
 *       input/DeviceTrustMac.h; emits hk_event_pointer_features via the shared
 *       common::fold_pointer_features. The IOHIDManager value-callback feed is the
 *       daemon poll loop's responsibility; this TU owns the window + the fold.
 */

#import <Foundation/Foundation.h>
#import <IOKit/hid/IOHIDValue.h>
#import <IOKit/hid/IOHIDUsageTables.h>

#include <cstdint>
#include <vector>

#include "common/PointerFeatureFold.h"
#include "input/DeviceTrustMac.h"

namespace hk { namespace daemon { namespace mac {

namespace {

/* Per-session relative-delta accumulator, fed by the IOHIDManager input-value callback
 * via pointer_window_add(); folded + cleared each poll tick. Raw deltas never leave
 * g_window (no getter ships them). */
hk::sdk::common::PointerFeatureWindow g_window;
uint64_t g_hdevice_token = 0;
uint32_t g_usage_class = HK_PCLASS_MOUSE;

} // namespace

/* Called from the IOHIDManager input-value callback. The caller pairs the GD_X and
 * GD_Y IOHIDValue integers for one event and passes the integer deltas; only the
 * aggregate leaves this module. */
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
        return 0;
    }
    hk_event_pointer_features rec{};
    const bool ok = hk::sdk::common::fold_pointer_features(g_window, g_usage_class,
                                                          g_hdevice_token, rec);
    g_window.clear(); /* discard raw deltas after folding (privacy invariant) */
    if (!ok) {
        return 0;
    }
    out.push_back(rec);
    return 1;
}

} } } // namespace hk::daemon::mac
