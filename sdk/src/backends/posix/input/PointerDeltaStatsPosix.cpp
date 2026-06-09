/*
 * sdk/src/backends/posix/input/PointerDeltaStatsPosix.cpp
 * Role: Signal 142 (Linux half) — pointer-delta statistical-feature extractor.
 *       Accumulates EV_REL REL_X/REL_Y deltas (read from the game's own evdev grab /
 *       libinput stream) into a bounded window and folds them into the
 *       hk_event_pointer_features aggregate vector via the shared platform-free fold —
 *       the same moments as the Windows and macOS halves. NEVER ships raw movement;
 *       only the 24-dim aggregate + the resolved HID usage class (privacy invariant;
 *       data-categories §5).
 * Target platforms: Linux userspace.
 * Interface: implements hk::sdk::posix::sense_pointer_stats from
 *       input/DeviceTrustPosix.h; emits hk_event_pointer_features via the shared
 *       common::fold_pointer_features.
 */

#include "common/PointerFeatureFold.h"
#include "input/DeviceTrustPosix.h"

#if defined(HK_PLATFORM_LINUX) || defined(__linux__)

#include <cstdint>
#include <vector>

namespace hk { namespace sdk { namespace posix {

namespace {

/* Per-session relative-delta accumulator, fed by the SDK evdev reader via
 * pointer_window_add(); folded + cleared each tick. The raw deltas never leave
 * g_window (no getter ships them). */
common::PointerFeatureWindow g_window;
uint64_t g_hdevice_token = 0;
uint32_t g_usage_class = HK_PCLASS_MOUSE;

} // namespace

/* Called from the SDK evdev reader for each EV_REL REL_X/REL_Y pair. */
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
    const bool ok = common::fold_pointer_features(g_window, g_usage_class,
                                                  g_hdevice_token, rec);
    g_window.clear(); /* discard raw deltas after folding (privacy invariant) */
    if (!ok) {
        return 0;
    }
    out.push_back(rec);
    return 1;
}

} } } // namespace hk::sdk::posix

#endif /* HK_PLATFORM_LINUX || __linux__ */
