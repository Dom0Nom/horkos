/*
 * Role: macOS raw-HID aim sampler (catalog signals 163/164/165). Drains the GAME'S
 *       OWN pointer HID values via IOHIDManager value callbacks, stamping each with
 *       IOHIDValueGetTimeStamp, into platform-free hk_hid_sample records the
 *       platform-neutral AimAccumulator.fold_tick collapses into the 163/165
 *       features. USERSPACE HID (IOKit) only — NOT the ES SystemExtension plane.
 * Target platforms: macOS userspace. Guardrail #1: the IOHIDManager/IOKit reads are
 *       confined to this backend. Guardrail #4/#7: a passive IOHIDManager value
 *       reader is userspace and owes NO EndpointSecurity auth reply — it is not on
 *       the ES plane.
 * Interface: implements hk::sdk::aim::sample_raw_hid from input/AimSampler.h.
 *       Catalog slots 163/164/165. Reads only the game's own HID; never injects.
 *
 * HK-UNCERTAIN(macos-tcc-input-monitoring): IOHIDManager value access requires the
 * Input-Monitoring (TCC) grant. This is NOT the Apple-approved EndpointSecurity
 * entitlement; it is the same TCC grant the CGEventTap path needs (plan R5). The
 * not-granted path MUST leave the 163/165 features at default and never crash. The
 * grant-state check + the IOHIDManager open are SDK bring-up integration (the SDK
 * owns the run-loop the value callbacks post to); per guardrail #12 they are not
 * assumed here — the live open is documented but no manager is created, so an
 * ungranted box simply drains nothing.
 * (docs: IOHIDManager is publicly documented (IOKit/hid/IOHIDManager.h). The TCC
 * Input-Monitoring requirement is Apple privacy policy, documented at
 * developer.apple.com/documentation/iokit/iohidmanager (see privacy entitlements).
 * The IOHIDManager API itself is public and stable; the blocking item is the TCC
 * grant state at runtime — still needs on-box TCC grant verification)
 */

#include "input/AimSampler.h"

#include "platform.h"

#if defined(HK_PLATFORM_MACOS) || defined(__APPLE__)

#import <Foundation/Foundation.h>
#include <stdint.h>

namespace hk { namespace sdk { namespace aim {

uint32_t sample_raw_hid(hk_hid_sample* samples, uint32_t cap)
{
    if (samples == nullptr || cap == 0) {
        return 0;
    }

    /* HK-UNCERTAIN(macos-tcc-input-monitoring): no IOHIDManager is open this tick
     * (see file header — docs note appended there). The live shape, once the SDK
     * creates the manager on its run loop with the Input-Monitoring grant confirmed:
     *
     *   IOHIDManagerRef m = IOHIDManagerCreate(kCFAllocatorDefault,
     *                                           kIOHIDOptionsTypeNone);
     *   // match the game's pointer usage page/usage (kHIDPage_GenericDesktop /
     *   // kHIDUsage_GD_Mouse), schedule on the SDK run loop, and in the value
     *   // callback for relative X/Y axes:
     *   //   IOHIDValueRef v = ...;
     *   //   int32_t delta = (int32_t)IOHIDValueGetIntegerValue(v);
     *   //   uint64_t ts   = IOHIDValueGetTimeStamp(v);  // mach abs time
     *   //   samples[written] = { dx, dy, mach_to_ns(ts), injected=0 };
     *   // (mach_to_ns via mach_timebase_info; one monotonic basis shared with the
     *   //  165 framelock comparison.)
     *
     * With no manager, write nothing — a zero-count tick is a true "no HID", not
     * an anomaly (catalog FP gate), and an ungranted-TCC box no-ops here per R5
     * rather than crashing. */
    (void)samples;
    (void)cap;
    return 0; /* no IOHIDManager open this tick: nothing drained */
}

} } } // namespace hk::sdk::aim

#endif /* HK_PLATFORM_MACOS || __APPLE__ */
