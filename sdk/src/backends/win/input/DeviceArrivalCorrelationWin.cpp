/*
 * Role: Signal 144 — device-arrival/activity-correlation sensor. Timestamps
 *       DBT_DEVICEARRIVAL / DBT_DEVICEREMOVECOMPLETE for GUID_DEVINTERFACE_HID (via
 *       RegisterDeviceNotification) and joins them against per-hDevice activity windows
 *       from the raw-input path, emitting device_lifetime_s + activity_burst_corr ONLY
 *       when the JOINT condition holds (new HID source + bursty combat-correlated
 *       activity + simultaneous idling of the prior device). Low-weight FEATURE, never
 *       a standalone verdict — KVM/dongle re-pair/hub power/mid-session swap all
 *       generate arrivals.
 * Target platforms: Windows userspace.
 * Interface: implements hk::sdk::win::sense_device_arrival from input/DeviceTrustWin.h;
 *       emits hk_pointer_cadence_features (lifetime/arrival fields). FEATURE only.
 */

#include "input/DeviceTrustWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>
#include <dbt.h>

#include <vector>

namespace hk { namespace sdk { namespace win {

int sense_device_arrival(std::vector<hk_pointer_cadence_features> &out)
{
    /* HK-UNCERTAIN(arrival-activity-join): the join requires (a) a live
     * RegisterDeviceNotification feed delivering DBT_DEVICEARRIVAL timestamps to the
     * SDK message loop, and (b) the per-hDevice activity windows + gameplay-burst
     * markers from the sibling raw-input/cadence path. Both are SDK-tick integration
     * owned by the host loop, absent in this scaffolding TU. The JOINT condition
     * (new source + bursty activity + prior-device idle) MUST hold before any feature
     * is emitted; emitting on arrival alone would make a benign KVM switch / dongle
     * re-pair / mid-session mouse swap a false positive (catalog FP gate). Per
     * guardrail #13 the live join is left a stub: with no arrival+activity feed wired,
     * this emits nothing rather than a fabricated lifetime/correlation feature.
     *
     * The on-box implementer wires:
     *   1. RegisterDeviceNotification(GUID_DEVINTERFACE_HID, DEVICE_NOTIFY_WINDOW_HANDLE)
     *      on the SDK's hidden message window; record arrival/remove QPC timestamps.
     *   2. On each report tick, for a device whose lifetime is short AND whose arrival
     *      coincides with a gameplay-burst window AND the prior dominant device went
     *      idle, fill device_lifetime_s + activity_burst_corr and set HK_CAD_HOTPLUG
     *      (+ HK_CAD_PRIOR_IDLE) here. Otherwise emit nothing.
     */
    (void)out;
    return 0;
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
