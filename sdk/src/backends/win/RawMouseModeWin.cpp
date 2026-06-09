/*
 * sdk/src/backends/win/RawMouseModeWin.cpp
 * Role: Signal 60 (win-input-automation). Raw-mouse coordinate-mode-transition
 *       sensor. Inspects RAWMOUSE.usFlags on each WM_INPUT for MOUSE_MOVE_ABSOLUTE /
 *       MOUSE_VIRTUAL_DESKTOP / MOUSE_MOVE_RELATIVE transitions per hDevice; a device
 *       that reported relative then emits absolute (or oscillates) on a LOCAL console
 *       with no absolute-class HID present is the anomaly. Gates on
 *       SM_REMOTESESSION (RDP/VNC) and on whether an absolute-capable device
 *       (digitizer/touch) actually enumerated (catalog FP: Wacom, touchscreens, VM
 *       guest-tools legitimately report absolute). Reports the flags + device path;
 *       the server scores.
 * Target platforms: Windows userspace. Guardrail #1: GetSystemMetrics is the only
 *       platform call; the bitmask + oscillation folding is the pure
 *       fold_rawmouse_flags in InputSensorWin.h (host-tested).
 * Interface: implements hk::sdk::win::sense_rawmouse_mode.
 */

#include "InputSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace win {

int sense_rawmouse_mode(const RawInputInventory& inv,
                        std::vector<hk_input_finding>& out)
{
    const bool remote_session = GetSystemMetrics(SM_REMOTESESSION) != 0;

    /* HK-TODO(sdk-integration): the per-event RAWMOUSE.usFlags come from the game's
     * OWN WM_INPUT handler (the SDK does not yet route the raw-mouse stream into the
     * sensors). `inv` already tells us, per hDevice, whether an absolute-class device
     * is present (dev.absolute_capable). Once the SDK delivers each RAWMOUSE, the
     * folding is:
     *
     *   RawMouseModeInput mi{};
     *   mi.flag_absolute        = (rm.usFlags & MOUSE_MOVE_ABSOLUTE) != 0;
     *   mi.flag_virtual_desktop = (rm.usFlags & MOUSE_VIRTUAL_DESKTOP) != 0;
     *   mi.prior_was_relative   = window_saw_relative_for(hDevice);
     *   mi.absolute_device_present = inventory_has_absolute_capable_device();
     *   mi.remote_session       = remote_session;
     *   finding.flags = fold_rawmouse_flags(mi);   // sets MODE_OSCILLATION only on the
     *                                              // local-console, no-absolute-device case
     *   if (finding.flags & (HK_INFLAG_MOUSE_ABSOLUTE | HK_INFLAG_MODE_OSCILLATION))
     *       out.push_back(finding);                // server scores; client never bans
     *
     * fold_rawmouse_flags encodes the FP gate: MODE_OSCILLATION is set only when the
     * device flipped relative->absolute, no absolute-class device explains it, and we
     * are on the local console — so Wacom/touch/RDP/VNC do not flag. With no live
     * RAWMOUSE stream this tick, emit nothing. */
    (void)inv;
    (void)remote_session;
    (void)out;
    (void)&fold_rawmouse_flags; /* keep the pure core referenced from this TU */
    return 0; /* no SDK-delivered RAWMOUSE stream this tick: nothing observed */
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
