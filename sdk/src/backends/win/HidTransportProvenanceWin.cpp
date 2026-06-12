/*
 * Role: Signal 57 (win-input-automation). HID-collection-vs-transport provenance
 *       sensor. For each HID mouse/keyboard collection, reads the HID caps
 *       (UsagePage/Usage via HidD_GetPreparsedData + HidP_GetCaps), the VID/PID
 *       (HidD_GetAttributes), and walks the device's parent/bus
 *       (SetupDiGetDevicePropertyW DEVPKEY_Device_Parent / _BusTypeGuid /
 *       _EnumeratorName) to confirm the underlying transport. A pointer/keyboard
 *       usage riding a USB-CDC/serial or generic-bridge parent is the emulator-bridge
 *       shape (Arduino / Pi Pico / KMBox-style serial-to-HID). Reports vidpid +
 *       parent bus + descriptor presence; the allow-list decision is server-side
 *       (catalog FP: composite gaming keyboards + serial config interfaces, DACs, KVM
 *       adapters legitimately pair HID with CDC — never flag VID/PID alone).
 * Target platforms: Windows userspace. Guardrail #1: SetupAPI/CfgMgr + HID API
 *       confined here.
 * Interface: implements hk::sdk::win::sense_hid_transport. Verdict via the pure
 *       classify_input_source (is_hid_transport path) in InputSensorWin.h.
 */

#include "InputSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace win {

int sense_hid_transport(std::vector<hk_input_finding>& out)
{
    /* HK-TODO(sdk-integration): the full enumeration walks
     * SetupDiGetClassDevs(GUID_DEVINTERFACE_HID) -> for each interface,
     * CreateFileW(path, 0, FILE_SHARE_READ|WRITE) (access 0 so we never disturb an
     * exclusively-opened device), HidD_GetPreparsedData + HidP_GetCaps for the
     * top-level UsagePage/Usage, HidD_GetAttributes for VID/PID, then
     * SetupDiGetDevicePropertyW(DEVPKEY_Device_Parent / _BusTypeGuid /
     * _EnumeratorName) on the parent to read the transport. The verdict folding is:
     *
     *   InputSourceInput si{};
     *   si.is_hid_transport = true;
     *   si.query_failed     = createfile_or_caps_failed;   // shared/exclusive open
     *   si.emulator_bridge  = pointer_or_kbd_usage &&
     *                         parent_bus_is_serial_or_cdc_or_generic_bridge &&
     *                         !vendor_report_descriptor_signature;  // the COMBINATION
     *   finding.verdict     = classify_input_source(si);
     *   // vidpid (HidD_GetAttributes) + parent-bus ride the JSON side-channel
     *   out.push_back(finding);
     *
     * The emulator-bridge verdict requires the COMBINATION of a generic/known-emulator
     * parent bus AND the absence of a vendor HID report-descriptor signature, never a
     * VID/PID allow-list match alone (catalog FP gate). CreateFileW on a HID path can
     * fail with sharing/access errors for exclusively-opened devices: that maps to
     * query_failed -> HK_INPUT_SRC_UNRESOLVED, never a crash and never a false bridge.
     *
     * The enumeration is read-only and self-contained (no input stream needed), but
     * the parent-bus classification + descriptor-signature check are the load-bearing
     * FP gate; until that pass is verified we emit nothing rather than risk a false
     * emulator-bridge verdict on a legitimate composite device. */
    (void)out;
    return 0; /* parent-bus + descriptor FP gate not yet verified: no verdict fabricated */
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
