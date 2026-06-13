/*
 * Role: Signal 62 (win-input-automation). HID report-rate-vs-declared-poll-interval
 *       contradiction sensor. Reads the device's USB interrupt-IN endpoint bInterval
 *       (declared poll rate) and compares it against the measured WM_INPUT arrival
 *       rate per hDevice; emits hk_input_timing_features with both rates +
 *       transport_flags. FEATURES ONLY — the server requires a large, sustained
 *       mismatch and exempts Bluetooth/wireless transports where connection-interval
 *       legitimately differs from HID bInterval (catalog FP: variable-rate mice, OS
 *       rate overrides, BLE connection-interval variance). No client verdict.
 * Target platforms: Windows userspace. Guardrail #1: SetupAPI + USB hub IOCTL
 *       confined here; the rate derivation + exemption are the pure
 *       declared_hz_from_binterval / pollrate_comparison_valid in InputSensorWin.h.
 * Interface: implements hk::sdk::win::sense_hid_pollrate.
 */

#include "InputSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace win {

int sense_hid_pollrate(const RawInputInventory& inv,
                       std::vector<hk_input_timing_features>& out)
{
    /* HK-UNCERTAIN(usb-hub-node-connection): deriving the declared poll rate requires
     * walking from the HID collection up to its parent hub and issuing
     * IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION on the hub to read the
     * interrupt-IN endpoint's bInterval. Resolving the hub device path, the
     * port/connection index, and the exact request layout is semi-documented and easy
     * to get subtly wrong across hub topologies (root hub vs external hub, composite
     * parents), and it does NOT apply to Bluetooth/virtual/composite devices. This is
     * NOT verified on-box and must not be guessed (guardrail #12). Until the
     * topology-walk + IOCTL request shape are confirmed on a real box, declared_hz
     * stays 0 (unknown) and the server simply gets no contradiction feature — never a
     * false positive (plan R4).
     *
     * The verified derivation, once the bInterval is reliably read, is pure and
     * host-tested:
     *
     *   hk_input_timing_features t{};
     *   t.schema_version  = HK_INPUT_SCHEMA_VERSION;
     *   t.signal          = HK_INPUT_SIG_HID_POLLRATE;
     *   t.hdevice_token   = dev.hdevice_token;
     *   t.transport_flags = dev.transport_flags;          // BT/wireless/virtual exemption
     *   t.declared_hz     = declared_hz_from_binterval(b_interval, high_speed);
     *   t.observed_hz_x100 = measured_wm_input_rate_x100; // from the inventory's timing window
     *   if (pollrate_comparison_valid(t))                 // suppresses BT/wireless/virtual/zero
     *       out.push_back(t);                             // server thresholds; client never bans
     *
     * pollrate_comparison_valid() encodes the exemption: a BLUETOOTH/WIRELESS/VIRTUAL
     * transport or a zero declared rate makes the comparison meaningless, so the
     * feature is not even emitted. With the hub-walk deferred, declared_hz is unknown
     * and there is no meaningful comparison to ship. */
    (void)inv;
    (void)out;
    (void)&declared_hz_from_binterval; /* keep the pure cores referenced from this TU */
    (void)&pollrate_comparison_valid;
    return 0; /* HK-UNCERTAIN(usb-hub-node-connection): bInterval read deferred; declared_hz unknown */
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
