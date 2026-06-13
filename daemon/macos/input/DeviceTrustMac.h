/*
 * Role: macOS daemon-internal façade for the device-trust input sensors
 *       (hardware-input-devices domain, catalog signals 141 IOHIDDevice transport
 *       audit and 142 pointer-delta features, macOS half). Declares the two sensor
 *       entry points and the pure transport-classification core (USB/Bluetooth
 *       transport + location-id vs IOHIDUserDevice/DriverKit virtual) that a host unit
 *       test drives with no IOHIDManager.
 * Target platforms: macOS (userspace daemon). The pure core is platform-free.
 * Interface: declares the entry points the horkosd poll loop calls; implemented by
 *       IOHIDTransportAuditMac.mm + PointerDeltaStatsMac.mm. Runs in the USERSPACE
 *       daemon, NOT the ES auth path — there is no ES event to reply to here, so
 *       guardrail #7's reply-deadline does not apply. Findings ride the device-trust
 *       JSON plane (device_trust_schema.h).
 */

#pragma once

#include <cstdint>
#include <vector>

#include "horkos/device_trust_schema.h"

namespace hk { namespace daemon { namespace mac {

/* The minimal IOHID transport facts the audit resolves before classifying. */
struct IOHidTransportInput {
    bool query_failed;        /* an IOHIDDeviceGetProperty / IORegistry read failed */
    bool transport_usb;       /* kIOHIDTransportKey == "USB" */
    bool transport_bluetooth; /* kIOHIDTransportKey == "Bluetooth" */
    bool has_location_id;     /* kIOHIDLocationIDKey present (a real USB/BT endpoint) */
    bool is_user_device;      /* IOHIDUserDevice / DriverKit virtual provider */
    bool unique_id_missing;   /* kIOHIDPhysicalDeviceUniqueIDKey absent (inconclusive, not synthetic) */
};

/* Pure transport classifier. Conservative: a failed query or a device whose physical-
 * unique-id is simply absent is INCONCLUSIVE, never a synthetic-device signal
 * (key availability varies by device/macOS version). A USB/BT
 * transport WITH a location id is a real endpoint (benign); an IOHIDUserDevice/
 * DriverKit-virtual provider with no location id is the virtual-HID shape, reported
 * with HK_DAUD_NO_USB_PARENT + the providing dext bundle id (server allowlists
 * Karabiner / BetterTouchTool / remote-control apps) — the VERDICT stays
 * PHYSICAL_KNOWN; the server decides. */
inline uint8_t classify_iohid_transport(const IOHidTransportInput &in,
                                        uint32_t &out_verdict)
{
    if (in.query_failed || in.unique_id_missing) {
        out_verdict = HK_INPUT_SRC_UNRESOLVED;
        return HK_DAUD_INCONCLUSIVE;
    }
    out_verdict = HK_INPUT_SRC_PHYSICAL_KNOWN;
    uint8_t flags = 0;
    const bool real_endpoint =
        (in.transport_usb || in.transport_bluetooth) && in.has_location_id;
    if (in.is_user_device || !real_endpoint) {
        flags |= HK_DAUD_NO_USB_PARENT; /* virtual HID; creator/dext bundle id sent for allowlist */
    }
    return flags;
}

/* IOHIDManager transport/conformance audit (141). Emits hk_device_descriptor_audit. */
int sense_iohid_transport(std::vector<hk_device_descriptor_audit> &out);

/* Pointer-delta feature extractor (142, macOS half). Emits hk_event_pointer_features;
 * never raw movement. */
int sense_pointer_stats(std::vector<hk_event_pointer_features> &out);

} } } // namespace hk::daemon::mac
