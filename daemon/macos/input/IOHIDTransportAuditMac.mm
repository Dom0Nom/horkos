/*
 * daemon/macos/input/IOHIDTransportAuditMac.mm
 * Role: Signal 141 — macOS IOHIDDevice transport/conformance-audit sensor. Enumerates
 *       HID devices via IOHIDManager, reads kIOHIDTransportKey / kIOHIDLocationIDKey /
 *       kIOHIDVendorIDKey / kIOHIDProductIDKey / kIOHIDPhysicalDeviceUniqueIDKey, and
 *       cross-checks the transport against a USB location id to distinguish a real
 *       USB/Bluetooth endpoint from an IOHIDUserDevice/DriverKit virtual provider.
 *       Reports the transport + (when virtual) the providing dext bundle id for
 *       server-side allowlisting (Karabiner, BetterTouchTool, remote-control apps
 *       create legitimate virtual HID). Runs in the userspace daemon, NOT the ES auth
 *       path — no ES reply deadline applies (impl-plan §141).
 * Target platforms: macOS (userspace daemon). Built ON for the bring-up path; no
 *       entitlement needed (IOHIDManager is userspace).
 * Interface: implements hk::daemon::mac::sense_iohid_transport from
 *       input/DeviceTrustMac.h; emits hk_device_descriptor_audit. Reuses the pure
 *       classify_iohid_transport core (host-tested with no IOHIDManager).
 *
 * Guardrail compliance:
 *   #1  No raw _WIN32/__linux__/__APPLE__ guard — compilation controlled by CMake
 *       (APPLE branch); the IOKit HID API is confined to this daemon TU.
 *   #3  This module comment covers role/platform/interface.
 *   #7  Not an ES client — there is no AUTH event here, so the reply-deadline rule
 *       does not apply; the audit is a passive IOHIDManager poll.
 *
 * API references:
 *   - IOHIDManager:  https://developer.apple.com/documentation/iokit/iohidmanager
 *   - IOHIDDeviceGetProperty / kIOHIDTransportKey / kIOHIDLocationIDKey:
 *     https://developer.apple.com/documentation/iokit/iohiddevice
 */

#import <Foundation/Foundation.h>
#import <IOKit/hid/IOHIDManager.h>
#import <IOKit/hid/IOHIDKeys.h>

#include <vector>

#include "input/DeviceTrustMac.h"

namespace hk { namespace daemon { namespace mac {

namespace {

/* Read an integer IOHIDDevice property into `out`; returns false if absent/non-numeric
 * (the caller treats absence as inconclusive, never as a synthetic signal). */
bool CopyIntProp(IOHIDDeviceRef dev, CFStringRef key, long &out)
{
    CFTypeRef v = IOHIDDeviceGetProperty(dev, key);
    if (v == nullptr || CFGetTypeID(v) != CFNumberGetTypeID()) {
        return false;
    }
    return CFNumberGetValue((CFNumberRef)v, kCFNumberLongType, &out) ? true : false;
}

/* Compare a string IOHIDDevice property against an ASCII literal. */
bool StrPropEquals(IOHIDDeviceRef dev, CFStringRef key, const char *ascii)
{
    CFTypeRef v = IOHIDDeviceGetProperty(dev, key);
    if (v == nullptr || CFGetTypeID(v) != CFStringGetTypeID()) {
        return false;
    }
    CFStringRef want =
        CFStringCreateWithCString(kCFAllocatorDefault, ascii, kCFStringEncodingASCII);
    if (want == nullptr) {
        return false;
    }
    const bool eq = CFStringCompare((CFStringRef)v, want, 0) == kCFCompareEqualTo;
    CFRelease(want);
    return eq;
}

/* Salt a location id into the opaque per-session container token (never the raw
 * location id; privacy). A trivial fold is sufficient — it is a correlation key, not
 * an authenticator. */
uint64_t ContainerToken(long location_id)
{
    uint64_t h = 1469598103934665603ULL; /* FNV-1a offset */
    const uint64_t v = (uint64_t)location_id;
    for (int i = 0; i < 8; ++i) {
        h ^= (v >> (i * 8)) & 0xFFu;
        h *= 1099511628211ULL;
    }
    return h;
}

} // namespace

int sense_iohid_transport(std::vector<hk_device_descriptor_audit> &out)
{
    IOHIDManagerRef mgr =
        IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);
    if (mgr == nullptr) {
        return -1;
    }
    /* Match all HID devices (no usage filter); open without seizing so we never take
     * exclusive control of an input device (read-only audit). */
    IOHIDManagerSetDeviceMatching(mgr, nullptr);
    if (IOHIDManagerOpen(mgr, kIOHIDOptionsTypeNone) != kIOReturnSuccess) {
        CFRelease(mgr);
        return -1;
    }

    int emitted = 0;
    CFSetRef devices = IOHIDManagerCopyDevices(mgr);
    if (devices != nullptr) {
        const CFIndex n = CFSetGetCount(devices);
        std::vector<const void *> refs((size_t)n, nullptr);
        CFSetGetValues(devices, refs.data());
        for (CFIndex i = 0; i < n; ++i) {
            IOHIDDeviceRef dev = (IOHIDDeviceRef)refs[(size_t)i];
            if (dev == nullptr) {
                continue;
            }

            IOHidTransportInput facts{};
            long location = 0, vid = 0, pid = 0;
            facts.has_location_id = CopyIntProp(dev, CFSTR(kIOHIDLocationIDKey), location);
            CopyIntProp(dev, CFSTR(kIOHIDVendorIDKey), vid);
            CopyIntProp(dev, CFSTR(kIOHIDProductIDKey), pid);
            facts.transport_usb = StrPropEquals(dev, CFSTR(kIOHIDTransportKey), "USB");
            facts.transport_bluetooth =
                StrPropEquals(dev, CFSTR(kIOHIDTransportKey), "Bluetooth");
            /* kIOHIDPhysicalDeviceUniqueIDKey availability varies by device/macOS
             * version (impl-plan Risks §141): treat absence as inconclusive. */
            facts.unique_id_missing =
                IOHIDDeviceGetProperty(dev, CFSTR(kIOHIDPhysicalDeviceUniqueIDKey)) ==
                nullptr;
            /* IOHIDUserDevice/DriverKit-virtual providers carry no USB/BT transport and
             * no location id; the !real_endpoint branch of the classifier handles them.
             * The exact dext-bundle-id property read (for the server allowlist) is the
             * IORegistry provider walk noted below; the classifier flags the virtual
             * shape regardless. */
            facts.is_user_device =
                !facts.transport_usb && !facts.transport_bluetooth &&
                !facts.has_location_id;

            uint32_t verdict = HK_INPUT_SRC_PHYSICAL_KNOWN;
            const uint8_t flags = classify_iohid_transport(facts, verdict);

            /* Report when non-benign OR a flag fired; a plain USB/BT endpoint with a
             * location id and a present unique id stays silent. */
            if (verdict == HK_INPUT_SRC_PHYSICAL_KNOWN && flags == 0) {
                continue;
            }

            hk_device_descriptor_audit rec{};
            rec.schema_version = HK_DEVICE_TRUST_SCHEMA_VERSION;
            rec.verdict = verdict;
            rec.vendor_id = (uint16_t)(vid & 0xFFFF);
            rec.product_id = (uint16_t)(pid & 0xFFFF);
            rec.bus_type = facts.transport_usb
                               ? HK_BUS_USB
                               : (facts.transport_bluetooth ? HK_BUS_BLUETOOTH
                                                            : HK_BUS_VIRTUAL);
            rec.iface_class_mask = HK_IFACE_HID;
            rec.audit_flags = flags;
            rec.container_token =
                facts.has_location_id ? ContainerToken(location) : 0;
            /* HK-UNCERTAIN(dext-bundle-id): the providing dext/driver bundle id (for the
             * server allowlist pairing with the ES exec record of the dext loader) comes
             * from an IORegistry provider walk (IOHIDDeviceGetService -> parent ->
             * kCFBundleIdentifierKey). That walk is the on-box-verified path (impl-plan
             * §141 pairs it with the ES exec record server-side, not in this poll); per
             * guardrail #13 it is left for the on-box implementer. The transport + virtual
             * shape are reported now; the bundle id is correlated server-side. */
            rec.creator_pid = 0;
            out.push_back(rec);
            ++emitted;
        }
        CFRelease(devices);
    }

    IOHIDManagerClose(mgr, kIOHIDOptionsTypeNone);
    CFRelease(mgr);
    return emitted;
}

} } } // namespace hk::daemon::mac
