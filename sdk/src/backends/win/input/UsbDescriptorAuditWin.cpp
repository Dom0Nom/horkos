/*
 * Role: Signal 137 — USB device-descriptor self-consistency sensor. Over the shared
 *       UsbTopology snapshot, cross-checks (VID, PID, bcdDevice, bMaxPacketSize0,
 *       iSerialNumber-presence) coherence and classifies HK_INPUT_SRC_DESCRIPTOR_
 *       INCOHERENT only on the catalog's narrow condition (a major-vendor VID combined
 *       with a known bridge-chip descriptor signature, e.g. CH340/CP2102/FTDI). The
 *       known-hardware corpus correlation is server-side; the client only ships the
 *       tuple + the resolved verdict bucket.
 * Target platforms: Windows userspace.
 * Interface: implements hk::sdk::win::sense_usb_descriptor_audit from
 *       input/DeviceTrustWin.h; emits hk_device_descriptor_audit. Reuses the pure
 *       classify_descriptor_coherence core (host-tested with no Win32).
 */

#include "input/DeviceTrustWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <vector>

namespace hk { namespace sdk { namespace win {

namespace {

/* Major peripheral-vendor VID set (Logitech 0x046D, Razer 0x1532, Corsair 0x1B1C,
 * SteelSeries 0x1038, Microsoft 0x045E, Glorious/PixArt-OEM 0x258A). Server keeps the
 * authoritative corpus; this local set only gates the "major vendor over a bridge
 * chip" condition so a hobby board with its own VID never trips 137. */
bool IsMajorVendorVid(uint16_t vid)
{
    switch (vid) {
    case 0x046D: case 0x1532: case 0x1B1C:
    case 0x1038: case 0x045E: case 0x258A:
        return true;
    default:
        return false;
    }
}

/* A CH340/CP2102/FTDI USB-serial bridge has a small, characteristic descriptor: a
 * 64-byte EP0 (bMaxPacketSize0 == 8 on the CH340, 64 on FTDI/CP2102) combined with a
 * CDC/vendor interface class and a bcdDevice in the bridge-chip ranges. The exact
 * corpus is server-side; this is a coarse local signature used ONLY to set the soft
 * HK_DAUD_BRIDGE_SIGNATURE bit, which alone is never a verdict. */
bool LooksLikeBridgeChip(const UsbNode &n)
{
    const bool serial_like =
        (n.iface_class_mask & (HK_IFACE_CDC | HK_IFACE_VENDOR)) != 0;
    const bool small_ep0 = (n.max_packet_size0 == 8 || n.max_packet_size0 == 64);
    return serial_like && small_ep0;
}

} // namespace

int sense_usb_descriptor_audit(const UsbTopology &topo,
                               std::vector<hk_device_descriptor_audit> &out)
{
    int emitted = 0;
    for (const UsbNode &n : topo.nodes) {
        DescriptorCoherenceInput cin{};
        cin.query_failed = (n.query_failed != 0);
        cin.major_vendor_vid = IsMajorVendorVid(n.vendor_id);
        cin.bridge_chip_signature = LooksLikeBridgeChip(n);
        cin.serial_present = (n.serial_present != 0);
        /* A HID input device under a major vendor normally ships a serial; a bare CDC
         * bridge does not. Only require it where the bus class implies it. */
        cin.serial_expected = (n.iface_class_mask & HK_IFACE_HID) != 0;

        uint32_t verdict = HK_INPUT_SRC_PHYSICAL_KNOWN;
        const uint8_t flags = classify_descriptor_coherence(cin, verdict);

        /* Report a record when the verdict is non-benign OR any soft flag fired, so a
         * fully-coherent mainstream device stays silent (catalog: report anomalies +
         * their gates, not every device). */
        if (verdict == HK_INPUT_SRC_PHYSICAL_KNOWN && flags == 0) {
            continue;
        }

        hk_device_descriptor_audit rec{};
        rec.schema_version = HK_DEVICE_TRUST_SCHEMA_VERSION;
        rec.verdict = verdict;
        rec.vendor_id = n.vendor_id;
        rec.product_id = n.product_id;
        rec.bcd_usb = n.bcd_usb;
        rec.bcd_device = n.bcd_device;
        rec.max_packet_size0 = n.max_packet_size0;
        rec.bus_type = HK_BUS_USB;
        rec.iface_class_mask = n.iface_class_mask;
        rec.audit_flags = flags;
        rec.container_token = n.container_token;
        rec.creator_pid = 0;
        out.push_back(rec);
        ++emitted;
    }
    return emitted;
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
