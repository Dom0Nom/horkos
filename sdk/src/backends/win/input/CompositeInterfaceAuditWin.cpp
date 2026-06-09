/*
 * sdk/src/backends/win/input/CompositeInterfaceAuditWin.cpp
 * Role: Signal 143 — composite-interface-collection sensor. Over the shared
 *       UsbTopology snapshot (config-descriptor IAD parse + interface-class set),
 *       flags an input device (HID, bInterfaceClass 0x03) co-resident with a
 *       CDC-ACM / vendor-serial interface under ONE ContainerID
 *       (HK_DAUD_CONTAINER_MISMATCH). Known vendor composite layouts (HID + CDC RGB
 *       channel) are reported-but-benign and allowlisted server-side; FP gate is low.
 * Target platforms: Windows userspace.
 * Interface: implements hk::sdk::win::sense_composite_interface from
 *       input/DeviceTrustWin.h; emits hk_device_descriptor_audit. Reuses the pure
 *       fold_composite_interface_flags core (host-tested with no Win32). The
 *       DEVPKEY_Device_ContainerId read is folded into the snapshot's container_token;
 *       this sensor only consumes the snapshot.
 */

#include "input/DeviceTrustWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <vector>

namespace hk { namespace sdk { namespace win {

int sense_composite_interface(const UsbTopology &topo,
                              std::vector<hk_device_descriptor_audit> &out)
{
    int emitted = 0;
    for (const UsbNode &n : topo.nodes) {
        if (n.query_failed) {
            /* Descriptors not resolvable -> report inconclusive, never a mismatch. */
            hk_device_descriptor_audit rec{};
            rec.schema_version = HK_DEVICE_TRUST_SCHEMA_VERSION;
            rec.verdict = HK_INPUT_SRC_UNRESOLVED;
            rec.vendor_id = n.vendor_id;
            rec.product_id = n.product_id;
            rec.bus_type = HK_BUS_USB;
            rec.iface_class_mask = n.iface_class_mask;
            rec.audit_flags = HK_DAUD_INCONCLUSIVE;
            rec.container_token = n.container_token;
            out.push_back(rec);
            ++emitted;
            continue;
        }

        const uint8_t flags =
            fold_composite_interface_flags(n.iface_class_mask, n.has_iad != 0);
        if (flags == 0) {
            continue; /* not a HID+serial composite -> silent */
        }

        hk_device_descriptor_audit rec{};
        rec.schema_version = HK_DEVICE_TRUST_SCHEMA_VERSION;
        /* Co-residency is reported with the descriptor-incoherent bucket so the server
         * fuses it with the 137 coherence finding under the same ContainerID; the
         * server allowlists known vendor composites (catalog FP gate). */
        rec.verdict = HK_INPUT_SRC_DESCRIPTOR_INCOHERENT;
        rec.vendor_id = n.vendor_id;
        rec.product_id = n.product_id;
        rec.bcd_usb = n.bcd_usb;
        rec.bcd_device = n.bcd_device;
        rec.max_packet_size0 = n.max_packet_size0;
        rec.bus_type = HK_BUS_USB;
        rec.iface_class_mask = n.iface_class_mask;
        rec.audit_flags = flags;
        rec.container_token = n.container_token;
        out.push_back(rec);
        ++emitted;
    }
    return emitted;
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
