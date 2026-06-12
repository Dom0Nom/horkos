/*
 * Role: Shared USB hub/node descriptor snapshot provider for the device-trust
 *       sensors (catalog 137/139/143). Enumerates GUID_DEVINTERFACE_USB_HUB, walks
 *       each hub's node connections, and pulls the raw 18-byte device descriptor, the
 *       configuration descriptor (interface-class set + IAD presence + interrupt-IN
 *       endpoint bInterval), and serial-string presence via
 *       IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX +
 *       IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION. Read-only: it reads descriptors
 *       and topology; it never sends a SET_DESCRIPTOR or any control transfer.
 * Target platforms: Windows userspace. Guardrail #1: the one place these sensors touch
 *       the USB hub IOCTL surface; confined to backends/win/ and HK_PLATFORM_WINDOWS-
 *       gated (with the _WIN32 fallback the sibling headers use).
 * Interface: implements hk::sdk::win::build_usb_topology from input/DeviceTrustWin.h.
 */

#include "input/DeviceTrustWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>
#include <setupapi.h>
#include <usbioctl.h>
#include <usbiodef.h>
#include <cfgmgr32.h>

#include <atomic>

namespace hk { namespace sdk { namespace win {

namespace {

/* Per-session opaque container-token counter. The raw ContainerID GUID / hub+port is
 * never shipped (privacy; data-categories §5); the snapshot hands out a monotonic
 * per-session id instead. Starts at 1 so 0 stays "unresolved". */
std::atomic<uint64_t> g_next_container{1};

/* Map a USB bInterfaceClass byte to the HK_IFACE_* bit. */
uint8_t IfaceClassBit(uint8_t b_interface_class)
{
    switch (b_interface_class) {
    case 0x03: return HK_IFACE_HID;
    case 0x02: /* CDC control */
    case 0x0A: return HK_IFACE_CDC; /* CDC data */
    case 0x09: return HK_IFACE_HUB;
    case 0xFF: return HK_IFACE_VENDOR;
    default:   return 0;
    }
}

/* Parse a configuration descriptor blob into the interface-class mask, IAD presence,
 * and the first interrupt-IN endpoint bInterval. The blob is the standard
 * USB_CONFIGURATION_DESCRIPTOR followed by interface/endpoint/IAD descriptors, each
 * prefixed by {bLength, bDescriptorType}. We walk by bLength only (never fixed
 * offsets) and stop at wTotalLength so a malformed device cannot read OOB. */
void ParseConfigDescriptor(const uint8_t *buf, size_t len, UsbNode &node)
{
    if (buf == nullptr || len < sizeof(USB_CONFIGURATION_DESCRIPTOR)) {
        node.query_failed = 1;
        return;
    }
    const USB_CONFIGURATION_DESCRIPTOR *cfg =
        reinterpret_cast<const USB_CONFIGURATION_DESCRIPTOR *>(buf);
    size_t total = cfg->wTotalLength;
    if (total > len) {
        total = len; /* clamp to what we actually read */
    }

    size_t off = 0;
    while (off + 2 <= total) {
        const uint8_t b_length = buf[off];
        const uint8_t b_type = buf[off + 1];
        if (b_length < 2 || off + b_length > total) {
            break; /* malformed; stop rather than read past the record */
        }
        switch (b_type) {
        case USB_INTERFACE_ASSOCIATION_DESCRIPTOR_TYPE:
            node.has_iad = 1;
            break;
        case USB_INTERFACE_DESCRIPTOR_TYPE:
            if (b_length >= sizeof(USB_INTERFACE_DESCRIPTOR)) {
                const USB_INTERFACE_DESCRIPTOR *id =
                    reinterpret_cast<const USB_INTERFACE_DESCRIPTOR *>(buf + off);
                node.iface_class_mask |= IfaceClassBit(id->bInterfaceClass);
            }
            break;
        case USB_ENDPOINT_DESCRIPTOR_TYPE:
            if (b_length >= sizeof(USB_ENDPOINT_DESCRIPTOR)) {
                const USB_ENDPOINT_DESCRIPTOR *ep =
                    reinterpret_cast<const USB_ENDPOINT_DESCRIPTOR *>(buf + off);
                const bool is_in = (ep->bEndpointAddress & 0x80u) != 0;
                const bool is_interrupt = (ep->bmAttributes & 0x03u) == 0x03u;
                if (is_in && is_interrupt && node.in_interrupt_binterval == 0) {
                    node.in_interrupt_binterval = ep->bInterval;
                }
            }
            break;
        default:
            break;
        }
        off += b_length;
    }
}

} // namespace

bool build_usb_topology(UsbTopology &out)
{
    out.nodes.clear();

    /* HK-UNCERTAIN(usb-hub-ioctl-access): the plan FLAGS (Risks §137/139/143) that it
     * is NOT verified a non-elevated usermode process can open the USB hub interface
     * (\\.\HCDx / GUID_DEVINTERFACE_USB_HUB) and issue
     * IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION /
     * IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX on every Windows 11 build, or
     * whether it needs the Horkos service's SYSTEM context. The exact privilege /
     * handle-share semantics MUST be verified on the Phase-3 Win11 25H2 box before
     * relying on the hub-IOCTL path; if blocked, the fallback is
     * SetupDiGetDeviceProperty / cfgmgr32 (DEVPKEY_Device_*) for the subset of fields
     * exposed there. Per guardrail #13 the live hub-IOCTL walk is NOT written here —
     * the scaffold below enumerates the hub interface set and leaves the per-node
     * descriptor IOCTL exchange as the documented stub. Until verified, every node is
     * reported HK_DAUD_INCONCLUSIVE / query_failed so no sensor fabricates an anomaly
     * from an absent descriptor.
     *
     * The verified shape of the live walk (for the on-box implementer):
     *   1. SetupDiGetClassDevs(&GUID_DEVINTERFACE_USB_HUB, ..., DIGCF_PRESENT |
     *      DIGCF_DEVICEINTERFACE) and SetupDiEnumDeviceInterfaces /
     *      SetupDiGetDeviceInterfaceDetailW to get each hub's \\?\USB#... path.
     *   2. CreateFileW(hub_path, GENERIC_WRITE, FILE_SHARE_WRITE, ...) — the hub
     *      IOCTLs require a writable handle even though they only READ descriptors.
     *   3. IOCTL_USB_GET_NODE_INFORMATION for the port count, then per port
     *      IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX (ConnectionStatus, the cached
     *      USB_DEVICE_DESCRIPTOR, speed) and
     *      IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION with a
     *      USB_DESCRIPTOR_REQUEST setup packet for the config + string descriptors.
     *   4. Fill the UsbNode fields below from the returned descriptors; ParseConfig-
     *      Descriptor() above is ready to consume the config blob; the speed field
     *      sets high_speed; a wireless receiver/dongle sets wireless_dongle (from the
     *      parent-device vendor/driver — itself an on-box check). Assign
     *      node.container_token = g_next_container.fetch_add(1) per ContainerID.
     */

    HDEVINFO dev_info = SetupDiGetClassDevsW(
        &GUID_DEVINTERFACE_USB_HUB, nullptr, nullptr,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (dev_info == INVALID_HANDLE_VALUE) {
        return false; /* no inventory; callers degrade to inconclusive */
    }

    SP_DEVICE_INTERFACE_DATA iface{};
    iface.cbSize = sizeof(iface);
    for (DWORD i = 0;
         SetupDiEnumDeviceInterfaces(dev_info, nullptr, &GUID_DEVINTERFACE_USB_HUB,
                                     i, &iface);
         ++i) {
        /* One placeholder node per present hub interface. The per-node descriptor IOCTL
         * exchange is the HK-UNCERTAIN path above: until it is implemented on-box, the
         * node is reported inconclusive (query_failed) so the coherence/composite/
         * cadence sensors all degrade safely rather than reading zeroed descriptors as
         * a real (VID=0,PID=0) device. */
        UsbNode node{};
        node.container_token = g_next_container.fetch_add(1);
        node.query_failed = 1; /* descriptors not yet fetched (HK-UNCERTAIN path) */
        out.nodes.push_back(node);
    }

    SetupDiDestroyDeviceInfoList(dev_info);
    return true;
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
