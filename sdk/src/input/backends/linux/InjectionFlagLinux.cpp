/*
 * Role: Linux input-provenance sensor (catalog signal 171 analog). Distinguishes a
 *       real /dev/input HID node from a uinput-created VIRTUAL device via libudev
 *       (ID_INPUT properties), and sets virtual_device_present when the active aim
 *       device this tick is virtual. Steam Input, Deck back-button/gyro remap,
 *       antimicro and accessibility remappers all create uinput devices — this
 *       SEGREGATES COHORTS, it does not convict; the client reports presence and
 *       the server decides (catalog high-FP gate). Linux has no per-event
 *       LLMHF_INJECTED equivalent, so the injected FRACTION (Q0.8) stays 0 here;
 *       the virtual-device bit carries 171 on Linux.
 * Target platforms: Linux userspace. Guardrail #1: the libudev provenance read is
 *       confined to this backend. USERSPACE — separate from the eBPF/LKM kernel
 *       plane (guardrail #4); this includes no .bpf.c header.
 * Interface: implements hk::sdk::aim::sample_injection_flag from
 *       input/AimSampler.h. Catalog slot 171.
 *
 * HK-UNCERTAIN(uinput-id-input-property): the exact libudev property set marking a
 * uinput-created virtual device (ID_INPUT vs the absence of a USB/PCI parent vs a
 * BUS_VIRTUAL bustype) varies by distro / udev version (Steam Deck included). I am
 * NOT certain which single property reliably flags a virtual device across the
 * target distros. Per guardrail #13 (plan R6) the property is not guessed: the
 * live udev query shape is documented below but no enumeration is performed here,
 * and virtual_device_present is left at its 0 default until the property is
 * confirmed on-box. (Userspace, no BSOD/kernel risk — a detection-validity flag.)
 */

#include "input/AimSampler.h"

#include "platform.h"

#if defined(HK_PLATFORM_LINUX) || defined(__linux__)

#include <cstdint>

namespace hk { namespace sdk { namespace aim {

bool sample_injection_flag(hk_aim_features* out)
{
    if (out == nullptr) {
        return false;
    }

    /* HK-UNCERTAIN(uinput-id-input-property): no confirmed virtual-device property
     * (see file header). The live udev query, once the SDK supplies the active aim
     * device's evdev node path and the virtual-marking property is confirmed:
     *
     *   struct udev* u = udev_new();
     *   struct udev_device* d = udev_device_new_from_subsystem_sysname(
     *                               u, "input", event_sysname);
     *   // walk to the parent input device, then test the confirmed property,
     *   // e.g. absence of a usb/pci parent + ID_INPUT set, or a BUS_VIRTUAL
     *   // bustype via EVIOCGID — the exact rule is the on-box-confirmed one:
     *   bool virtual_dev = device_is_uinput_virtual(d);  // confirmed predicate
     *   out->virtual_device_present = virtual_dev ? 1 : 0;
     *   udev_device_unref(d); udev_unref(u);
     *
     * With the property unconfirmed, leave virtual_device_present at default — the
     * server reads "no virtual-source signal", never a fabricated cohort flag.
     * injected_event_fraction_q8 stays 0: Linux evdev has no per-event injected
     * bit (the Windows LLMHF_INJECTED analog), so the fraction is not a Linux
     * signal — the virtual-device bit carries 171 here. */
    (void)out;
    return false; /* virtual-device property unconfirmed: no 171 sample this tick */
}

} } } // namespace hk::sdk::aim

#endif /* HK_PLATFORM_LINUX || __linux__ */
