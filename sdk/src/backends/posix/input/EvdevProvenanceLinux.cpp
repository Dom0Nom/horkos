/*
 * Role: Signal 140 (userspace half) — evdev/uinput provenance correlator. Drains the
 *       hk_input_prov_bpf records the input_provenance.bpf.c program pushes into the
 *       shared ringbuf, supplements each with an EVIOCGID/EVIOCGPHYS poll over
 *       /dev/input/event*, attaches the uinput creator PID, classifies (BUS_VIRTUAL vs
 *       BUS_USB), and emits hk_device_descriptor_audit findings. The creator-PID is
 *       reported for the server's allowlist (Steam Input / Deck back-button-gyro
 *       remap / antimicro / accessibility remappers all use uinput) — the client never
 *       bans on uinput presence (catalog high-FP gate).
 * Target platforms: Linux userspace.
 * Interface: implements hk::sdk::posix::sense_evdev_provenance from
 *       input/DeviceTrustPosix.h; reuses the pure classify_evdev_provenance core.
 *       Guardrail #4: consumes the kernel record only via the userspace ringbuf API,
 *       never includes a .bpf.c header.
 */

#include "input/DeviceTrustPosix.h"

#if defined(HK_PLATFORM_LINUX) || defined(__linux__)

#include <cstdint>
#include <vector>

namespace hk { namespace sdk { namespace posix {

int sense_evdev_provenance(std::vector<hk_device_descriptor_audit> &out)
{
    /* HK-UNCERTAIN(bpf-ringbuf-drain + evdev-supplement): the live correlation needs
     * (a) the libbpf ringbuf consumer that delivers hk_input_prov_bpf records (owned by
     * the Linux eBPF Loader, kernel/linux/userspace/Loader.cpp — the device-trust drain
     * arm is added there when this domain's eBPF object is wired into the loader), and
     * (b) an EVIOCGID/EVIOCGPHYS ioctl poll over /dev/input/event* plus the uinput
     * creator-PID lookup (the kernel candidate creator_pid is re-validated against the
     * uinput fd owner via /proc, per the .bpf.c HK-UNCERTAIN). Both are integration the
     * loader/sdk tick owns and are absent in this scaffolding TU. Per guardrail #12 the
     * drain + ioctl supplement are left a stub here; the pure classify_evdev_provenance
     * core (the testable decision) is exercised by the host unit test and the bypass
     * test with synthetic facts. With no live drain wired, this emits nothing rather
     * than fabricating a provenance finding.
     *
     * The on-box implementer wires per drained hk_input_prov_bpf record:
     *   EvdevProvenanceInput f{};
     *   f.bustype = rec.bustype;
     *   f.emits_rel_or_key = (rec.evbit_rel_key & (HK_DT_EV_REL|HK_DT_EV_KEY)) != 0;
     *   f.has_usb_parent = sysfs_has_usb_parent(rec.input_dev_id);   // EVIOCGPHYS/sysfs
     *   f.creator_pid = resolve_uinput_creator(rec.creator_pid);     // /proc re-validate
     *   f.creator_resolved = (f.creator_pid != 0);
     *   uint32_t verdict; uint8_t flags = classify_evdev_provenance(f, verdict);
     *   // fill hk_device_descriptor_audit{ verdict, bus_type=map_bustype(...),
     *   //   audit_flags=flags, creator_pid=f.creator_pid, ... } and push.
     */
    (void)out;
    return 0;
}

} } } // namespace hk::sdk::posix

#endif /* HK_PLATFORM_LINUX || __linux__ */
