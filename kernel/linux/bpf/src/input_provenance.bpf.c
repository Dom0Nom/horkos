/*
 * Role: Signal 140 — evdev/uinput virtual-device provenance sensor. CO-RE reads of
 *       input_dev->id.{bustype,vendor,product} on device registration, pushing a
 *       compact hk_input_prov_bpf record into the shared hk_ringbuf. The userspace
 *       half (EvdevProvenanceLinux.cpp) correlates BUS_VIRTUAL + no-USB-parent +
 *       EV_REL/EV_KEY, attaches the creator PID, and emits the wire finding.
 * Target platform: Linux eBPF (CO-RE; kprobe on input_register_device).
 * Interface: emits the BPF tag HK_BPF_DT_INPUT_PROV into hk_ringbuf (extern, defined
 *            in lsm_file_open.bpf.c, repointed by Loader.cpp); consumed by
 *            EvdevProvenanceLinux.cpp which repacks into hk_device_descriptor_audit.
 *
 * Guardrail compliance:
 *   #1  No raw platform macros — Linux-only by build gating.
 *   #3  This module comment covers role/platform/interface.
 *   #4  Pure kernel eBPF TU — no userspace headers; the wire struct lives separately.
 *   #6  Compiled -Wall -Wextra -Werror (CMakeLists.txt).
 *   #13 The parent-chain usb_device walk and the creator-PID context are FLAGGED
 *       UNCERTAIN by the impl-plan (Risks §140) and are left as documented stubs
 *       below — a wrong CO-RE read is a verifier reject or a bad signal; the on-box
 *       implementer confirms the chain on the target (Steam Deck) kernel BTF first.
 *
 * API references:
 *   - input_register_device:  drivers/input/input.c (kernel source)
 *   - BPF_CORE_READ:          https://docs.ebpf.io/linux/concepts/CO-RE/
 *   - bpf_get_current_pid_tgid: https://docs.ebpf.io/linux/helper-function/bpf_get_current_pid_tgid/
 *
 * BPF-LSM / attach PREREQUISITE (document, do not assume): this program attaches a
 * kprobe on input_register_device. Whether that symbol is the stable, non-inlined
 * attach point for capturing the uinput creator on the target kernel is UNCERTAIN
 * (impl-plan Risks §140) — confirm via /sys/kernel/debug/tracing/available_filter_
 * functions or BTF before relying on creator-PID attribution.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "hk_bpf_shared.h"

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/* Stable per-device cookie: low 32 bits of the input_dev pointer. Not the kernel
 * address that ships to userspace (the userspace half re-keys to EVIOCGID), only a
 * within-session correlation id so a register/event pair can be joined. */
static __always_inline __u32 hk_dev_cookie(const void *input_dev)
{
    return (__u32)((unsigned long)input_dev & 0xFFFFFFFFu);
}

/*
 * input_register_device(struct input_dev *dev) — the device-registration entry. The
 * id.{bustype,vendor,product} fields are populated by the driver before this call, so
 * they are CO-RE-readable here. The EV_REL/EV_KEY capability bits live in dev->evbit
 * (an unsigned long bitmap); we read the first word and test the two bits we classify
 * on (BUS_VIRTUAL + EV_REL is the uinput-mouse shape).
 */
SEC("kprobe/input_register_device")
int BPF_KPROBE(hk_kp_input_register, struct input_dev *dev)
{
    struct hk_input_prov_bpf *evt;
    __u16 bustype = 0, vendor = 0, product = 0;
    __u8  evbits = 0;

    if (!dev)
        return 0;

    bustype = BPF_CORE_READ(dev, id.bustype);
    vendor  = BPF_CORE_READ(dev, id.vendor);
    product = BPF_CORE_READ(dev, id.product);

    /* evbit is `unsigned long evbit[BITS_TO_LONGS(EV_CNT)]`. EV_REL == 0x02,
     * EV_KEY == 0x01, both in the first long. Read word 0 CO-RE-relocatably. */
    {
        unsigned long ev0 = BPF_CORE_READ(dev, evbit[0]);
        if (ev0 & (1UL << 0x02)) /* EV_REL */
            evbits |= HK_DT_EV_REL;
        if (ev0 & (1UL << 0x01)) /* EV_KEY */
            evbits |= HK_DT_EV_KEY;
    }

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->schema_version = HK_PW_SCHEMA_VERSION;
    evt->event_tag      = HK_BPF_DT_INPUT_PROV;
    evt->ts_ns          = bpf_ktime_get_ns();
    evt->input_dev_id   = hk_dev_cookie(dev);
    evt->bustype        = bustype;
    evt->vendor         = vendor;
    evt->product        = product;
    evt->evbit_rel_key  = evbits;

    /*
     * HK-UNCERTAIN(creator-pid): the impl-plan's FP gate (the entire Steam-Input
     * allowlist) depends on creator_pid being the PID that created the uinput device.
     * Whether bpf_get_current_pid_tgid() in the input_register_device context is the
     * CREATOR (the process that issued UI_DEV_CREATE) vs a kernel worker thread is NOT
     * verified across kernels (impl-plan Risks §140). Per guardrail #13 we do NOT
     * assert it here: creator_pid is set to the current tgid as a CANDIDATE only, and
     * the userspace half re-validates it against /proc and the uinput fd owner before
     * trusting it. If the on-box check shows this context is a worker, the userspace
     * half ignores this field and falls back to the uinput-open owner.
     */
    evt->creator_pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    /*
     * HK-UNCERTAIN(usb-parent-walk): has_usb_parent requires walking
     * input_dev->dev.parent up the device tree to a usb_device, comparing
     * dev->bus == &usb_bus_type (or the device-type name) CO-RE-relocatably. The
     * pointer chain + struct shapes may not be CO-RE-relocatable on every target
     * (impl-plan Risks §140 flags the Deck kernel specifically), and a wrong read is a
     * verifier reject or a bad signal. Per guardrail #13 the walk is NOT written: we
     * report has_usb_parent = 0 (unknown) and the userspace half derives the USB-parent
     * fact from EVIOCGPHYS / sysfs (/sys/class/input/eventN/device/.. parent), which is
     * stable. The server treats 0 here as "unknown", never "no USB parent".
     */
    evt->has_usb_parent = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
