/*
 * Role: Signal 108 — synthetic-input (uinput/evdev) audit. The injecting tgid is
 *       attributed and the EV type/code emitted; the Steam-Input/hid-steam/
 *       gamescope-libinput allowlist + pre-focus gate is userspace
 *       (DeckInputBaseline.cpp). HIGH FP — weighted server-correlated signal only.
 * Target platform: Linux eBPF (kprobe).
 * Interface: shares hk_ringbuf; emits HK_BPF_PW_SYNTH_INPUT -> HK_EVENT_SYNTH_INPUT.
 *
 * Guardrail compliance: #1 Linux-only by gating; #3 module comment; #4 pure BPF
 *   TU; #6 -Wall -Wextra -Werror. #13: uinput_create_device / input_inject_event
 *   are INTERNAL symbols (kprobe-by-name, possibly inlined) — flagged uncertain
 *   below; this whole program is gated behind HORKOS_LINUX_EBPF_KPROBES (default
 *   OFF) per the impl-plan sequencing.
 *
 * The create-device arm uses a STABLE handle: the /dev/uinput open path via the
 * uinput_open fop, which is non-inlined. The inject arm and the
 * uinput_create_device kprobe are the ABI-fragile ones and carry the HK-UNCERTAIN.
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

static __always_inline void
hk_emit_synth_input(__u32 flags, __u32 ev_type, __u32 ev_code)
{
    struct hk_bpf_pw_synth_input *evt;
    __u64 now = bpf_ktime_get_ns();

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->schema_version = HK_PW_SCHEMA_VERSION;
    evt->event_tag      = HK_BPF_PW_SYNTH_INPUT;
    evt->timestamp_ns   = now;
    evt->injector_tgid  = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt->flags          = flags;   /* MID_SESSION/OFF_ALLOWLIST set userspace */
    evt->ev_type        = ev_type;
    evt->ev_code        = ev_code;
    evt->event_time_ns  = now;

    bpf_ringbuf_submit(evt, 0);
}

/*
 * STABLE arm: kprobe on uinput_open — the registered file_operations.open for
 * /dev/uinput (drivers/input/misc/uinput.c). uinput_open is a non-inlined fop
 * pointer target, so kprobe-by-name is reliable. A /dev/uinput open is the
 * precursor to a uinput device creation; the create itself is confirmed by the
 * (uncertain) uinput_create_device arm below. We emit the create-precursor here
 * so the signal is present even when the create kprobe is unavailable.
 *
 * Signature: int uinput_open(struct inode *inode, struct file *file).
 */
SEC("kprobe/uinput_open")
int BPF_KPROBE(hk_kp_uinput_open, struct inode *inode, struct file *file)
{
    (void)inode; (void)file;
    hk_emit_synth_input(HK_PW_SYNTH_UINPUT_CREATE, 0, 0);
    return 0;
}

/*
 * HK-UNCERTAIN(uinput-internal-symbols): the impl-plan's precise arms are kprobes
 * on uinput_create_device (the actual device-creation, post UI_DEV_CREATE ioctl)
 * and input_inject_event (the per-event injection carrying EV type/code). Both
 * are INTERNAL kernel symbols: kprobe-attach-by-name is NOT ABI-stable and they
 * may be inlined on some kernel builds (input_inject_event in particular is a
 * small wrapper frequently inlined). Per guardrail #13 these arms are NOT
 * written — confirm kprobe-ability on the target Deck kernel (check
 * /sys/kernel/debug/tracing/available_filter_functions or BTF), then add:
 *   SEC("kprobe/uinput_create_device")
 *   int BPF_KPROBE(hk_kp_uinput_create, ...) {
 *       hk_emit_synth_input(HK_PW_SYNTH_UINPUT_CREATE, 0, 0);
 *   }
 *   SEC("kprobe/input_inject_event")
 *   int BPF_KPROBE(hk_kp_input_inject, struct input_handle *handle,
 *                  unsigned int type, unsigned int code, int value) {
 *       hk_emit_synth_input(HK_PW_SYNTH_INJECT, type, code);
 *   }
 * If either is inlined/unprobeable, the uinput_open arm above plus userspace
 * evdev sysfs enumeration (DeckInputBaseline.cpp) is the fallback (loses the
 * per-event EV type/code precision). This whole TU is built only when
 * HORKOS_LINUX_EBPF_KPROBES is ON.
 */

char _license[] SEC("license") = "GPL";
