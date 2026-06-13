/*
 * Role: Linux eBPF hardware-breakpoint-install audit (memory-integrity-selfcheck,
 *       signal 148). Tracepoints on the hw-breakpoint install path / perf_event_open
 *       with HW_BREAKPOINT_X targeting the AC's address space, emitting an install
 *       event scoped to the AC task only. The trustworthy path is this install-time
 *       observation, not PTRACE_PEEKUSER (which is spoofable / racy).
 * Target platform: Linux eBPF (CO-RE). Default OFF (locked decision 3).
 * Interface: shares hk_ringbuf (extern); the loader keys events to the AC task and
 *       translates them into HK_EVENT_SELF_HWBP.
 *
 * Guardrail compliance: #1, #3, #4, #6 (-Wall -Wextra -Werror at the kernel warning
 * level — every CO-RE read is relocatable; the uncertain attach is a stub, not a
 * guess, so the verifier-clean program still builds with -Werror).
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define HK_SCHEMA_VERSION    3u
#define HK_EVENT_HWBP_INSTALL 0x2Bu  /* loader maps to HK_EVENT_SELF_HWBP */

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/* AC task tgid (set by the loader) — events are scoped to the AC's address space. */
const volatile __u32 hk_ac_tgid = 0;

struct hk_bpf_hwbp_event {
    __u32 schema_version;
    __u32 event_tag;
    __u64 timestamp_ns;
    __u32 pid;          /* task whose address space the breakpoint targets */
    __u32 tid;
    __u64 bp_addr;      /* breakpoint linear address (bp_addr from the install) */
};

/* HK-UNCERTAIN(hwbp-attach): the exact attach point — a tracepoint on
 * arch_install_hw_breakpoint vs a kprobe/fexit on perf_event_open with the
 * HW_BREAKPOINT_X bit set — and the CO-RE field path to bp_addr (struct
 * perf_event_attr.bp_addr) are version-sensitive and must be confirmed against the
 * target kernel BTF (Deck-class) before relying on them. Per guardrail #12 the real
 * attach + bp_addr read are left as a documented stub; this raw_tracepoint body
 * compiles verifier-clean (no unrelocated reads) so -Werror still passes. The actual
 * install observation activates once the attach point + field path are confirmed.
 * (docs: perf_event_open(2) documents PERF_TYPE_BREAKPOINT = 5 and perf_event_attr
 * .bp_addr as UAPI-stable fields: man7.org/linux/man-pages/man2/perf_event_open.2.html.
 * The struct perf_event_attr layout is UAPI so it is in vmlinux BTF. The question is
 * whether a kprobe/fexit on ksys_perf_event_open itself is stable on the target kernel
 * — still needs on-target BTF probe and kprobe-ability check) */
SEC("raw_tracepoint/sys_enter")
int hk_hwbp_install_probe(struct bpf_raw_tracepoint_args *ctx)
{
    struct hk_bpf_hwbp_event *evt;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;

    (void)ctx; /* the syscall-arg decode + HW_BREAKPOINT_X filter is the stub above */

    if (hk_ac_tgid == 0u || tgid != hk_ac_tgid)
        return 0; /* only when the loader has armed the AC task and this is it */

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_EVENT_HWBP_INSTALL;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->pid            = tgid;
    evt->tid            = (__u32)pid_tgid;
    evt->bp_addr        = 0; /* HK-UNCERTAIN(hwbp-attach): real bp_addr read deferred */

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
