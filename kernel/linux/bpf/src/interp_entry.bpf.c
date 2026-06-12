/*
 * Role: uprobe on the mapped dynamic loader's entry/_start to confirm WHICH
 *       ld.so actually serviced relocation for a watched exec. Emits a compact
 *       record so the userspace correlator InterpCheck.cpp (signal 84) can
 *       correlate the live interpreter identity against PT_INTERP + the mapped
 *       loader's NT_GNU_BUILD_ID, resolving the expected interpreter through the
 *       container manifest (Flatpak / Steam pressure-vessel) before scoring.
 *       The PT_INTERP / build-id read is entirely userspace (guardrail #4).
 * Target platform: Linux eBPF (uprobe, kernel >= 4.17; shared ringbuf >= 5.8).
 * Interface: reuses the existing tracepoint/sched/sched_process_exec
 *            (tracepoints.bpf.c) to learn of the protected exec; shares
 *            hk_ringbuf (extern); Loader.cpp translates HK_EVENT_INTERP.
 *
 * Guardrail compliance: #1, #3, #4, #6.
 *
 * HK-UNCERTAIN(glibc-internal): locating the loader entry symbol reliably across
 * ld.so builds is unverified. ld.so's `_start` / `_dl_start` are internal and
 * vary by glibc version and are absent/renamed on musl. The attach must resolve
 * the entry offset per target from the mapped interpreter in /proc/<pid>/maps and
 * skip the signal gracefully when it cannot. Left as the cadence/identity event
 * (reports "the interpreter entry fired for this pid") without dereferencing any
 * loader-internal struct in-kernel; userspace does the build-id comparison. Do
 * NOT guess the entry offset.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define HK_SCHEMA_VERSION   3u
#define HK_EVENT_INTERP     0x24u   /* loader maps to HK_EVENT_INTERP_MISMATCH */

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

struct hk_bpf_interp_event {
    __u32 schema_version;
    __u32 event_tag;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 reserved;
    __u64 entry_ip;     /* instruction pointer at the loader entry uprobe */
};

/* ---- uprobe: dynamic-loader entry ---------------------------------------- */
SEC("uprobe")
int BPF_KPROBE(hk_uprobe_interp_entry)
{
    struct hk_bpf_interp_event *evt;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_EVENT_INTERP;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->pid            = bpf_get_current_pid_tgid() >> 32;
    evt->reserved       = 0;
    /* PT_REGS_IP gives the user IP at the probe — confirms the entry fired and
     * lets userspace anchor it against the mapped interpreter's VMA range. */
    evt->entry_ip       = PT_REGS_IP(ctx);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
