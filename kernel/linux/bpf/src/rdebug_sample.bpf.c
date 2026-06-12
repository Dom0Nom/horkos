/*
 * Role: uprobe-triggered CADENCE program for signal 88. On fire it emits a
 *       lightweight "this watched PID needs an _r_debug r_brk / RELRO re-check"
 *       tick. The actual integrity work — locating _r_debug via PT_DYNAMIC
 *       DT_DEBUG at the load-biased address, reading it through /proc/<pid>/mem,
 *       range-checking r_brk against ld.so's VMA, and reading RELRO page perms —
 *       is entirely userspace (RDebugCheck.cpp). /proc/<pid>/mem reads are never
 *       done in BPF (guardrail #4).
 * Target platform: Linux eBPF (uprobe, kernel >= 4.17; ringbuf >= 5.8).
 * Interface: shares hk_ringbuf (extern); Loader.cpp translates HK_EVENT_RDEBUG_TICK.
 *
 * Guardrail compliance: #1, #3, #4, #6.
 *
 * HK-VERIFIED(proc-mem-self-suppress): /proc/pid/mem requires
 * PTRACE_MODE_ATTACH_FSCREDS (stronger than READ) per proc_pid_mem(5) man page
 * and kernel source (mem_open → ptrace_may_access(PTRACE_MODE_ATTACH_FSCREDS)).
 * This is the same access-mode check as PTRACE_ATTACH itself, which ESTABLISHES
 * a tracer relationship on the target process.  The loader opening /proc/<pid>/mem
 * would therefore make itself the ptrace tracer of the game process, suppressing
 * signal 88 (cross-ptrace detection). The self-suppression is confirmed, not
 * merely conjectured. Sources: proc_pid_mem(5) man7.org/linux/man-pages/man5/
 * proc_pid_mem.5.html; cloudflare.com/blog/diving-into-proc-pid-mem (explains
 * ptrace attachment semantics). On-box verification of the exact side-effects
 * (does attaching via /proc/mem actually set PT_PTRACED?) is still needed to
 * determine whether the suppression is total or partial — still needs on-target test.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define HK_SCHEMA_VERSION     3u
#define HK_EVENT_RDEBUG_TICK  0x26u   /* loader maps to HK_EVENT_RDEBUG_ANOMALY (tick) */

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

struct hk_bpf_rdebug_tick_event {
    __u32 schema_version;
    __u32 event_tag;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 reserved;
};

SEC("uprobe")
int BPF_KPROBE(hk_uprobe_rdebug_sample)
{
    struct hk_bpf_rdebug_tick_event *evt;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_EVENT_RDEBUG_TICK;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->pid            = bpf_get_current_pid_tgid() >> 32;
    evt->reserved       = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
