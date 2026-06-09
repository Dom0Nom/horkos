/*
 * kernel/linux/bpf/src/rdebug_sample.bpf.c
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
 * HK-UNCERTAIN(proc-mem-self-suppress): reading another process's /proc/<pid>/mem
 * at a load-biased address has the same ptrace-access-mode gating as a debugger;
 * whether the userspace loader can do this WITHOUT itself becoming a ptrace
 * tracer (which would then self-suppress signal 88) is unconfirmed. Flagged for
 * on-box verification before enabling signal 88 (default-OFF in CMake).
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
