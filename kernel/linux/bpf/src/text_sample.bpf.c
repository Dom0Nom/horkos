/*
 * Role: uprobe-triggered CADENCE program for signal 90. On fire it emits a
 *       lightweight "this watched PID needs an executable-page COW/back-store
 *       scan" tick. The actual scan — reading /proc/<pid>/smaps_rollup, per-VMA
 *       /proc/<pid>/smaps (Private_Dirty) and /proc/<pid>/pagemap (file-backed
 *       bit) for r-xp file-backed mappings — is entirely userspace
 *       (TextPageBacking.cpp). No /proc reads in BPF (guardrail #4).
 * Target platform: Linux eBPF (uprobe, kernel >= 4.17; ringbuf >= 5.8).
 * Interface: shares hk_ringbuf (extern); Loader.cpp translates HK_EVENT_TEXT_TICK.
 *
 * Guardrail compliance: #1, #3, #4, #6.
 *
 * HK-VERIFIED(pagemap-caps): permission to access /proc/pid/pagemap is governed
 * by a ptrace access mode PTRACE_MODE_READ_FSCREDS check (proc_pid_pagemap(5)
 * man page: man7.org/linux/man-pages/man5/proc_pid_pagemap.5.html). CAP_BPF and
 * CAP_PERFMON do NOT satisfy this ptrace check; cross-process pagemap requires
 * CAP_SYS_PTRACE (or equivalent ptrace access that passes __ptrace_may_access).
 * The loader's typical capability set (CAP_BPF/CAP_PERFMON) is therefore
 * INSUFFICIENT for cross-process pagemap reads. Signal 90 requires either running
 * the loader with CAP_SYS_PTRACE or using an in-process sampling strategy.
 * Flagged for on-box capability-set decision before enabling signal 90 (default-OFF
 * in CMake). HK-UNCERTAIN(uprobe-perf): same hot-fn trap cost caveat as
 * got_sample.bpf.c.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define HK_SCHEMA_VERSION   3u
#define HK_EVENT_TEXT_TICK  0x27u   /* loader maps to HK_EVENT_TEXT_PATCH (tick) */

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

struct hk_bpf_text_tick_event {
    __u32 schema_version;
    __u32 event_tag;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 reserved;
};

SEC("uprobe")
int BPF_KPROBE(hk_uprobe_text_sample)
{
    struct hk_bpf_text_tick_event *evt;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_EVENT_TEXT_TICK;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->pid            = bpf_get_current_pid_tgid() >> 32;
    evt->reserved       = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
