/*
 * kernel/linux/bpf/src/dl_audit.bpf.c
 * Role: uprobe on the glibc rtld-audit dispatcher _dl_audit_symbind to detect
 *       that LD_AUDIT la_symbind callbacks are actively firing for a watched PID.
 *       Emits a compact record so the userspace correlator (signal 89, env
 *       capture shared with bprm_env.bpf.c) can flag la_symbind firing with no
 *       recorded/allowlisted LD_AUDIT at exec.
 * Target platform: Linux eBPF (uprobe, kernel >= 4.17; shared ringbuf >= 5.8).
 * Interface: shares hk_ringbuf (extern); env presence from bprm_env.bpf.c;
 *            Loader.cpp translates HK_EVENT_DL_AUDIT.
 *
 * Guardrail compliance: #1, #3, #4, #6.
 *
 * HK-UNCERTAIN(glibc-internal): `_dl_audit_symbind` is glibc-version-specific and
 * may be inlined or renamed (it was reorganized in the glibc 2.35 audit rework).
 * It is internal, not stable ABI, and absent on musl. Resolve per-target at
 * attach and skip the signal gracefully when absent — do NOT guess the symbol or
 * its argument layout. This program reports PRESENCE only (la_symbind fired for
 * this pid); it does not dereference any audit struct in-kernel.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define HK_SCHEMA_VERSION   3u
#define HK_EVENT_DL_AUDIT   0x25u   /* loader maps to HK_EVENT_PRELOAD_ANOMALY (LD_AUDIT kind) */

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

struct hk_bpf_dl_audit_event {
    __u32 schema_version;
    __u32 event_tag;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 reserved;
};

/* ---- uprobe: glibc _dl_audit_symbind ------------------------------------- */
SEC("uprobe")
int BPF_KPROBE(hk_uprobe_dl_audit_symbind)
{
    struct hk_bpf_dl_audit_event *evt;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_EVENT_DL_AUDIT;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->pid            = bpf_get_current_pid_tgid() >> 32;
    evt->reserved       = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
