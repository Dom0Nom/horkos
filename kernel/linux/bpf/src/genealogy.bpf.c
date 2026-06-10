/*
 * kernel/linux/bpf/src/genealogy.bpf.c
 * Role: Signal 205 — launch-under-tracer. Joins the ptrace syscall stream with
 *       exec (sched_process_exec) keyed by (tgid,pid) and a BPF LSM
 *       ptrace_access_check hook, tagging an exec that occurs while the task is
 *       being traced. The tracer pid/comm is surfaced so the server can
 *       distinguish a debugger from the Steam/Proton supervisor or an allowlisted
 *       crash reporter. Audit-only — the LSM hook observes and returns the
 *       incoming ret unchanged, never denies.
 * Target platforms: Linux eBPF (TRACEPOINT + BPF_LSM). Compiles -Wall -Wextra
 *       -Werror at the kernel warning level (guardrail #6). Shares hk_ringbuf.
 *
 *       HK-UNCERTAIN (plan UNCERTAINTY FLAG): BPF LSM (lsm/ptrace_access_check)
 *       requires CONFIG_BPF_LSM=y AND "bpf" in the boot lsm= list — not universal,
 *       notably uncertain on stock Steam Deck SteamOS. The tracepoint-join path
 *       stands alone if the LSM program fails to attach (the loader attach-gates
 *       it). The task_struct->ptrace / ->real_parent reads are CO-RE-relocatable
 *       and confirmed against the target BTF.
 * Interface: shares hk_ringbuf (extern, from lsm_file_open.bpf.c); the
 *       HK_EVENT_LAUNCH_TRACED tag is mapped to the server record by Loader.cpp.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "hk_protected.bpf.h"

#define HK_SCHEMA_VERSION    5u   /* mirrors HK_EVENT_SCHEMA_VERSION (v5). */
#define HK_EVENT_LAUNCH_TRACED 0x22u

struct hk_bpf_launch_event {
    __u32 schema_version;
    __u32 event_tag;
    __u64 timestamp_ns;
    __u32 pid;          /* tracee / exec'ing task. */
    __u32 tracer_pid;   /* tracer task pid (0 if none). */
    __u32 taint_flags;  /* unused for 205; 0. */
    char  comm[16];     /* tracer comm for server allowlisting. */
};

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/* Per-tgid "is being traced" marker set by the LSM hook, read at exec. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);   /* tracee tgid. */
    __type(value, __u32); /* tracer pid. */
} hk_traced SEC(".maps");

/* LSM ptrace_access_check: observe-only. Records tracer->tracee when the tracee
 * is in the protected set. Returns the incoming ret unchanged (never denies). */
SEC("lsm/ptrace_access_check")
int BPF_PROG(hk_ptrace_access_check, struct task_struct *child, unsigned int mode, int ret)
{
    __u32 child_tgid = (__u32)BPF_CORE_READ(child, tgid);
    __u32 tracer_pid;

    (void)mode;
    if (!hk_is_protected_tgid(child_tgid)) {
        return ret;
    }
    tracer_pid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&hk_traced, &child_tgid, &tracer_pid, BPF_ANY);
    return ret; /* audit-only. */
}

/* sched_process_exec: if the exec'ing task is marked traced, emit the join. */
SEC("tracepoint/sched/sched_process_exec")
int hk_on_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u32 *tracer;
    struct hk_bpf_launch_event *e;

    (void)ctx;
    if (!hk_is_protected_tgid(tgid)) {
        return 0;
    }
    tracer = bpf_map_lookup_elem(&hk_traced, &tgid);
    if (!tracer) {
        return 0; /* not traced at exec time — no signal. */
    }

    e = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    e->schema_version = HK_SCHEMA_VERSION;
    e->event_tag = HK_EVENT_LAUNCH_TRACED;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = tgid;
    e->tracer_pid = *tracer;
    e->taint_flags = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
