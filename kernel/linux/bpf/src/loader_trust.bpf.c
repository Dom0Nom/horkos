/*
 * Role: Signal 206 — dynamic-linker-hijack detection at exec. On
 *       sys_enter_execve it scans the new process's environment (the syscall's
 *       third arg, envp) for LD_PRELOAD / LD_AUDIT / LD_LIBRARY_PATH and tags a
 *       tainted-loader-env event. The userspace reconcile (/proc maps vs
 *       DT_NEEDED, PT_INTERP, /etc/ld.so.preload) lives in Loader.cpp; the
 *       server allowlists overlay/HUD .so by path+hash and flags only unlisted
 *       preloads.
 * Target platforms: Linux eBPF (TRACEPOINT). Compiles -Wall -Wextra -Werror
 *       (guardrail #6). Shares hk_ringbuf.
 *
 *       HK-UNCERTAIN (plan UNCERTAINTY FLAG): reading envp at sys_enter_execve.
 *       The sys_enter_execve tracepoint args[] layout is documented: args[0]=path,
 *       args[1]=argv, args[2]=envp (raw syscall arguments per
 *       include/trace/events/syscalls.h and man2/execve.2). The envp pointer in
 *       args[2] IS the userspace envp pointer and IS accessible as a user pointer
 *       via bpf_probe_read_user. The fixed-unrolled loop (N<=32) with bounded
 *       bpf_probe_read_user_str is the documented verifier-safe pattern.
 *       (docs: docs.ebpf.io/linux/tracepoints/syscalls/sys_enter_execve confirms
 *       args[2] == envp for the execve tracepoint. Source: sys_enter generic
 *       tracepoint defined in include/trace/events/syscalls.h.)
 *       STILL UNCERTAIN: whether the bounded loop + double bpf_probe_read_user
 *       (pointer then string) passes the verifier on the TARGET kernel (Deck 6.x
 *       BPF verifier) without additional helper hints — still needs on-target test.
 * Interface: shares hk_ringbuf; HK_EVENT_LOADER_TAINT mapped by Loader.cpp.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "hk_protected.bpf.h"

#define HK_SCHEMA_VERSION    5u
/* 0x23 is claimed by bprm_env.bpf.c (HK_EVENT_BPRM_ENV); 0x29 is free. */
#define HK_EVENT_LOADER_TAINT 0x29u

#define HK_TAINT_LD_PRELOAD     0x1u
#define HK_TAINT_LD_AUDIT       0x2u
#define HK_TAINT_LD_LIBRARY_PATH 0x4u

#define HK_ENV_SCAN_MAX   32   /* bounded env entries (verifier-friendly). */
#define HK_ENV_STR_MAX    64   /* prefix bytes read per entry. */

struct hk_bpf_launch_event {
    __u32 schema_version;
    __u32 event_tag;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tracer_pid;   /* unused for 206; 0. */
    __u32 taint_flags;  /* HK_TAINT_*. */
    char  comm[16];
};

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/* Classify one env string prefix into a taint bit. Compares the LD_* prefixes
 * byte-by-byte (bounded). */
static __always_inline __u32 hk_env_taint(const char *s)
{
    /* "LD_PRELOAD=" / "LD_AUDIT=" / "LD_LIBRARY_PATH=" — match the discriminating
     * prefix after the shared "LD_". */
    if (s[0] != 'L' || s[1] != 'D' || s[2] != '_') {
        return 0;
    }
    if (s[3] == 'P' && s[4] == 'R' && s[5] == 'E') {
        return HK_TAINT_LD_PRELOAD;
    }
    if (s[3] == 'A' && s[4] == 'U' && s[5] == 'D') {
        return HK_TAINT_LD_AUDIT;
    }
    if (s[3] == 'L' && s[4] == 'I' && s[5] == 'B') {
        return HK_TAINT_LD_LIBRARY_PATH;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int hk_on_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    const char *const *envp;
    __u32 taint = 0;
    int i;

    if (!hk_is_protected_tgid(tgid)) {
        return 0;
    }
    /* execve(path, argv, envp): envp is the third syscall arg. */
    envp = (const char *const *)(void *)ctx->args[2];
    if (!envp) {
        return 0;
    }

#pragma unroll
    for (i = 0; i < HK_ENV_SCAN_MAX; ++i) {
        const char *entry = NULL;
        char buf[HK_ENV_STR_MAX];
        if (bpf_probe_read_user(&entry, sizeof(entry), &envp[i]) != 0 || !entry) {
            break; /* end of envp or unreadable. */
        }
        if (bpf_probe_read_user_str(buf, sizeof(buf), entry) < 7) {
            continue; /* too short to be an LD_* assignment. */
        }
        taint |= hk_env_taint(buf);
    }

    if (taint != 0) {
        struct hk_bpf_launch_event *e = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*e), 0);
        if (e) {
            e->schema_version = HK_SCHEMA_VERSION;
            e->event_tag = HK_EVENT_LOADER_TAINT;
            e->timestamp_ns = bpf_ktime_get_ns();
            e->pid = tgid;
            e->tracer_pid = 0;
            e->taint_flags = taint;
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
