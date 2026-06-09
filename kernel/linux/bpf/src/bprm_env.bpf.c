/*
 * kernel/linux/bpf/src/bprm_env.bpf.c
 * Role: BPF LSM program on bprm_creds_for_exec. At exec it scans the new
 *       program's environment for the dynamic-loader injection keys
 *       LD_PRELOAD / LD_AUDIT / LD_LIBRARY_PATH and stamps a presence bitmask
 *       into a compact event. Feeds the userspace correlators PreloadWatch.cpp
 *       (signals 85) and the dl_audit path (signal 89). AUDIT-ONLY: always
 *       returns the inbound `ret` (never a hard 0), so it can never override
 *       another LSM module's deny (guardrail: BPF LSM audit posture).
 * Target platform: Linux eBPF (BPF LSM, kernel >= 5.7; requires CONFIG_BPF_LSM=y
 *                  and "bpf" in the lsm= boot list, else lsm/ programs do NOT
 *                  attach — document in README, do not assume).
 * Interface: shares hk_ringbuf with lsm_file_open.bpf.c (extern); Loader.cpp
 *            translates the HK_EVENT_BPRM_ENV record to hk_event_record.
 *
 * Guardrail compliance: #1, #3, #4, #6 as in the sibling LSM programs.
 *
 * HK-UNCERTAIN(lsm-hook+envp): the impl-plan lists BOTH bprm_creds_for_exec and
 * bprm_committing_creds as candidate hooks. Which hook exists, and whether
 * linux_binprm->envp points at a FULLY-POPULATED, safely-readable user env at
 * the chosen hook, is kernel-version-dependent and NOT verified here. envp at
 * exec is a user-pointer array in the NEW mm that may not yet be fully copied.
 * Reading it in BPF needs on-box confirmation (Deck 6.x). Until verified, the
 * envp WALK below is gated behind HK_BPRM_ENV_WALK_VERIFIED (undefined by
 * default): the program still emits the exec event (cadence + argc/envc counts
 * from binprm) so userspace PreloadWatch.cpp can correlate against its own
 * /proc/<pid>/environ read (which IS safe post-exec from userspace), but it does
 * NOT dereference the user env array in-kernel until the hook+validity contract
 * is confirmed. Do NOT enable the walk without on-box verification — a bad read
 * here faults in kernel context.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define HK_SCHEMA_VERSION   3u
#define HK_EVENT_BPRM_ENV   0x23u   /* loader maps to HK_EVENT_PRELOAD_ANOMALY */

/* Presence bits for the three injection keys (mirrored in Loader.cpp). */
#define HK_ENV_LD_PRELOAD      0x1u
#define HK_ENV_LD_AUDIT        0x2u
#define HK_ENV_LD_LIBRARY_PATH 0x4u

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

struct hk_bpf_bprm_env_event {
    __u32 schema_version;
    __u32 event_tag;
    __u64 timestamp_ns;
    __u32 pid;              /* execing tgid */
    __u32 env_flags;        /* HK_ENV_* bitmask of keys seen at exec */
    __u32 argc;             /* binprm->argc (bounded hint) */
    __u32 envc;             /* binprm->envc (bounded hint) */
};

/* ---- LSM hook: lsm/bprm_creds_for_exec ----------------------------------- */
/*
 * Always returns the inbound `ret` (audit-only). The hook signature is
 * (struct linux_binprm *bprm, int ret); BPF_PROG unpacks it. The trailing `ret`
 * is the prior LSM/BPF program's decision — propagate it unchanged.
 */
SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(hk_lsm_bprm_creds, struct linux_binprm *bprm, int ret)
{
    struct hk_bpf_bprm_env_event *evt;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return ret;   /* drop on overflow — never override the prior decision */

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_EVENT_BPRM_ENV;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->pid            = bpf_get_current_pid_tgid() >> 32;
    evt->env_flags      = 0;
    /* argc/envc are kernel-side ints in linux_binprm, safe via CO-RE. */
    evt->argc           = (__u32)BPF_CORE_READ(bprm, argc);
    evt->envc           = (__u32)BPF_CORE_READ(bprm, envc);

#ifdef HK_BPRM_ENV_WALK_VERIFIED
    /* HK-UNCERTAIN(envp): only compiled when the on-box envp-validity contract is
     * confirmed. Bounded walk: at most N entries, M bytes each, scanning for the
     * three key prefixes. binprm->p is the current top-of-stack user pointer into
     * the arg/env block; iterating it correctly is the part needing verification.
     * Left as a clearly-bounded skeleton, NOT enabled by default. */
    {
        const unsigned int N = 64;   /* max env entries scanned */
        const unsigned int M = 16;   /* bytes compared per entry (prefix only) */
        char buf[M];
        /* Placeholder: the real loop resolves each envp[i] user pointer and
         * bpf_probe_read_user_str's M bytes, then prefix-matches "LD_PRELOAD=",
         * "LD_AUDIT=", "LD_LIBRARY_PATH=". Implement only after envp validity is
         * confirmed on the target kernel. */
        (void)N; (void)M; (void)buf;
    }
#endif

    bpf_ringbuf_submit(evt, 0);
    return ret;   /* audit-only: preserve the prior LSM decision */
}

char _license[] SEC("license") = "GPL";
