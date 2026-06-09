/*
 * kernel/linux/bpf/src/lsm_ptrace.bpf.c
 * Role: BPF LSM sensors for inbound ptrace authorization (signal 73,
 *       lsm/ptrace_access_check) and PTRACE_TRACEME self-arm (signal 81,
 *       lsm/ptrace_traceme) against a protected game process. Both are
 *       AUDIT-ONLY: they return the incoming LSM stack `ret` unchanged and
 *       never deny. They emit a compact record to the shared hk_ringbuf only
 *       when the subject (child / current) is in the hk_protected set, so an
 *       external debugger or a self-debug pre-arm becomes server-side evidence.
 * Target platform: Linux eBPF (BPF LSM, kernel >= 5.7; CONFIG_BPF_LSM=y and
 *                  "bpf" present in lsm= boot param / CONFIG_LSM, else these
 *                  programs do NOT attach — documented in the build README).
 * Interface: implements lsm/ptrace_access_check + lsm/ptrace_traceme; reads the
 *            hk_protected map (include/hk_protected.bpf.h); writes hk_ringbuf
 *            (shared via Loader.cpp bpf_map__reuse_fd, declared extern here).
 *            Maps to server events HK_EVENT_PTRACE_ACCESS / HK_EVENT_PTRACE_TRACEME.
 *
 * Guardrail compliance:
 *   #1  No raw platform macros — Linux-only by build gating.
 *   #3  This module comment covers role/platform/interface.
 *   #4  Pure kernel eBPF TU — no userspace headers.
 *   #6  Compiled -Wall -Wextra -Werror (enforced in CMakeLists.txt).
 *
 * API references:
 *   - BPF LSM:   https://docs.kernel.org/bpf/prog_lsm.html
 *   - ptrace LSM hooks: security_ptrace_access_check / security_ptrace_traceme
 *                 in kernel/security/security.c, include/linux/lsm_hook_defs.h
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "hk_protected.bpf.h"

/* ---- Wire-format constants (mirror the other .bpf.c files) --------------- */
#define HK_SCHEMA_VERSION       3u   /* mirrors HK_EVENT_SCHEMA_VERSION; bumped
                                        to 3 by the schema phase for the memory
                                        signals. */
#define HK_BPF_PTRACE_ACCESS    0x30u
#define HK_BPF_PTRACE_TRACEME   0x31u

/* PTRACE_MODE_* bits we care about (from include/linux/ptrace.h). These are a
 * stable UAPI-adjacent ABI; we duplicate the two we test rather than relying on
 * them being present in the generated vmlinux.h (they are #defines, not types,
 * so CO-RE/BTF does not carry them). */
#ifndef PTRACE_MODE_READ
#define PTRACE_MODE_READ    0x01u
#endif
#ifndef PTRACE_MODE_ATTACH
#define PTRACE_MODE_ATTACH  0x02u
#endif

/* ---- Shared ring buffer (defined in lsm_file_open.bpf.c) ----------------- */
extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/* ---- Ring-buffer event layout -------------------------------------------- */
/*
 * Mirrored in Loader.cpp as HkBpfPtraceEvent. Header triple matches every other
 * BPF record { schema_version, event_tag, timestamp_ns } then the ptrace fields.
 * Loader maps this onto the server hk_event_ptrace payload (caller/target pid,
 * mode, caller_uid, lsm_ret).
 */
struct hk_bpf_ptrace_event {
    __u32 schema_version;
    __u32 event_tag;        /* HK_BPF_PTRACE_ACCESS | HK_BPF_PTRACE_TRACEME */
    __u64 timestamp_ns;
    __u32 caller_pid;       /* requester tgid (73) / would-be tracer (81)   */
    __u32 target_pid;       /* protected tgid                               */
    __u32 mode;             /* PTRACE_MODE_* (73); 0 for traceme (81)       */
    __u32 caller_uid;       /* caller cred uid                              */
    __s32 lsm_ret;          /* incoming LSM-stack decision (0 = granted)    */
    __u32 reserved;         /* zero pad to 8-byte multiple                  */
};

/* ---- Signal 73: lsm/ptrace_access_check ---------------------------------- */
/*
 * Fires when a task attempts to ptrace-inspect `child` (the would-be tracee).
 * `mode` carries PTRACE_MODE_ATTACH (real attach) vs PTRACE_MODE_READ (peek).
 * We emit only when:
 *   - child->tgid is in hk_protected, AND
 *   - mode includes PTRACE_MODE_ATTACH (attach intent, not a benign read), AND
 *   - the caller tgid differs from the protected tgid (not the game inspecting
 *     itself / its own threads).
 *
 * AUDIT-ONLY: return `ret` (the prior LSM decision) unchanged. Returning a hard
 * 0 would override a real deny from another stacked module (the lsm_file_open
 * sibling documents this invariant).
 *
 * HK-UNCERTAIN(ptrace-access-check-arity): the BPF-LSM signature for
 * security_ptrace_access_check is commonly
 *   BPF_PROG(name, struct task_struct *child, unsigned int mode, int ret)
 * but some kernel trees carry a different arg list on this hook. The exact
 * BPF_PROG arg arity MUST be confirmed against the CI/target kernel's BTF
 * (`bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -A3
 * bpf_lsm_ptrace_access_check`) before this attaches; a wrong arity is a
 * verifier reject or silently wrong field reads. Coded here against the common
 * 3-arg form; do not assume it is correct on every kernel.
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(hk_lsm_ptrace_access_check,
             struct task_struct *child, unsigned int mode, int ret)
{
    __u32 caller_tgid;
    __u32 child_tgid;
    struct hk_bpf_ptrace_event *evt;
    struct task_struct *caller;

    if (!child)
        return ret;

    child_tgid = (__u32)BPF_CORE_READ(child, tgid);
    if (!hk_is_protected_tgid(child_tgid))
        return ret;

    /* Attach intent only — a bare PTRACE_MODE_READ peek is lower signal and
     * would balloon the FP budget on benign /proc readers. */
    if (!(mode & PTRACE_MODE_ATTACH))
        return ret;

    caller_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    /* The game inspecting its own threads is benign (same tgid). */
    if (caller_tgid == child_tgid)
        return ret;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return ret;   /* drop on overflow — never override the prior decision */

    caller = (struct task_struct *)bpf_get_current_task_btf();

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_BPF_PTRACE_ACCESS;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->caller_pid     = caller_tgid;
    evt->target_pid     = child_tgid;
    evt->mode           = (__u32)mode;
    evt->caller_uid     = (__u32)BPF_CORE_READ(caller, cred, uid.val);
    evt->lsm_ret        = (__s32)ret;
    evt->reserved       = 0;

    bpf_ringbuf_submit(evt, 0);
    return ret;   /* audit-only */
}

/* ---- Signal 81: lsm/ptrace_traceme --------------------------------------- */
/*
 * Fires when `current` requests PTRACE_TRACEME, asking `parent` to become its
 * tracer. A protected game process pre-arming TRACEME is a self-debug / anti-
 * debug-evasion tell. We emit when current->tgid is protected; caller_pid is the
 * PARENT tgid (the would-be tracer), mode is 0 (no PTRACE_MODE bits on this hook).
 *
 * HK-UNCERTAIN(ptrace-traceme-arity): the common BPF-LSM form is
 *   BPF_PROG(name, struct task_struct *parent, int ret)
 * Confirm against the target BTF as for signal 73 above before relying on it.
 *
 * AUDIT-ONLY: return `ret` unchanged.
 */
SEC("lsm/ptrace_traceme")
int BPF_PROG(hk_lsm_ptrace_traceme, struct task_struct *parent, int ret)
{
    __u32 self_tgid;
    struct hk_bpf_ptrace_event *evt;
    struct task_struct *self;

    self_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (!hk_is_protected_tgid(self_tgid))
        return ret;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return ret;

    self = (struct task_struct *)bpf_get_current_task_btf();

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_BPF_PTRACE_TRACEME;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    /* caller = the would-be tracer = the parent that TRACEME asks to attach. */
    evt->caller_pid     = (parent != (void *)0)
                          ? (__u32)BPF_CORE_READ(parent, tgid)
                          : 0u;
    evt->target_pid     = self_tgid;
    evt->mode           = 0u;   /* no PTRACE_MODE bits on the traceme hook */
    evt->caller_uid     = (__u32)BPF_CORE_READ(self, cred, uid.val);
    evt->lsm_ret        = (__s32)ret;
    evt->reserved       = 0;

    bpf_ringbuf_submit(evt, 0);
    return ret;   /* audit-only */
}

char _license[] SEC("license") = "GPL";
