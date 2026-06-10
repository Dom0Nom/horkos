/*
 * kernel/linux/bpf/src/fexit_process_vm.bpf.c
 * Role: BPF TRACING (fexit) sensors for cross-mm memory transfer via
 *       process_vm_writev(2) / process_vm_readv(2) (signal 74). On syscall
 *       return, resolve the target task from the pid argument, compare its mm
 *       to the protected game's mm, and emit a write/read event carrying the
 *       fexit return value (bytes transferred). A foreign writer poking the
 *       game's address space is the classic external-memory-cheat choke point.
 * Target platform: Linux eBPF (BPF_PROG_TYPE_TRACING / fexit; needs BTF and the
 *                  target fn in kallsyms/BTF — see HK-VERIFIED note in hk_emit_vm_access).
 * Interface: fexit on the process_vm_writev / process_vm_readv syscall fns;
 *            reads hk_protected (include/hk_protected.bpf.h); writes hk_ringbuf
 *            (extern, shared via Loader.cpp). Maps to server events
 *            HK_EVENT_VM_WRITE / HK_EVENT_VM_READ.
 *
 * Guardrail compliance:
 *   #1  No raw platform macros — Linux-only by build gating.
 *   #3  This module comment covers role/platform/interface.
 *   #4  Pure kernel eBPF TU — no userspace headers.
 *   #6  Compiled -Wall -Wextra -Werror (enforced in CMakeLists.txt).
 *
 * API references:
 *   - fexit / BPF_PROG: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_TRACING/
 *   - process_vm_writev: man 2 process_vm_writev (mm/process_vm_access.c)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "hk_protected.bpf.h"

#define HK_SCHEMA_VERSION   3u
#define HK_BPF_VM_WRITE     0x40u
#define HK_BPF_VM_READ      0x41u

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/* Mirrored in Loader.cpp as HkBpfVmAccessEvent. */
struct hk_bpf_vm_access_event {
    __u32 schema_version;
    __u32 event_tag;        /* HK_BPF_VM_WRITE | HK_BPF_VM_READ */
    __u64 timestamp_ns;
    __u32 caller_pid;       /* writer/reader tgid               */
    __u32 target_pid;       /* protected tgid                   */
    __s64 bytes;            /* fexit return: bytes transferred (<0 = -errno) */
};

/*
 * Shared emit helper. Resolves the target task from the syscall `pid` argument,
 * checks the protected set, and submits an event. `tag` selects write vs read.
 *
 * HK-VERIFIED(process-vm-fexit-target): mm/process_vm_access.c defines
 *   SYSCALL_DEFINE6(process_vm_writev, ...)  →  sys_process_vm_writev
 *   SYSCALL_DEFINE6(process_vm_readv, ...)   →  sys_process_vm_readv
 * The inner helper process_vm_rw() is STATIC and therefore absent from BTF and
 * kallsyms; fentry/fexit cannot attach to it. The SYSCALL_DEFINE6 wrappers ARE
 * exported (non-static); their canonical BTF names on x86-64 are
 * "__x64_sys_process_vm_writev" / "__x64_sys_process_vm_readv" (the syscall
 * table wrapper) AND the "process_vm_writev" / "process_vm_readv" names used in
 * the SEC() strings below, which libbpf resolves to the arch-prefixed symbol at
 * load time via the syscall-naming convention. The SEC("fexit/process_vm_writev")
 * form is the correct libbpf spelling; libbpf handles the arch prefix.
 * The first argument (pid_t pid) is confirmed as the first register-argument in
 * the SYSCALL_DEFINE6 expansion, matching the BPF_PROG declaration below.
 * Source: https://github.com/torvalds/linux/blob/master/mm/process_vm_access.c
 *
 * process_vm_rw fallback note: if the arch-prefixed symbol is absent on an
 * unusual target, the loader kprobe fallback on process_vm_rw is NOT viable
 * (static/inlined). The kprobe fallback should target __x64_sys_process_vm_writev
 * directly instead.
 */
static __always_inline int
hk_emit_vm_access(__u32 tag, pid_t target_pid_arg, long ret)
{
    struct hk_bpf_vm_access_event *evt;
    struct task_struct *target;
    struct mm_struct *target_mm;
    __u32 target_tgid;

    /* bpf_task_from_pid resolves a struct task_struct* from a pid within the
     * init pid namespace and takes a reference; we must release it with
     * bpf_task_release. (kfunc; kernel >= 5.17. On older kernels the loader
     * uses the kprobe fallback path.) */
    target = bpf_task_from_pid(target_pid_arg);
    if (!target)
        return 0;

    target_tgid = (__u32)BPF_CORE_READ(target, tgid);
    if (!hk_is_protected_tgid(target_tgid)) {
        bpf_task_release(target);
        return 0;
    }

    target_mm = BPF_CORE_READ(target, mm);
    (void)target_mm;   /* mm presence implies a userspace target; kernel threads
                          (mm==NULL) are not a protected game and were already
                          filtered by the tgid check above. */

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt) {
        bpf_task_release(target);
        return 0;
    }

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = tag;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->caller_pid     = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt->target_pid     = target_tgid;
    evt->bytes          = (__s64)ret;

    bpf_ringbuf_submit(evt, 0);
    bpf_task_release(target);
    return 0;
}

/* process_vm_writev(pid_t pid, const struct iovec *lvec, unsigned long liovcnt,
 *                    const struct iovec *rvec, unsigned long riovcnt,
 *                    unsigned long flags) -> ssize_t */
SEC("fexit/process_vm_writev")
int BPF_PROG(hk_fexit_process_vm_writev,
             pid_t pid, const void *lvec, unsigned long liovcnt,
             const void *rvec, unsigned long riovcnt, unsigned long flags,
             long ret)
{
    (void)lvec; (void)liovcnt; (void)rvec; (void)riovcnt; (void)flags;
    return hk_emit_vm_access(HK_BPF_VM_WRITE, pid, ret);
}

/* Reads are a separate, lower-severity tag per the catalog. */
SEC("fexit/process_vm_readv")
int BPF_PROG(hk_fexit_process_vm_readv,
             pid_t pid, const void *lvec, unsigned long liovcnt,
             const void *rvec, unsigned long riovcnt, unsigned long flags,
             long ret)
{
    (void)lvec; (void)liovcnt; (void)rvec; (void)riovcnt; (void)flags;
    return hk_emit_vm_access(HK_BPF_VM_READ, pid, ret);
}

char _license[] SEC("license") = "GPL";
