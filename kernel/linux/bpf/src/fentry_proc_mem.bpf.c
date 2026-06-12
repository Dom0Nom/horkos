/*
 * Role: BPF TRACING (fentry) sensor for /proc/<pid>/mem opens (signal 75).
 *       fs/proc/base.c:mem_open() runs on every open of a /proc/<pid>/mem node;
 *       we recover the TARGET task from the proc inode, compare its tgid to the
 *       protected set, and flag a CROSS-tgid opener (a same-tgid self-open is
 *       benign). Path-independent: survives bind-mounts / chroot because it
 *       keys on the inode's backing pid, not the path string.
 * Target platform: Linux eBPF (BPF_PROG_TYPE_TRACING / fentry; needs mem_open
 *                  in BTF/kallsyms — see HK-UNCERTAIN below).
 * Interface: fentry on mem_open(struct inode*, struct file*); reads hk_protected
 *            (include/hk_protected.bpf.h); writes hk_ringbuf (extern, shared via
 *            Loader.cpp). Maps to server event HK_EVENT_PROC_MEM_OPEN.
 *
 * Guardrail compliance:
 *   #1  No raw platform macros — Linux-only by build gating.
 *   #3  This module comment covers role/platform/interface.
 *   #4  Pure kernel eBPF TU — no userspace headers.
 *   #6  Compiled -Wall -Wextra -Werror (enforced in CMakeLists.txt).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "hk_protected.bpf.h"

#define HK_SCHEMA_VERSION       3u
#define HK_BPF_PROC_MEM_OPEN    0x50u

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/* Mirrored in Loader.cpp as HkBpfProcMemOpenEvent. */
struct hk_bpf_proc_mem_open_event {
    __u32 schema_version;
    __u32 event_tag;        /* HK_BPF_PROC_MEM_OPEN */
    __u64 timestamp_ns;
    __u32 caller_pid;       /* opener tgid                           */
    __u32 target_pid;       /* tgid backing the opened /proc mem node */
};

/*
 * fentry/mem_open: mem_open(struct inode *inode, struct file *file).
 * The target task is recovered from the proc_inode that backs `inode`:
 *   struct proc_inode { ... struct pid *pid; ... struct inode vfs_inode; };
 * container_of(inode, struct proc_inode, vfs_inode)->pid -> numeric pid from
 * pid->numbers[0].nr -> bpf_task_from_pid (same kfunc used in
 * fexit_process_vm.bpf.c:79). bpf_task_release must pair every successful
 * bpf_task_from_pid call.
 *
 * HK-UNCERTAIN(mem-open-attachability): fs/proc/base.c:mem_open is declared
 * `static` in the kernel source; whether it appears in BTF/kallsyms depends on
 * whether the target kernel was compiled with CONFIG_KALLSYMS_ALL or equivalent
 * BTF export of static functions. If absent, fentry fails to attach.
 * The signature `static int mem_open(struct inode *inode, struct file *file)` is
 * stable across v6.x (no renames found); it is the BPF_PROG form used below.
 * The loader MUST design in a fallback to lsm/file_open filtered by the proc-mem
 * inode (i_op == proc_mem_inode_operations / dname == "mem" under /proc) — not
 * bolt it on later. CONFIRM mem_open is in BTF on the target kernels before
 * relying on this attach point.
 * (docs: pahole >= 1.16 encodes static functions into BTF by default when
 * CONFIG_DEBUG_INFO_BTF=y, but the final set depends on inlining decisions at
 * the specific kernel build — still needs on-target BTF probe via bpftool)
 *
 * HK-UNCERTAIN(proc-inode-core-read): recovering struct pid from the proc_inode
 * via container_of + BPF_CORE_READ relies on the proc_inode layout being in the
 * generated vmlinux.h. If proc_inode is opaque in the target BTF, this read
 * must move to a get_proc_task kfunc. Verify against BTF.
 * (docs: proc_inode is an in-kernel struct defined in fs/proc/inode.c; it is
 * included in vmlinux BTF on kernels with CONFIG_DEBUG_INFO_BTF=y, but its
 * presence is build-config-dependent — still needs on-target BTF dump to confirm
 * proc_inode.pid field is visible)
 */
SEC("fentry/mem_open")
int BPF_PROG(hk_fentry_mem_open, struct inode *inode, struct file *file)
{
    struct hk_bpf_proc_mem_open_event *evt;
    struct proc_inode *pi;
    struct pid *pid_struct;
    struct task_struct *target;
    __u32 caller_tgid;
    __u32 target_tgid;
    pid_t numeric_pid;

    (void)file;

    if (!inode)
        return 0;

    /* container_of(inode, struct proc_inode, vfs_inode) via CO-RE. The
     * __builtin_offsetof of vfs_inode is relocated at load time; this avoids the
     * layout assumption that plagued the earlier pid_links subtraction. */
    pi = (struct proc_inode *)((char *)inode
            - __builtin_offsetof(struct proc_inode, vfs_inode));

    pid_struct = BPF_CORE_READ(pi, pid);
    if (!pid_struct)
        return 0;

    /* Read the numeric pid from the root-namespace slot (numbers[0].nr). This
     * gives us the value bpf_task_from_pid expects — the same kfunc pattern used in
     * fexit_process_vm.bpf.c. bpf_task_from_pid requires kernel >= 5.17.
     * HK-UNCERTAIN(pid-numbers-co-re): struct pid's numbers[] is a flexible
     * array; CO-RE must be able to relocate numbers[0].nr from BTF. Confirm the
     * target BTF exposes struct upid.nr at this path before relying on this read.
     * (docs: BPF CO-RE supports fixed-index flexible-array access when the struct
     * and its member types appear in vmlinux BTF; struct pid/upid are in-kernel
     * types so they should appear, but on-target bpftool btf dump confirmation
     * required — still needs on-target BTF probe) */
    numeric_pid = BPF_CORE_READ(pid_struct, numbers[0].nr);
    if (numeric_pid <= 0)
        return 0;

    target = bpf_task_from_pid(numeric_pid);
    if (!target)
        return 0;

    target_tgid = (__u32)BPF_CORE_READ(target, tgid);
    if (!hk_is_protected_tgid(target_tgid)) {
        bpf_task_release(target);
        return 0;
    }

    caller_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    /* Same-tgid self-open of /proc/self/mem is benign. */
    if (caller_tgid == target_tgid) {
        bpf_task_release(target);
        return 0;
    }

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt) {
        bpf_task_release(target);
        return 0;
    }

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_BPF_PROC_MEM_OPEN;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->caller_pid     = caller_tgid;
    evt->target_pid     = target_tgid;

    bpf_task_release(target);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
