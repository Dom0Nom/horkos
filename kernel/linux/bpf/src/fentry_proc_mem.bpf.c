/*
 * kernel/linux/bpf/src/fentry_proc_mem.bpf.c
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
 * container_of(inode, struct proc_inode, vfs_inode)->pid -> pid_task(pid,
 * PIDTYPE_PID) -> task->tgid.
 *
 * HK-UNCERTAIN(mem-open-attachability): fs/proc/base.c:mem_open is `static` on
 * some kernels and may be absent from BTF/kallsyms; fentry then fails to attach.
 * The loader MUST design in a fallback to lsm/file_open filtered by the proc-mem
 * inode (i_op == proc_mem_inode_operations / dname == "mem" under /proc) — not
 * bolt it on later. CONFIRM mem_open is in BTF on the target kernels before
 * relying on this attach point.
 *
 * HK-UNCERTAIN(proc-inode-core-read): recovering struct pid from the proc_inode
 * via container_of + BPF_CORE_READ relies on the proc_inode layout being in the
 * generated vmlinux.h. If proc_inode is opaque in the target BTF, this read
 * must move to a pid_task helper / get_proc_task kfunc. Verify against BTF.
 */
SEC("fentry/mem_open")
int BPF_PROG(hk_fentry_mem_open, struct inode *inode, struct file *file)
{
    struct hk_bpf_proc_mem_open_event *evt;
    struct proc_inode *pi;
    struct pid *pid;
    struct task_struct *target;
    __u32 caller_tgid;
    __u32 target_tgid;

    (void)file;

    if (!inode)
        return 0;

    /* container_of(inode, struct proc_inode, vfs_inode). bpf_core_read handles
     * the offset via CO-RE; we compute the proc_inode base by subtracting the
     * vfs_inode offset. bpf_core_field_offset gives the relocatable offset. */
    pi = (struct proc_inode *)((char *)inode
            - __builtin_offsetof(struct proc_inode, vfs_inode));

    pid = BPF_CORE_READ(pi, pid);
    if (!pid)
        return 0;

    /* pid_task(pid, PIDTYPE_PID): the first task in the PIDTYPE_PID list.
     * struct pid { ... struct hlist_head tasks[PIDTYPE_MAX]; ... }; the task is
     * the container_of the first hlist node by pid_links[PIDTYPE_PID]. Reading
     * it via CO-RE is layout-sensitive; bpf_task_from_pid is cleaner but takes a
     * numeric pid, which we do not have here. We read tasks[0] (PIDTYPE_PID). */
    {
        struct hlist_node *first;
        first = BPF_CORE_READ(pid, tasks[0].first);
        if (!first)
            return 0;
        /* task->pid_links[PIDTYPE_PID] is the hlist_node embedded in the task;
         * recover the task base. PIDTYPE_PID == 0. */
        target = (struct task_struct *)((char *)first
                    - __builtin_offsetof(struct task_struct, pid_links));
    }

    target_tgid = (__u32)BPF_CORE_READ(target, tgid);
    if (!hk_is_protected_tgid(target_tgid))
        return 0;

    caller_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    /* Same-tgid self-open of /proc/self/mem is benign. */
    if (caller_tgid == target_tgid)
        return 0;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_BPF_PROC_MEM_OPEN;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->caller_pid     = caller_tgid;
    evt->target_pid     = target_tgid;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
