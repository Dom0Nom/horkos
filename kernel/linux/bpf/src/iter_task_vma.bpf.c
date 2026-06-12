/*
 * Role: BPF iterator (iter/task_vma) for executable-VMA inventory drift
 *       (signal 80). Driven on a userspace timer trigger from Loader.cpp, it
 *       walks the protected task's VMAs and emits one hk_event_vma_row per
 *       VM_EXEC region (vm_start, vm_end, vm_flags, dev, inode, anon). Userspace
 *       diffs successive snapshots against the baseline taken at load_done_ns;
 *       a new or grown executable region between scans is drift. This is a
 *       STATE-based ground truth orthogonal to the edge-triggered hooks — it
 *       catches a region that already exists even if its creating event was
 *       missed.
 * Target platform: Linux eBPF iterator. REQUIRES kernel >= 5.13 AT RUNTIME for
 *                  the task_vma iterator; compile-time only needs BTF. The
 *                  Loader probes availability and disables signal 80 gracefully
 *                  on older kernels (Steam Deck / self-hosted) — see plan §8.
 * Interface: SEC("iter/task_vma"); reads hk_protected; writes the iterator's
 *            seq_file output stream (read by the Loader via the iter fd), NOT
 *            hk_ringbuf — iterators stream through bpf_seq_write. Maps to server
 *            event HK_EVENT_VMA_DRIFT (one row per emitted record).
 *
 * Guardrail compliance:
 *   #1  No raw platform macros — Linux-only by build gating.
 *   #3  This module comment covers role/platform/interface.
 *   #4  Pure kernel eBPF TU — no userspace headers.
 *   #6  Compiled -Wall -Wextra -Werror (enforced in CMakeLists.txt).
 *
 * FP NOTE (impl-plan §7): JIT titles legitimately grow VM_EXEC VMAs; signal 80
 * is low-confidence evidence, NOT a fail-closed ban input until per-title
 * baselining exists. It emits state; the server treats it as low-confidence.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "hk_protected.bpf.h"

#define HK_SCHEMA_VERSION   3u
#define HK_BPF_VMA_ROW      0x90u

#ifndef VM_EXEC
#define VM_EXEC     0x00000004u
#endif

/*
 * One streamed row. Mirrored in Loader.cpp as HkBpfVmaRow. Unlike the ringbuf
 * sensors, the iterator writes rows into the seq stream via bpf_seq_write; the
 * Loader reads the iter fd to consume them. The leading {schema_version,
 * event_tag, timestamp_ns} triple is kept for a uniform decode path.
 */
struct hk_bpf_vma_row {
    __u32 schema_version;
    __u32 event_tag;        /* HK_BPF_VMA_ROW */
    __u64 timestamp_ns;
    __u32 pid;
    __u32 vm_flags;         /* VM_EXEC | VM_WRITE | ... */
    __u64 vm_start;
    __u64 vm_end;
    __u64 dev;              /* 0 = anonymous */
    __u64 inode;
};

/*
 * iter/task_vma context: struct bpf_iter__task_vma { struct bpf_iter_meta *meta;
 * struct task_struct *task; struct vm_area_struct *vma; }. The iterator is
 * invoked once per (task,vma); `task`/`vma` are NULL on the terminating call.
 * We only iterate tasks in hk_protected and only emit VM_EXEC VMAs.
 */
SEC("iter/task_vma")
int hk_iter_task_vma(struct bpf_iter__task_vma *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    struct vm_area_struct *vma = ctx->vma;
    struct hk_bpf_vma_row row = {};
    struct file *file;
    __u32 tgid;
    __u64 vm_flags;

    if (!task || !vma)
        return 0;   /* terminating call or hole */

    tgid = (__u32)BPF_CORE_READ(task, tgid);
    if (!hk_is_protected_tgid(tgid))
        return 0;

    vm_flags = (__u64)BPF_CORE_READ(vma, vm_flags);
    if (!(vm_flags & VM_EXEC))
        return 0;   /* only executable regions are in scope for drift */

    row.schema_version = HK_SCHEMA_VERSION;
    row.event_tag      = HK_BPF_VMA_ROW;
    row.timestamp_ns   = bpf_ktime_get_ns();
    row.pid            = tgid;
    row.vm_flags       = (__u32)vm_flags;
    row.vm_start       = (__u64)BPF_CORE_READ(vma, vm_start);
    row.vm_end         = (__u64)BPF_CORE_READ(vma, vm_end);

    file = BPF_CORE_READ(vma, vm_file);
    if (file) {
        row.inode = (__u64)BPF_CORE_READ(file, f_inode, i_ino);
        row.dev   = (__u64)BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    } else {
        row.inode = 0;   /* anonymous executable mapping — strongest drift tell */
        row.dev   = 0;
    }

    /* bpf_seq_write streams the row to the iter fd's seq buffer; returns 0 on
     * success or -E2BIG if the buffer is full (the kernel re-invokes for the
     * same element after userspace drains). We ignore the value: a full buffer
     * is retried by the iterator framework. */
    bpf_seq_write(seq, &row, sizeof(row));
    return 0;
}

char _license[] SEC("license") = "GPL";
