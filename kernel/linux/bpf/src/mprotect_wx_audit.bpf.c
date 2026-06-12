/*
 * Role: Signal 107 (mprotect arm) — flag PROT_EXEC re-protection of a VMA that is
 *       currently executable-backed, i.e. a W^X re-arm of a Wine builtin's text
 *       page. Emits the VMA range + backing dev:ino + new prot; the in-builtin-
 *       range and inode-off-manifest decisions are userspace
 *       (WineBuiltinIntegrity.cpp), which also runs the on-demand /proc/<pid>/maps
 *       SHA256 inode arm.
 * Target platform: Linux eBPF (BPF_PROG_TYPE_LSM, lsm/file_mprotect).
 * Interface: shares hk_ringbuf; emits HK_BPF_PW_WX_ARM -> HK_EVENT_WX_ARM.
 *
 * Guardrail compliance: #1 Linux-only by gating; #3 module comment; #4 pure BPF
 *   TU; #6 -Wall -Wextra -Werror; lsm/* returns inbound `ret`. #13: the prior-prot
 *   precision is flagged uncertain (see below).
 *
 * NOTE: this is a DISTINCT lsm/file_mprotect program from the memory-access set's
 * hk_lsm_file_mprotect (lsm_mmap_mprotect.bpf.c, signal 76). Multiple BPF LSM
 * programs may attach to the same hook; this one is scoped to the builtin-text
 * W^X re-arm shape (currently-exec VMA, request adds/keeps PROT_EXEC) and does NOT
 * gate on the hk_protected map (it reports broadly, userspace narrows to builtin
 * SOs). The 76 program gates on hk_protected and flags add-WRITE-to-exec; the two
 * are complementary, not duplicates.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "hk_bpf_shared.h"

#ifndef PROT_EXEC
#define PROT_EXEC 0x4u
#endif

#ifndef VM_EXEC
#define VM_EXEC 0x00000004u
#endif

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/*
 * lsm/file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
 *                   unsigned long prot) -> int ret
 * We flag a request that arms PROT_EXEC on a VMA that is (or was) executable and
 * file-backed — the builtin-text re-arm shape. Audit-only.
 */
SEC("lsm/file_mprotect")
int BPF_PROG(hk_lsm_mprotect_wx_audit,
             struct vm_area_struct *vma, unsigned long reqprot,
             unsigned long prot, int ret)
{
    struct hk_bpf_pw_wx_arm *evt;
    struct file *file;
    __u64 vm_flags;
    __u64 vstart = 0, vend = 0, inode = 0;
    __u32 dev = 0;
    __u32 flags = 0;

    (void)reqprot;

    if (!vma)
        return ret;

    /* Only arming PROT_EXEC is in scope (the re-arm half of W^X). */
    if (!(prot & PROT_EXEC))
        return ret;

    vm_flags = (__u64)BPF_CORE_READ(vma, vm_flags);

    /*
     * HK-VERIFIED(prior-prot-reachability): security_file_mprotect() is called
     * by do_mprotect_pkey() (mm/mprotect.c) BEFORE mprotect_fixup() which
     * actually applies the flag change. Therefore vma->vm_flags at hook entry
     * IS the pre-mprotect state. Source: mm/mprotect.c in torvalds/linux master
     * (security_file_mprotect() precedes mprotect_fixup() call; the fixup saves
     * oldflags = vma->vm_flags at its own entry, confirming pre-change state).
     * Confirms: VM_EXEC in vma->vm_flags here accurately reflects "was executable
     * before this mprotect" — the proxy is correct, not a guess.
     */
    if (vm_flags & VM_EXEC)
        flags |= HK_PW_WX_WAS_RX;

    vstart = (__u64)BPF_CORE_READ(vma, vm_start);
    vend   = (__u64)BPF_CORE_READ(vma, vm_end);

    file = BPF_CORE_READ(vma, vm_file);
    if (file) {
        inode = (__u64)BPF_CORE_READ(file, f_inode, i_ino);
        dev   = (__u32)BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    }

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return ret;

    evt->schema_version = HK_PW_SCHEMA_VERSION;
    evt->event_tag      = HK_BPF_PW_WX_ARM;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->pid            = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt->new_prot       = (__u32)prot;
    evt->vma_start      = vstart;
    evt->vma_end        = vend;
    evt->backing_inode  = inode;
    evt->backing_dev    = dev;
    evt->flags          = flags;   /* IN_BUILTIN/INODE_OFF_MANIFEST set userspace */

    bpf_ringbuf_submit(evt, 0);
    return ret;   /* audit-only */
}

char _license[] SEC("license") = "GPL";
