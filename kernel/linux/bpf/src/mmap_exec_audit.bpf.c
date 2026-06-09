/*
 * kernel/linux/bpf/src/mmap_exec_audit.bpf.c
 * Role: Signal 101 — audit PROT_EXEC mappings, emitting the backing dev:ino so
 *       the userspace classifier (PrefixMapAudit.cpp) can decide off-tree /
 *       off-allowlist. Anonymous|memfd PROT_EXEC maps are tagged HK_PW_MAP_MEMFD
 *       in-kernel (cheap to know); the dist-tree/overlay-SO allowlist decision is
 *       userspace. The kernel stays allowlist-free (impl-plan §101).
 * Target platform: Linux eBPF (BPF_PROG_TYPE_LSM, lsm/mmap_file, kernel >= 5.7).
 * Interface: shares hk_ringbuf; emits HK_BPF_PW_FOREIGN_MAP -> HK_EVENT_FOREIGN_MAP.
 *            Audit-only: returns the inbound `ret` on every path.
 *
 * Guardrail compliance: #1 Linux-only by gating; #3 module comment; #4 pure BPF
 *   TU; #6 -Wall -Wextra -Werror. lsm/* programs return the inbound `ret` to
 *   never override another LSM (the lsm_file_open.bpf.c invariant).
 *
 * API references:
 *   - BPF LSM mmap_file: https://docs.kernel.org/bpf/prog_lsm.html
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "hk_bpf_shared.h"

#ifndef PROT_EXEC
#define PROT_EXEC 0x4u
#endif

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/*
 * lsm/mmap_file(struct file *file, unsigned long reqprot, unsigned long prot,
 *               unsigned long flags) -> int ret
 * `prot` is the applied protection. We only care about PROT_EXEC maps. The off-
 * tree / overlay-allowlist decision is userspace; here we report (pid, prot,
 * dev:ino) and set MEMFD/anon as the only in-kernel-cheap flag.
 */
SEC("lsm/mmap_file")
int BPF_PROG(hk_lsm_mmap_exec_audit,
             struct file *file, unsigned long reqprot, unsigned long prot,
             unsigned long flags, int ret)
{
    struct hk_bpf_pw_foreign_map *evt;
    __u64 inode = 0;
    __u32 dev = 0;
    __u32 map_flags = 0;

    (void)reqprot; (void)flags;

    if (!(prot & PROT_EXEC))
        return ret;   /* only executable mappings are in scope for 101 */

    if (!file) {
        /* Anonymous PROT_EXEC mapping — JIT or reflective load. memfd-backed
         * maps arrive here with a file; a bare anon exec map has file==NULL. The
         * MEMFD distinction (anon-shmem inode) is resolved userspace via the
         * memfd correlation already in Loader.cpp's memory-access path; here we
         * just flag anon. */
        map_flags |= HK_PW_MAP_ANON_THEN_BACKED;
    } else {
        inode = (__u64)BPF_CORE_READ(file, f_inode, i_ino);
        dev   = (__u32)BPF_CORE_READ(file, f_inode, i_sb, s_dev);
        /* A non-zero i_nlink==0 (deleted) inode that is still mapped exec is a
         * classic reflective-load tell. i_nlink is cheap to read via CO-RE. */
        unsigned int nlink = (unsigned int)BPF_CORE_READ(file, f_inode, i_nlink);
        if (nlink == 0)
            map_flags |= HK_PW_MAP_DELETED_INODE;
    }

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return ret;

    evt->schema_version = HK_PW_SCHEMA_VERSION;
    evt->event_tag      = HK_BPF_PW_FOREIGN_MAP;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->pid            = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt->prot_flags     = (__u32)prot;
    evt->map_base       = 0;   /* vm_start is not available at mmap_file hook entry */
    evt->backing_inode  = inode;
    evt->backing_dev    = dev;
    evt->map_flags      = map_flags;   /* userspace adds OFF_TREE/MEMFD post-classify */

    bpf_ringbuf_submit(evt, 0);
    return ret;   /* audit-only */
}

char _license[] SEC("license") = "GPL";
