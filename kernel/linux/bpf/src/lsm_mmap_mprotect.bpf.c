/*
 * Role: BPF LSM mapping-anomaly sensors. Two emit paths over the same mmap hook
 *       plus an mprotect hook, all AUDIT-ONLY:
 *         - Signal 76: RWX map (lsm/mmap_file with PROT_WRITE|PROT_EXEC) and
 *           W^X / text->writable flip (lsm/file_mprotect adding PROT_WRITE to an
 *           executable VMA) inside the PROTECTED game's own mm.
 *         - Signal 79: foreign-tgid mmap of the protected game's own file-backed
 *           text/data inode (dev,inode match against hk_protected, mapper tgid
 *           != protected tgid).
 *       Both compare bpf_ktime_get_ns() to hk_protected.load_done_ns so post-
 *       link patches separate from legitimate dynamic-linker / loader activity.
 * Target platform: Linux eBPF (BPF LSM, kernel >= 5.7; CONFIG_BPF_LSM + lsm=bpf).
 * Interface: implements lsm/mmap_file + lsm/file_mprotect; reads hk_protected
 *            (include/hk_protected.bpf.h); writes hk_ringbuf (extern, shared via
 *            Loader.cpp). Maps to server events HK_EVENT_RWX_MAP /
 *            HK_EVENT_WX_FLIP / HK_EVENT_FOREIGN_MAP.
 *
 * Guardrail compliance:
 *   #1  No raw platform macros — Linux-only by build gating.
 *   #3  This module comment covers role/platform/interface.
 *   #4  Pure kernel eBPF TU — no userspace headers.
 *   #6  Compiled -Wall -Wextra -Werror (enforced in CMakeLists.txt).
 *
 * FP NOTE: JIT/IL2CPP/LuaJIT/V8/Proton legitimately create
 * RWX and W->X->W and grow VM_EXEC VMAs. Signals 76/79 are LOW-CONFIDENCE
 * evidence only and must NOT be wired to the fail-closed ban path until per-
 * title baselining + the signed allow-list (server side) exists. They emit;
 * the server treats them as low-confidence.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "hk_protected.bpf.h"

#define HK_SCHEMA_VERSION   3u
#define HK_BPF_RWX_MAP      0x60u
#define HK_BPF_WX_FLIP      0x61u
#define HK_BPF_FOREIGN_MAP  0x62u

/* PROT_* (mman-common.h) and VM_* (mm.h) bits we test. Duplicated as #defines:
 * they are not types, so BTF/vmlinux.h does not carry them. */
#ifndef PROT_READ
#define PROT_READ   0x1u
#endif
#ifndef PROT_WRITE
#define PROT_WRITE  0x2u
#endif
#ifndef PROT_EXEC
#define PROT_EXEC   0x4u
#endif

#ifndef VM_WRITE
#define VM_WRITE    0x00000002u
#endif
#ifndef VM_EXEC
#define VM_EXEC     0x00000004u
#endif

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/* Mirrored in Loader.cpp as HkBpfMapAnomalyEvent. */
struct hk_bpf_map_anomaly_event {
    __u32 schema_version;
    __u32 event_tag;        /* HK_BPF_RWX_MAP | HK_BPF_WX_FLIP | HK_BPF_FOREIGN_MAP */
    __u64 timestamp_ns;
    __u32 caller_pid;       /* mapping/mprotecting tgid             */
    __u32 prot;             /* requested PROT_* bits                */
    __u32 vm_flags;         /* existing VMA VM_* (mprotect/foreign)  */
    __u32 reserved;
    __u64 dev;              /* backing s_dev (0 = anon)             */
    __u64 inode;            /* backing i_ino (0 = anon)             */
};

/* Read (dev,inode) for a file, 0/0 if anonymous (file == NULL). */
static __always_inline void
hk_file_dev_inode(struct file *file, __u64 *dev, __u64 *inode)
{
    if (!file) {
        *dev = 0;
        *inode = 0;
        return;
    }
    *inode = (__u64)BPF_CORE_READ(file, f_inode, i_ino);
    *dev   = (__u64)BPF_CORE_READ(file, f_inode, i_sb, s_dev);
}

/* True once the protected task's baseline load has settled (load_done_ns set and
 * now strictly after it). Pre-baseline events are loader noise and suppressed. */
static __always_inline int
hk_after_load_done(const struct hk_protected_val *pv)
{
    __u64 ld = pv->load_done_ns;
    return ld != 0 && bpf_ktime_get_ns() > ld;
}

/* ---- Signals 76 (RWX map) + 79 (foreign inode map): lsm/mmap_file --------- */
/*
 * mmap_file(struct file *file, unsigned long reqprot, unsigned long prot,
 *           unsigned long flags) -> int ret
 * `prot` is the actual protection applied (reqprot before arch fixups). We test
 * the applied `prot`.
 */
SEC("lsm/mmap_file")
int BPF_PROG(hk_lsm_mmap_file,
             struct file *file, unsigned long reqprot, unsigned long prot,
             unsigned long flags, int ret)
{
    struct hk_bpf_map_anomaly_event *evt;
    struct hk_protected_val *pv;
    __u32 caller_tgid;
    __u64 dev = 0, inode = 0;

    (void)reqprot; (void)flags;

    caller_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    hk_file_dev_inode(file, &dev, &inode);

    /* Path A — signal 76: the protected game maps RWX inside its OWN mm. */
    pv = hk_protected_lookup(caller_tgid);
    if (pv) {
        if ((prot & PROT_WRITE) && (prot & PROT_EXEC) && hk_after_load_done(pv)) {
            evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
            if (evt) {
                evt->schema_version = HK_SCHEMA_VERSION;
                evt->event_tag      = HK_BPF_RWX_MAP;
                evt->timestamp_ns   = bpf_ktime_get_ns();
                evt->caller_pid     = caller_tgid;
                evt->prot           = (__u32)prot;
                evt->vm_flags       = 0;
                evt->reserved       = 0;
                evt->dev            = dev;
                evt->inode          = inode;
                bpf_ringbuf_submit(evt, 0);
            }
        }
        /* The game mapping its own inode is expected; do not also fire 79. */
        return ret;
    }

    /* Path B — signal 79: a FOREIGN tgid maps the protected game's own backing
     * (dev,inode). Iterate the protected set is not possible per-key cheaply in
     * a hot hook, so we rely on the userspace populator additionally pinning a
     * secondary (dev,inode)->tgid index when that lands. Until then we cannot
     * answer "is this file the protected inode?" without the reverse index.
     *
     * HK-TODO(schema): a (dev,inode)->protected-tgid reverse map is needed for
     * an O(1) foreign-inode test here; the forward hk_protected map is keyed by
     * tgid only. ProtectedSet.cpp owns populating it. Until that reverse index
     * exists, signal 79 is GATED OFF in-kernel (emits nothing) rather than doing
     * an unbounded scan that would blow the verifier instruction budget. This is
     * the conservative choice (FP-gated by design). */
    if (file == (void *)0)
        return ret;   /* anonymous map by a non-protected task — never 79 */

    return ret;
}

/* ---- Signal 76 (W^X flip): lsm/file_mprotect ------------------------------ */
/*
 * file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
 *               unsigned long prot) -> int ret
 * We flag adding PROT_WRITE to a region that is currently executable (VM_EXEC)
 * inside the protected game's own mm, after load_done_ns.
 */
SEC("lsm/file_mprotect")
int BPF_PROG(hk_lsm_file_mprotect,
             struct vm_area_struct *vma, unsigned long reqprot,
             unsigned long prot, int ret)
{
    struct hk_bpf_map_anomaly_event *evt;
    struct hk_protected_val *pv;
    struct file *file;
    __u32 caller_tgid;
    __u64 vm_flags;
    __u64 dev = 0, inode = 0;

    (void)reqprot;

    if (!vma)
        return ret;

    caller_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    pv = hk_protected_lookup(caller_tgid);
    if (!pv)
        return ret;

    if (!hk_after_load_done(pv))
        return ret;   /* loader-stage relocation; suppressed */

    vm_flags = (__u64)BPF_CORE_READ(vma, vm_flags);

    /* text -> writable: currently executable, request adds write. */
    if (!((vm_flags & VM_EXEC) && (prot & PROT_WRITE)))
        return ret;

    file = BPF_CORE_READ(vma, vm_file);
    hk_file_dev_inode(file, &dev, &inode);

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return ret;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_BPF_WX_FLIP;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->caller_pid     = caller_tgid;
    evt->prot           = (__u32)prot;
    evt->vm_flags       = (__u32)vm_flags;
    evt->reserved       = 0;
    evt->dev            = dev;
    evt->inode          = inode;

    bpf_ringbuf_submit(evt, 0);
    return ret;   /* audit-only */
}

char _license[] SEC("license") = "GPL";
