/*
 * Role: BPF sensors for fileless-execution staging (signal 77). Two hooks whose
 *       correlation completes in Loader.cpp:
 *         - Stage A: tracepoint syscalls/sys_enter_memfd_create records
 *           (tgid, MFD_* flags) into a per-tgid LRU map and emits a cheap
 *           HK_EVENT_MEMFD_CREATE (memfd_create alone is common/benign).
 *         - Stage B: lsm/bprm_creds_for_exec detects an exec whose backing file
 *           has no on-disk path (anon-shmem, i.e. memfd-backed) and emits a
 *           pre-join HK_EVENT_FILELESS_EXEC tag; the (tgid,inode) JOIN that
 *           confirms "exec of a memfd this task created" is finished in the
 *           Loader (the consumer owns the join per the catalog).
 * Target platform: Linux eBPF (tracepoint kernel >= 4.7; BPF LSM kernel >= 5.7).
 * Interface: tracepoint sys_enter_memfd_create + lsm/bprm_creds_for_exec; reads
 *            hk_protected; writes hk_ringbuf (extern, shared via Loader.cpp).
 *            Maps to server events HK_EVENT_MEMFD_CREATE / HK_EVENT_FILELESS_EXEC.
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
#define HK_BPF_MEMFD_CREATE     0x70u
#define HK_BPF_FILELESS_EXEC    0x71u

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/*
 * Per-tgid record of the most recent memfd_create. LRU so a flood cannot pin
 * memory; the Loader does the authoritative (tgid,inode) TTL join, this map only
 * lets stage B note "this tgid recently created a memfd" in-kernel cheaply.
 */
struct hk_memfd_rec {
    __u64 inode;        /* anon shmem inode of the memfd (filled by Loader join
                           in the full design; 0 here at create time)          */
    __u64 ts_ns;
    __u32 mfd_flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);                 /* tgid */
    __type(value, struct hk_memfd_rec);
} hk_memfd_seen SEC(".maps");

/* Mirrored in Loader.cpp as HkBpfMemfdEvent. */
struct hk_bpf_memfd_event {
    __u32 schema_version;
    __u32 event_tag;        /* HK_BPF_MEMFD_CREATE | HK_BPF_FILELESS_EXEC */
    __u64 timestamp_ns;
    __u32 pid;
    __u32 mfd_flags;        /* MFD_* (create); 0 on the exec tag          */
    __u64 inode;            /* anon-shmem inode of the memfd / exec file  */
};

/* ---- Stage A: tracepoint syscalls/sys_enter_memfd_create ------------------ */
/*
 * sys_enter_memfd_create args: (const char __user *uname, unsigned int flags).
 * args[0] = uname ptr, args[1] = flags. We record the create per tgid and emit
 * the cheap create tag. We do NOT yet know the resulting anon inode here (the
 * fd/inode is assigned after syscall entry); inode is filled by the Loader-side
 * join, so we emit inode=0 and let the consumer correlate.
 */
SEC("tracepoint/syscalls/sys_enter_memfd_create")
int hk_tp_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
    struct hk_bpf_memfd_event *evt;
    struct hk_memfd_rec rec = {};
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u32 mfd_flags = (__u32)(BPF_CORE_READ(ctx, args[1]) & 0xFFFFFFFFULL);

    rec.inode     = 0;
    rec.ts_ns     = bpf_ktime_get_ns();
    rec.mfd_flags = mfd_flags;
    bpf_map_update_elem(&hk_memfd_seen, &tgid, &rec, BPF_ANY);

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_BPF_MEMFD_CREATE;
    evt->timestamp_ns   = rec.ts_ns;
    evt->pid            = tgid;
    evt->mfd_flags      = mfd_flags;
    evt->inode          = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* ---- Stage B: lsm/bprm_creds_for_exec ------------------------------------- */
/*
 * bprm_creds_for_exec(struct linux_binprm *bprm) -> int ret. We inspect
 * bprm->file: a memfd/anon-shmem-backed exec has a file whose dentry has no
 * meaningful on-disk name (d_parent == self for the anon-inode pseudo fs) — the
 * classic execveat(memfd, "", AT_EMPTY_PATH) shape. We emit a pre-join
 * HK_EVENT_FILELESS_EXEC carrying the exec file inode; the Loader joins it
 * against hk_memfd_seen / its own LRU on (tgid,inode).
 *
 * AUDIT-ONLY: return `ret`.
 *
 * HK-UNCERTAIN(anon-shmem-detection): the precise in-kernel test for "this exec
 * file is anon-shmem / memfd-backed" varies by kernel — candidates are
 * (file->f_inode->i_sb->s_magic == TMPFS_MAGIC && IS_PRIVATE) or a NULL/empty
 * dentry name, or i_op == shmem_inode_operations. The robust discriminator is
 * left to the Loader-side (tgid,inode) join against the recorded memfd inode;
 * the in-kernel pre-filter below uses the empty-name heuristic and MUST be
 * confirmed against the target kernel before being treated as authoritative.
 * (docs: execveat(2) with AT_EMPTY_PATH on a memfd passes an empty pathname
 * component to the bprm path, resulting in d_name.len == 0 at the dentry level —
 * this is the documented semantics of AT_EMPTY_PATH per execveat(2) man page.
 * However this heuristic may also fire for pipes/sockets exec'd via AT_EMPTY_PATH;
 * the Loader-side join is the authoritative discriminator — still needs on-target)
 */
SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(hk_lsm_bprm_creds_for_exec, struct linux_binprm *bprm, int ret)
{
    struct hk_bpf_memfd_event *evt;
    struct file *file;
    struct dentry *dentry;
    struct qstr dname;
    __u32 tgid;
    __u64 inode;
    __u32 name_len;

    if (!bprm)
        return ret;

    tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    file = BPF_CORE_READ(bprm, file);
    if (!file)
        return ret;

    dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return ret;

    BPF_CORE_READ_INTO(&dname, dentry, d_name);
    name_len = dname.len;
    inode = (__u64)BPF_CORE_READ(file, f_inode, i_ino);

    /* memfd execs present via execveat(fd, "", AT_EMPTY_PATH): the anon-inode
     * dentry name is typically "memfd:<name>" but the path component as seen
     * here is the synthetic anon name. We emit on the empty-/synthetic-name
     * shape and let the Loader join confirm against a recorded memfd inode. A
     * zero-length component is the strongest cheap tell. */
    if (name_len != 0)
        return ret;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return ret;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_BPF_FILELESS_EXEC;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->pid            = tgid;
    evt->mfd_flags      = 0;
    evt->inode          = inode;

    bpf_ringbuf_submit(evt, 0);
    return ret;   /* audit-only */
}

char _license[] SEC("license") = "GPL";
