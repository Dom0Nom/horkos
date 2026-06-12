/*
 * Role: BPF-side shared header for the protected-target gating map. Every
 *       memory-access sensor (.bpf.c) includes this to read the pinned
 *       `hk_protected` BPF_MAP_TYPE_HASH and decide, in-kernel and as early
 *       as possible, whether the subject task is one of the protected game
 *       processes. This is the single structural gate (impl-plan §"protected-
 *       target gating") that keeps signals 74/75/76/79/80 from becoming
 *       unfilterable firehoses; without a populated map nothing fires.
 * Target platform: Linux eBPF only (BPF LSM / fentry / fexit / iterator
 *                  programs; included into kernel BPF TUs, never userspace).
 * Interface: declares the `hk_protected` map, `struct hk_protected_val`, and
 *            the `hk_is_protected_tgid()` / `hk_protected_lookup()` inlines.
 *            The userspace counterpart that POPULATES the map lives in
 *            kernel/linux/userspace/ProtectedSet.{h,cpp} (separate TU,
 *            guardrail #4).
 *
 * This header is a pure BPF TU fragment: it uses only vmlinux.h types
 * (__u32/__u64) and libbpf map macros. It must NOT pull in <stdint.h> or any
 * libc header (-nostdinc on the BPF compile line, guardrail #6). The including
 * .bpf.c is responsible for `#include "vmlinux.h"` and the bpf/ helper headers
 * BEFORE including this file.
 *
 * Guardrail compliance:
 *   #1  No raw platform macros — Linux-only by build gating.
 *   #3  This module comment covers role/platform/interface.
 *   #4  BPF-side only; the userspace populator is a separate TU.
 *   #6  Compiled -Wall -Wextra -Werror with the rest of the BPF set.
 */

#ifndef HK_PROTECTED_BPF_H
#define HK_PROTECTED_BPF_H

/* The including .bpf.c must have already pulled in "vmlinux.h" (for __u32/__u64)
 * and <bpf/bpf_helpers.h> (for SEC, __uint, __type, bpf_map_lookup_elem). We do
 * not include them here to avoid double-inclusion ordering surprises across the
 * different sensor TUs — they all include the helpers first by convention. */

/* ---- Protected-target value ---------------------------------------------- */
/*
 * One row per protected tgid. Populated from userspace (ProtectedSet.cpp) out of
 * the Linux attestation backend's recorded identity for the game process:
 *   - dev/inode: the main executable's file-backing (st_dev/st_ino). Used by
 *     signals 76/79 to recognise a mapping of the game's own text/data inode.
 *   - load_done_ns: bpf_ktime_get_ns() captured by userspace once the dynamic
 *     linker has settled, so signals 76/79/80 can separate legitimate loader
 *     activity (RWX during relocation, growing VM_EXEC VMAs) from post-link
 *     patches. A flip BEFORE this timestamp is loader noise; AFTER it is
 *     suspicious. Zero means "baseline not yet recorded" — sensors that depend
 *     on it must treat 0 as "do not yet trust the post-link distinction".
 */
struct hk_protected_val {
    __u64 dev;          /* main-executable backing super_block s_dev */
    __u64 inode;        /* main-executable backing i_ino             */
    __u64 load_done_ns; /* ktime after dynamic linker settled (76/79/80) */
};

/* ---- Protected-set map ---------------------------------------------------- */
/*
 * key   = protected tgid (__u32)
 * value = struct hk_protected_val
 *
 * BPF_MAP_TYPE_HASH, small fixed capacity (a host runs few protected titles at
 * once). Populated/cleared exclusively from userspace via bpf_map_update_elem /
 * bpf_map_delete_elem on the pinned fd (ProtectedSet.cpp). The map is shared by
 * every memory-access sensor through libbpf's bpf_map__reuse_fd() repointing in
 * Loader.cpp, mirroring how hk_ringbuf is shared today.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct hk_protected_val);
} hk_protected SEC(".maps");

/* ---- Lookup helpers ------------------------------------------------------- */
/*
 * hk_protected_lookup — return the protected row for `tgid`, or NULL if the tgid
 * is not protected. NULL is the common case (most tasks on the box are not the
 * game), so callers bail immediately on NULL to hold the verifier instruction
 * budget and the false-positive budget.
 */
static __always_inline struct hk_protected_val *
hk_protected_lookup(__u32 tgid)
{
    return bpf_map_lookup_elem(&hk_protected, &tgid);
}

/*
 * hk_is_protected_tgid — boolean convenience wrapper for sensors that only need
 * the membership test and not the dev/inode/load_done_ns fields.
 */
static __always_inline int
hk_is_protected_tgid(__u32 tgid)
{
    return hk_protected_lookup(tgid) != (void *)0;
}

/* ---- Task-resolution kfuncs (kernel >= 5.17) -----------------------------
 * BPF kfuncs are NOT declared by libbpf's headers — a program that calls them
 * must provide the extern `__ksym` prototype, which the verifier resolves
 * against the kernel BTF at load. The vm-access fentry/fexit programs
 * (fentry_proc_mem / fexit_process_vm) resolve a target task by pid and must
 * release the acquired reference; declaring them here keeps the prototypes in
 * one place. Programs that do not call them are unaffected (unused extern).
 */
extern struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

#endif /* HK_PROTECTED_BPF_H */
