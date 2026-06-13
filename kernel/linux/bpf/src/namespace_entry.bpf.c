/*
 * Role: Signal 103 — namespace-entry audit (pressure-vessel breach). Stable arm:
 *       sys_enter_setns tracepoint (reports the nsfd + nstype the caller is
 *       joining). Uncertain arm: a kprobe on the internal namespace-install
 *       symbol that would let us read the JOINED ns inode directly — left as an
 *       HK-UNCERTAIN stub pending on-box confirmation of the symbol name/args.
 *       The launcher-lineage / game-ns-inode baseline is userspace
 *       (ContainerNsBaseline.cpp).
 * Target platform: Linux eBPF (tracepoint + kprobe).
 * Interface: shares hk_ringbuf; emits HK_BPF_PW_NS_ENTRY -> HK_EVENT_NS_ENTRY.
 *
 * Guardrail compliance: #1 Linux-only by gating; #3 module comment; #4 pure BPF
 *   TU; #6 -Wall -Wextra -Werror. #13: the install-symbol kprobe is NOT written —
 *   it is a flagged stub (a wrong kprobe target is worse than a delay).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "hk_bpf_shared.h"

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/* CLONE_NEW* flags (sched.h) used as the setns nstype arg. Stable UAPI values. */
#ifndef CLONE_NEWNS
#define CLONE_NEWNS   0x00020000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID  0x20000000
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif

static __always_inline __u32 hk_ns_type_from_flags(__u64 nstype)
{
    if (nstype & CLONE_NEWNS)   return HK_PW_NS_MNT;
    if (nstype & CLONE_NEWPID)  return HK_PW_NS_PID;
    if (nstype & CLONE_NEWUSER) return HK_PW_NS_USER;
    return 0;   /* setns(fd, 0) auto-detects; userspace resolves the real type */
}

static __always_inline void
hk_emit_ns_entry(__u32 ns_type, __u64 target_ns_inode)
{
    struct hk_bpf_pw_ns_entry *evt;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->schema_version  = HK_PW_SCHEMA_VERSION;
    evt->event_tag       = HK_BPF_PW_NS_ENTRY;
    evt->timestamp_ns    = bpf_ktime_get_ns();
    evt->caller_tgid     = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt->target_ns_type  = ns_type;
    evt->target_ns_inode = target_ns_inode;
    evt->game_ns_inode   = 0;   /* filled by the loader/baseliner */
    evt->flags           = 0;   /* OFF_LINEAGE/DEV_NSENTER set userspace */
    evt->reserved        = 0;

    bpf_ringbuf_submit(evt, 0);
}

/*
 * sys_enter_setns arg layout: args[0]=fd, args[1]=nstype (CLONE_NEW* or 0).
 * STABLE arm: report the caller + the requested nstype. We CANNOT cheaply read
 * the joined ns inode here (it requires resolving fd -> nsfs file -> ns_common
 * .inum, a multi-deref fd walk that risks verifier blowups), so target_ns_inode
 * is 0 and the loader resolves it from /proc/<pid>/ns/<type> after the setns
 * returns. The caller lineage check (descendant of pv-bwrap?) is userspace.
 */
SEC("tracepoint/syscalls/sys_enter_setns")
int hk_tp_setns(struct trace_event_raw_sys_enter *ctx)
{
    __u64 nstype = (__u64)BPF_CORE_READ(ctx, args[1]);
    hk_emit_ns_entry(hk_ns_type_from_flags(nstype), 0);
    return 0;
}

/*
 * HK-UNCERTAIN(ns-install-symbol): commit_nsset /
 * install_nsproxy / validate_nsset are candidate kprobe targets to read the
 * JOINED ns inode directly (avoiding the post-hoc /proc resolution above). I am
 * NOT certain which symbol is the stable kprobe target on the target Deck kernel,
 * nor its exact arg layout (struct nsset* vs struct nsproxy*; field offsets to
 * ns_common.inum). On a wrong target this either fails to attach or reads garbage
 * offsets. Per guardrail #12 the kprobe is NOT written — confirm the symbol +
 * arg layout against the target kernel BTF, then implement this arm to populate
 * target_ns_inode in-kernel. Until then the sys_enter_setns arm above carries the
 * signal and the loader fills the inode from /proc.
 * (docs: commit_nsset() is present in kernel/nsproxy.c (torvalds/linux master)
 * and takes a struct nsset* argument; struct nsset contains the new nsproxy.
 * However it is a static internal function — whether it appears in the target
 * kernel BTF/kallsyms depends on the specific Deck kernel build. validate_nsset
 * also in kernel/nsproxy.c. Neither is a stable exported symbol. Confirmed:
 * commit_nsset exists on mainline but on-target kprobe-ability check required)
 *
 * Intended shape once confirmed (DO NOT enable without on-box verification):
 *   SEC("kprobe/<confirmed_symbol>")
 *   int BPF_KPROBE(hk_kp_ns_install, struct <confirmed_type> *set) {
 *       // read set->...->ns_common.inum for each installed ns and emit.
 *   }
 */

char _license[] SEC("license") = "GPL";
