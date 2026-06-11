/*
 * kernel/linux/bpf/src/selfcheck_read.bpf.c
 * Role: Linux eBPF self-read cooperator for the AC's OWN image (memory-integrity-
 *       selfcheck, signals 145/146/152). On a self-read tick for the AC task it
 *       would bpf_probe_read_user the requested VA (145), sample soft-dirty/private
 *       state (146), and observe security_file_mprotect on an exec VMA (152), keyed
 *       to the AC task only. CO-RE; emits self-read replies for the AC task only.
 * Target platform: Linux eBPF (CO-RE; ringbuf >= 5.8; lsm hooks need kernel >= 5.7
 *       + CONFIG_BPF_LSM=y + "bpf" in the lsm= boot parameter — document, do not
 *       assume). Default OFF (locked decision 3); the LKM path serves non-Deck.
 * Interface: shares hk_ringbuf (extern); the libbpf loader keys replies to the AC
 *       task and translates them into the self-read reply plane.
 *
 * Guardrail compliance: #1, #3, #4 (no /proc reads in BPF — the spoofable usermode
 * half lives in the loader), #6 (-Wall -Wextra -Werror at the kernel warning level).
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define HK_SCHEMA_VERSION       3u
#define HK_EVENT_SELF_READ_TICK 0x2Au  /* loader maps to the self-read reply plane */

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/* The loader sets this to the AC task's tgid so the program only ever cooperates
 * for the AC's OWN address space — never a foreign task (the self-read contract). */
const volatile __u32 hk_ac_tgid = 0;

struct hk_bpf_self_read_event {
    __u32 schema_version;
    __u32 event_tag;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 kind;        /* hk_self_read_kind mirror (BYTES/PAGE_SHARE/PTE_PROT) */
};

/* HK-VERIFIED(ebpf-self-read): bpf_probe_read_user() reads user-space memory of
 * the CURRENT task only — it uses set_fs(USER_DS) / uaccess semantics against
 * the running task's mm, not a specified task. There is no BPF helper to read
 * another task's user address space directly. Source: bpf-helpers(7) man page
 * (man7.org/linux/man-pages/man7/bpf-helpers.7.html); kernel commit 6ae08ae3
 * ("bpf: Add probe_read_{user,kernel}") confirms the user variant operates on
 * the current task's USER_DS.
 * Confirms: a foreign read of the AC task from an unrelated probe context is NOT
 * possible via bpf_probe_read_user; the uprobe-on-the-AC-itself pattern (this
 * program's current approach) IS correct for self-read since the uprobe fires in
 * the AC task's context. Soft-dirty (146) and mprotect (152) halves still need
 * kernel config verification. Per guardrail #13 the actual bpf_probe_read_user
 * of the requested VA is NOT performed here; this program only emits a keyed tick
 * that the loader correlates. The LKM path (locked decision 3) is the fallback. */
SEC("uprobe")
int BPF_KPROBE(hk_uprobe_self_read)
{
    struct hk_bpf_self_read_event *evt;
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (hk_ac_tgid != 0u && tgid != hk_ac_tgid)
        return 0; /* not the AC task — never cooperate for a foreign task */

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_EVENT_SELF_READ_TICK;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->pid            = tgid;
    evt->kind           = 0u; /* HK_SELF_READ_BYTES; loader fills the real kind */

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
