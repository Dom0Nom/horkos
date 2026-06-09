/*
 * kernel/linux/bpf/src/cross_mem_audit.bpf.c
 * Role: Signal 102 — cross-process memory-access audit. Three arms over the same
 *       record: sys_enter_process_vm_readv / _writev tracepoints, lsm/
 *       ptrace_access_check, and a kprobe on mem_open (/proc/pid/mem). Emits the
 *       caller/target tgids + first remote_iov base/len; the wineserver-allowlist
 *       and debugger-tag enrichment is done in Loader.cpp / the verifier (impl-
 *       plan §102), never dropped in-kernel.
 * Target platform: Linux eBPF (tracepoint + LSM + kprobe).
 * Interface: shares hk_ringbuf; emits HK_BPF_PW_CROSS_MEM -> HK_EVENT_CROSS_MEM.
 *            Strictly additive to the existing sys_enter_ptrace probe in
 *            tracepoints.bpf.c (this adds the readv/writev probe the catalog
 *            notes is absent). The ptrace_access_check arm is audit-only.
 *
 * Guardrail compliance: #1 Linux-only by gating; #3 module comment; #4 pure BPF
 *   TU; #6 -Wall -Wextra -Werror; lsm/* returns inbound `ret`.
 *
 * API references:
 *   - sys_enter_process_vm_readv: https://docs.ebpf.io/linux/tracepoints/syscalls/
 *   - ptrace_access_check (LSM):  https://docs.kernel.org/bpf/prog_lsm.html
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

/* Emit one cross-mem record. caller is current; target/addr/len/kind per arm. */
static __always_inline void
hk_emit_cross_mem(__u32 target_tgid, __u32 access_kind,
                  __u64 remote_addr, __u64 remote_len)
{
    struct hk_bpf_pw_cross_mem *evt;
    __u64 now = bpf_ktime_get_ns();

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->schema_version = HK_PW_SCHEMA_VERSION;
    evt->event_tag      = HK_BPF_PW_CROSS_MEM;
    evt->timestamp_ns   = now;
    evt->caller_tgid    = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt->target_tgid    = target_tgid;
    evt->access_kind    = access_kind;
    evt->flags          = 0;   /* WINESERVER/HORKOS_SELF/DEBUGGER set userspace */
    evt->remote_addr    = remote_addr;
    evt->remote_len     = remote_len;
    evt->event_time_ns  = now;

    bpf_ringbuf_submit(evt, 0);
}

/*
 * sys_enter_process_vm_readv arg layout (raw syscall args):
 *   args[0] = pid (target), args[1] = local_iov, args[2] = liovcnt,
 *   args[3] = remote_iov, args[4] = riovcnt, args[5] = flags.
 * We read the target pid and the FIRST remote iov_base/iov_len for evidence.
 * Reading deeper iovs would require a bounded loop; the first base/len is enough
 * for the server correlation, and the full walk is left to userspace.
 */
SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int hk_tp_vm_readv(struct trace_event_raw_sys_enter *ctx)
{
    __u32 target = (__u32)(BPF_CORE_READ(ctx, args[0]) & 0xFFFFFFFFULL);
    const void *remote_iov = (const void *)BPF_CORE_READ(ctx, args[3]);
    __u64 addr = 0, len = 0;

    if (remote_iov) {
        /* struct iovec { void *iov_base; size_t iov_len; } in user memory. */
        struct iovec iov = {};
        if (bpf_probe_read_user(&iov, sizeof(iov), remote_iov) == 0) {
            addr = (__u64)(unsigned long)iov.iov_base;
            len  = (__u64)iov.iov_len;
        }
    }
    hk_emit_cross_mem(target, HK_PW_XMEM_READV, addr, len);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int hk_tp_vm_writev(struct trace_event_raw_sys_enter *ctx)
{
    __u32 target = (__u32)(BPF_CORE_READ(ctx, args[0]) & 0xFFFFFFFFULL);
    const void *remote_iov = (const void *)BPF_CORE_READ(ctx, args[3]);
    __u64 addr = 0, len = 0;

    if (remote_iov) {
        struct iovec iov = {};
        if (bpf_probe_read_user(&iov, sizeof(iov), remote_iov) == 0) {
            addr = (__u64)(unsigned long)iov.iov_base;
            len  = (__u64)iov.iov_len;
        }
    }
    hk_emit_cross_mem(target, HK_PW_XMEM_WRITEV, addr, len);
    return 0;
}

/*
 * lsm/ptrace_access_check(struct task_struct *child, unsigned int mode) -> int ret
 * Fires when a tracer requests access to `child`. Audit-only: report the target
 * tgid and return the inbound `ret`.
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(hk_lsm_ptrace_xmem, struct task_struct *child, unsigned int mode, int ret)
{
    __u32 target = 0;
    (void)mode;
    if (child)
        target = (__u32)BPF_CORE_READ(child, tgid);
    hk_emit_cross_mem(target, HK_PW_XMEM_PTRACE, 0, 0);
    return ret;   /* audit-only: never override the prior ptrace decision */
}

/*
 * kprobe on mem_open — the open handler for /proc/<pid>/mem (fs/proc/base.c).
 * Signature: int mem_open(struct inode *inode, struct file *file).
 * We resolve the TARGET tgid from the proc inode's associated task is non-trivial
 * in-kernel; the catalog places that resolution userspace. Here we emit caller +
 * a PROCMEM kind with target 0 (the loader resolves the target from the fd path).
 *
 * mem_open is a stable, non-inlined symbol on mainline kernels (it is the
 * registered file_operations.open for the proc mem entry), so kprobe-by-name is
 * reliable here — unlike the §108 internal-symbol kprobes flagged uncertain.
 */
SEC("kprobe/mem_open")
int BPF_KPROBE(hk_kp_mem_open, struct inode *inode, struct file *file)
{
    (void)inode; (void)file;
    hk_emit_cross_mem(0, HK_PW_XMEM_PROCMEM, 0, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
