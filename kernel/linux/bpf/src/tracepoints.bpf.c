/*
 * kernel/linux/bpf/src/tracepoints.bpf.c
 * Role: BPF tracepoint programs for syscalls/sys_enter_ptrace and
 *       sched/sched_process_exec.  Both programs push event records to the
 *       shared hk_ringbuf so the userspace loader can convert them to
 *       hk_event_records (event_schema.h) and forward them to the server.
 * Target platform: Linux eBPF (BPF_PROG_TYPE_TRACEPOINT, kernel ≥ 4.7
 *                  for tracepoints; kernel ≥ 5.8 for shared ringbuf).
 * Interface: shares hk_ringbuf with lsm_file_open.bpf.c (declared extern
 *            here); both .bpf.o files must be linked into the same BPF
 *            object set by the loader so the map descriptor is unified.
 *
 * Tracepoint context struct layouts (sys_enter_ptrace, sched_process_exec)
 * are accessed via CO-RE (BPF_CORE_READ) and the vmlinux BTF, so they
 * relocate correctly across kernel versions.
 *
 * API references:
 *   - Tracepoints:         https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_TRACEPOINT/
 *   - sched_process_exec:  https://docs.ebpf.io/linux/tracepoints/sched/sched_process_exec/
 *   - sys_enter_ptrace:    https://docs.ebpf.io/linux/tracepoints/syscalls/sys_enter_ptrace/
 *   - ringbuf:             https://docs.kernel.org/bpf/ringbuf.html
 *   - CO-RE:               https://docs.ebpf.io/linux/concepts/CO-RE/
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

/* ---- Wire-format constants (mirror lsm_file_open.bpf.c) ------------------ */
#define HK_SCHEMA_VERSION       2u
#define HK_EVENT_PTRACE         0x20u   /* BPF-side tag; loader maps to server type */
#define HK_EVENT_PROC_EXEC      0x21u   /* BPF-side tag; loader maps to HK_EVENT_PROCESS_CREATE */
#define HK_PATH_MAX             256

/* ---- Shared ring buffer (defined in lsm_file_open.bpf.c) ----------------- */
/*
 * The two .bpf.c files are compiled into two independent skeletons, so the
 * map is NOT shared by libbpf extern name-resolution. Sharing is achieved in
 * Loader.cpp, which calls bpf_map__reuse_fd() to repoint this object's
 * hk_ringbuf at the already-created fd before load. The extern declaration here
 * just lets this TU reference the map symbol.
 */
extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/* ---- Ring-buffer event layouts ------------------------------------------- */

struct hk_bpf_ptrace_event {
    __u32 schema_version;
    __u32 event_tag;
    __u64 timestamp_ns;
    __u32 pid;          /* tracer (caller of ptrace) */
    __u32 target_pid;   /* PTRACE_* request target */
    __u64 request;      /* ptrace request code */
};

struct hk_bpf_exec_event {
    __u32 schema_version;
    __u32 event_tag;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 parent_pid;
    char  filename[HK_PATH_MAX];
};

/* ---- Tracepoint: syscalls/sys_enter_ptrace -------------------------------- */
/*
 * Fires on entry to every ptrace(2) syscall.  We record the calling PID and
 * the target PID (pid argument to ptrace) to detect suspicious cross-process
 * inspection.
 *
 * sys_enter_ptrace tracepoint context layout (from vmlinux.h / BTF):
 *   long  __syscall_nr
 *   long  request   (PTRACE_ATTACH, PTRACE_PEEKDATA, etc.)
 *   long  pid       (target pid_t)
 *   long  addr
 *   long  data
 *
 * The tracepoint context struct field names and sizes are stable across
 * kernels (they are the raw syscall args).  CO-RE relocation corrects field
 * offsets but cannot invent fields absent in the target BTF; vmlinux.h must
 * be generated on the target kernel.
 */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int hk_tp_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    struct hk_bpf_ptrace_event *evt;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_EVENT_PTRACE;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->pid            = bpf_get_current_pid_tgid() >> 32;
    /* args[0] = request, args[1] = target pid.
     * trace_event_raw_sys_enter.args is a fixed array; CO-RE handles the
     * offset.  We cast to __u32 after masking to avoid sign-extension.
     * Reference: include/trace/events/syscalls.h in the kernel source. */
    evt->request        = (__u64)BPF_CORE_READ(ctx, args[0]);
    evt->target_pid     = (__u32)(BPF_CORE_READ(ctx, args[1]) & 0xFFFFFFFFULL);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* ---- Tracepoint: sched/sched_process_exec -------------------------------- */
/*
 * Fires after execve succeeds and the new binary has been fully set up but
 * before it runs.  At this point current->pid reflects the execing process
 * and current->real_parent->pid is the parent.
 *
 * sched_process_exec tracepoint context layout (vmlinux.h):
 *   struct trace_event_raw_sched_process_exec {
 *       ...
 *       __data_loc char[] filename;   (data-location encoded offset+len)
 *       pid_t             pid;
 *       pid_t             old_pid;
 *   };
 *
 * __data_loc fields are not directly CO-RE accessible with plain BPF_CORE_READ
 * — use bpf_probe_read_kernel_str with the __data_loc-decoded pointer.
 * BPF_CORE_READ_STR_INTO is the idiomatic helper for this pattern (libbpf ≥ 0.4).
 * Reference: https://nakryiko.com/posts/bpf-core-reference-guide/#reading-strings
 *            https://docs.ebpf.io/linux/tracepoints/sched/sched_process_exec/
 */
SEC("tracepoint/sched/sched_process_exec")
int hk_tp_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct hk_bpf_exec_event *evt;
    struct task_struct *task;
    struct task_struct *parent;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_EVENT_PROC_EXEC;
    evt->timestamp_ns   = bpf_ktime_get_ns();

    task   = (struct task_struct *)bpf_get_current_task();
    evt->pid = BPF_CORE_READ(ctx, pid);

    parent = BPF_CORE_READ(task, real_parent);
    evt->parent_pid = (parent != NULL) ? BPF_CORE_READ(parent, pid) : 0;

    /* Read the filename from the __data_loc-encoded field. The data_loc word
     * packs the string OFFSET in its low 16 bits (length in the high 16). This
     * is the canonical libbpf-bootstrap sched_process_exec idiom: access the
     * field directly on the raw tracepoint ctx (CO-RE-relocated by -g/BTF), not
     * via BPF_CORE_READ.
     *
     * The generated vmlinux.h names the field `__data_loc_filename` in
     * trace_event_raw_sched_process_exec — true on mainline 5.x/6.x. */
    unsigned int fname_off = (unsigned int)(ctx->__data_loc_filename & 0xFFFFu);
    const char  *fname_ptr = (const char *)ctx + fname_off;
    long rc = bpf_probe_read_kernel_str(evt->filename,
                                        sizeof(evt->filename),
                                        fname_ptr);
    if (rc < 0)
        evt->filename[0] = '\0';

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* ===========================================================================
 * Signals 98 + 99 — MSR / devmem writes via syscall tracepoints.
 *
 * §1.2 / §7-A split: the BPF side stays SIMPLE and verifier-friendly. It emits
 * the RAW (pid, fd, file_offset, write_intent) for write/pwrite64/mmap on a fd;
 * USERSPACE (Loader.cpp translate path / MsrPathResolver) resolves whether the
 * fd is /dev/cpu/N/msr or a devmem node and whether the offset (= MSR index for
 * msr writes) is in the sensitive set (LSTAR 0xC0000082, SYSENTER_EIP 0x176,
 * debug/feature-control MSRs). Doing the fd→path walk in BPF (task->files->fdt->
 * fd[fd]->f_path, dentry/inode match) risks verifier complexity blowups, so we
 * do NOT do it here.
 *
 * HK-UNCERTAIN(msr-fd-identity-in-bpf): without the fd→path walk, the BPF side
 * cannot itself know the fd is an msr node — it reports EVERY write/pwrite64 fd +
 * offset, which would flood the ring. To bound this WITHOUT the verifier-heavy
 * walk, the program is GATED on the protected set is NOT applicable (these are
 * host-wide kernel-memory writes). The lower-risk shippable form: emit only
 * pwrite64/pwrite (which carry an explicit offset = candidate MSR index) and let
 * userspace drop non-msr fds. CONFIRM on-box whether an inexpensive CO-RE
 * fd→i_rdev read at sys_enter is verifier-safe before widening to plain write().
 * Until confirmed, this program covers sys_enter_pwrite64 only and tags every
 * record for userspace fd-resolution; sys_enter_write (no offset arg) and the
 * PROT_WRITE-mmap correlation are left as // HK-TODO below.
 * (docs: there is no BPF helper to resolve fd→file→path in O(1) at a syscall
 * tracepoint without a multi-hop pointer walk through task->files->fdt->fd[n]->
 * f_path. The pointer chain is verifier-hostile (unbounded ptr-to-ptr). Reading
 * fd→f_inode→i_rdev at sys_enter IS a finite chain but requires the fd to have
 * already been resolved to a file pointer, which requires dereferencing the files
 * table — must be validated against target verifier — still needs on-target test)
 * ===========================================================================*/

/* 0xA1: module-trust msr-write tag (0x31 is taken by ptrace-traceme; the
 * module-trust domain uses the 0xA0 range — see lsm_file_open.bpf.c). */
#define HK_BPF_MSR_WRITE    0xA1u   /* loader maps to HK_EVENT_MSR_WRITE_SENSITIVE */

/* Mirrored in Loader.cpp as HkBpfMsrEvent. The device identity + MSR-index
 * sensitivity decision lives in userspace (MsrPathResolver), not here. */
struct hk_bpf_msr_event {
    __u32 schema_version;
    __u32 event_tag;        /* HK_BPF_MSR_WRITE */
    __u64 timestamp_ns;
    __u32 requesting_pid;
    __u32 fd;               /* the written fd; userspace resolves to a device */
    __u64 file_offset;      /* pwrite64 offset = candidate MSR index */
};

/* sys_enter_pwrite64 arg layout (raw syscall args):
 *   args[0] = fd, args[1] = buf, args[2] = count, args[3] = pos (offset).
 * We forward fd + offset; userspace decides if fd is /dev/cpu/N/msr and if the
 * offset is a sensitive MSR index. */
SEC("tracepoint/syscalls/sys_enter_pwrite64")
int hk_tp_pwrite64(struct trace_event_raw_sys_enter *ctx)
{
    struct hk_bpf_msr_event *evt;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_BPF_MSR_WRITE;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->requesting_pid = bpf_get_current_pid_tgid() >> 32;
    evt->fd             = (__u32)(BPF_CORE_READ(ctx, args[0]) & 0xFFFFFFFFULL);
    evt->file_offset    = (__u64)BPF_CORE_READ(ctx, args[3]);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* HK-TODO(schema): sys_enter_write (no explicit offset; the MSR index comes from
 * the fd's current position, which BPF cannot read cheaply) and the
 * sys_enter_mmap PROT_WRITE-of-an-msr/devmem-fd correlation (§1.2(a)) are left
 * unimplemented pending the §7-A fd-resolution confirmation. Adding them without
 * the fd identity would flood the ring with every write()/mmap() in the system.
 */

char _license[] SEC("license") = "GPL";
