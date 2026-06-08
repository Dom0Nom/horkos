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

char _license[] SEC("license") = "GPL";
