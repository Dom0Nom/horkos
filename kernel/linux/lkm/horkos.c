/*
 * kernel/linux/lkm/horkos.c
 * Role: Linux LKM entry/exit and process-exec monitoring for the non-Deck path.
 *       Attaches to the sched_process_exec tracepoint and emits a log line per
 *       exec (the full ring-buffer + chrdev pipeline lands later). The primary
 *       Linux path is eBPF (kernel/linux/bpf/); this LKM is gated on
 *       HORKOS_LINUX_LKM for self-hosted servers and non-Deck distros.
 * Target platform: Linux (LKM). Never compiled on Windows or macOS.
 * Interface: implements the module lifecycle (linux/module.h) and a probe for
 *            the sched_process_exec tracepoint (trace/events/sched.h).
 *
 * Mechanism note (important): an out-of-tree module CANNOT register an LSM hook
 * — security_add_hooks() and the security_hook_heads table are not exported to
 * modules, and LSM registration is a boot-time-only path (DEFINE_LSM). So this
 * LKM uses the sched_process_exec TRACEPOINT instead, which IS module-legal and
 * cleanly unregisterable (rmmod-safe). The eBPF path (kernel/linux/bpf/) remains
 * the only LSM-based Linux path. Requires CONFIG_TRACEPOINTS=y.
 *
 * Guardrail compliance:
 *   #1  No raw _WIN32/__linux__/__APPLE__ — the Makefile/CMake gates compilation
 *       to Linux; no preprocessor platform ifdefs here.
 *   #3  This module comment covers role/platform/interface.
 *   #4  Pure kernel TU — no userspace headers.
 *   #6  -Wall -Wextra -Werror set in the Makefile ccflags-y.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>     /* task_struct, task_pid_nr */
#include <linux/binfmts.h>   /* linux_binprm */
#include <linux/rcupdate.h>  /* rcu_read_lock, rcu_dereference */
#include <linux/tracepoint.h>
#include <trace/events/sched.h> /* sched_process_exec tracepoint + register_trace_* */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Horkos Project");
MODULE_DESCRIPTION("Horkos anti-cheat/DRM LKM — process exec monitor");
MODULE_VERSION("0.1.0");

static bool g_probe_registered;

/* --------------------------------------------------------------------------
 * sched_process_exec tracepoint probe.
 *
 * The TRACE_EVENT(sched_process_exec) signature (include/trace/events/sched.h)
 * is: (struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm). The
 * register_trace_* probe takes a leading void *data argument.
 * Reference: include/trace/events/sched.h; Documentation/trace/tracepoints.rst.
 *
 * The tracepoint argument list has been stable across 5.x/6.x.
 * Runs in the exec'ing task's context.
 * -------------------------------------------------------------------------- */
static void horkos_sched_process_exec(void *data, struct task_struct *p,
                                      pid_t old_pid, struct linux_binprm *bprm)
{
    pid_t pid;
    pid_t ppid;
    struct task_struct *parent;

    (void)data;
    (void)old_pid;

    if (p == NULL)
        return;

    pid = task_pid_nr(p);

    rcu_read_lock();
    parent = rcu_dereference(p->real_parent);
    ppid   = (parent != NULL) ? task_pid_nr(parent) : 0;
    rcu_read_unlock();

    /* TODO (later phase): write an hk_event_header + hk_event_process_create
     * record into the kernel ring buffer and wake the chrdev reader. For now,
     * a rate-limited log line keeps the probe exercisable in a VM. */
    pr_info_ratelimited("horkos: exec pid=%d ppid=%d file=%.32s\n",
                        pid, ppid,
                        (bprm != NULL && bprm->filename != NULL) ? bprm->filename
                                                                 : "?");
}

/* --------------------------------------------------------------------------
 * Module lifecycle
 * -------------------------------------------------------------------------- */

static int __init horkos_lkm_init(void)
{
    int ret;

    /* register_trace_sched_process_exec returns 0 on success. Unlike LSM
     * registration, this is fully supported from a module and reversible. */
    ret = register_trace_sched_process_exec(horkos_sched_process_exec, NULL);
    if (ret != 0) {
        pr_err("horkos: failed to register sched_process_exec probe: %d\n", ret);
        return ret;
    }
    g_probe_registered = true;

    pr_info("horkos: LKM loaded (sched_process_exec probe registered)\n");
    return 0;
}

static void __exit horkos_lkm_exit(void)
{
    if (g_probe_registered) {
        unregister_trace_sched_process_exec(horkos_sched_process_exec, NULL);
        /* Ensure no probe is mid-flight on another CPU before the module text
         * is freed. Mandatory after unregister_trace_*. */
        tracepoint_synchronize_unregister();
        g_probe_registered = false;
    }
    pr_info("horkos: LKM unloaded\n");
}

module_init(horkos_lkm_init);
module_exit(horkos_lkm_exit);
