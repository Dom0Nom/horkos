/*
 * Role: P_TRACED transition-edge detector (signal 116) via
 *       sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID). Reports only the
 *       untraced->traced edge with the attaching pid (kp_eproc.e_ppid),
 *       correlated server-side with the GET_TASK source.
 * Target platform: macOS only (built behind `if(APPLE)`).
 * Interface: implements HKPtracePoll() from HKPtraceWatch.h.
 *
 * Guardrail compliance:
 *   #1  No platform #ifdef — CMake selects this TU.
 *   #13 sysctl(KERN_PROC_PID) -> struct kinfo_proc is a documented, stable,
 *       non-privileged read (it does NOT require a task port), so it is
 *       implemented for real here rather than stubbed. The build-channel gate
 *       (release_signed) is supplied by the caller, not guessed here.
 */

#include "HKPtraceWatch.h"

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/proc.h>      /* P_TRACED, struct kinfo_proc via sys/sysctl */
#include <string.h>
#include <os/log.h>

namespace {
os_log_t hk_log() {
    static os_log_t log = os_log_create("io.horkos.daemon", "ptrace-watch");
    return log;
}
}  // namespace

extern "C" bool HKPtracePoll(HKPtraceWatchState *state,
                             bool                release_signed,
                             hk_es_ptrace       *out_event) {
    if (state == nullptr || out_event == nullptr) {
        return false;
    }

    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, static_cast<int>(state->pid) };
    struct kinfo_proc kp;
    memset(&kp, 0, sizeof(kp));
    size_t len = sizeof(kp);

    if (sysctl(mib, 4, &kp, &len, nullptr, 0) != 0 || len == 0) {
        /* Process gone or query failed; reset the baseline so a later relaunch
         * with the same pid is treated as a fresh untraced start. */
        state->have_baseline = false;
        return false;
    }

    bool traced_now = (kp.kp_proc.p_flag & P_TRACED) != 0;

    bool is_edge = false;
    if (state->have_baseline && !state->last_traced && traced_now) {
        is_edge = true;
    }
    state->have_baseline = true;
    state->last_traced   = traced_now;

    if (!is_edge) {
        return false;
    }

    memset(out_event, 0, sizeof(*out_event));
    out_event->game_pid          = static_cast<uint32_t>(state->pid);
    /* e_ppid is the parent; for a PT_ATTACH tracer the tracer becomes the
     * parent of the traced process, so e_ppid is the attaching pid. The server
     * cross-checks this against the GET_TASK source for confirmation. */
    out_event->tracer_pid        = static_cast<uint32_t>(kp.kp_eproc.e_ppid);
    out_event->traced_now        = 1u;
    out_event->cs_release_signed = release_signed ? 1u : 0u;

    os_log(hk_log(),
        "HKPtraceWatch: P_TRACED edge on pid %d (tracer %d, release_signed=%d)",
        state->pid, kp.kp_eproc.e_ppid, release_signed ? 1 : 0);
    return true;
}
