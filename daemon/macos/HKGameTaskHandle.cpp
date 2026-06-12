/*
 * Role: Obtain + validate the game's task_t once and share it to all daemon
 *       pollers (signals 113/114/117). Centralises the single privileged
 *       task_for_pid-equivalent path so the audit-token validation is written
 *       and reviewed exactly once.
 * Target platform: macOS only (built behind `if(APPLE)` in CMake).
 * Interface: implements HKGameTaskGet()/HKGameTaskRelease() from
 *            HKGameTaskHandle.h. Userspace TU — no kernel headers (guardrail #4).
 *
 * Guardrail compliance:
 *   #1  No raw __APPLE__ guard — CMake `if(APPLE)` selects this TU.
 *   #13 The privileged task acquisition is NOT guessed. task_for_pid against a
 *       foreign task requires either SIP-disabled + root or an Apple-granted
 *       `com.apple.security.cs.debugger` / task_for_pid entitlement, and the
 *       exact production path (entitlement vs the ES-provisioned profile)
 *       is unverified. The acquisition is left as an HK-UNCERTAIN stub that
 *       returns failure (valid=false) so every poller degrades to a no-op on a
 *       stock system rather than acting on an unvalidated or absent port.
 */

#include "HKGameTaskHandle.h"

#include <mach/mach.h>
#include <mach/task.h>
#include <bsm/libbsm.h>     /* audit_token_to_pid */
#include <os/log.h>

namespace {
os_log_t hk_log() {
    static os_log_t log = os_log_create("io.horkos.daemon", "game-task");
    return log;
}

/*
 * Validate that a candidate task port really refers to `expect_pid`.
 *
 * The robust cross-task identity check is task_name_for_pid-independent:
 * read the task's audit token via task_info(TASK_AUDIT_TOKEN) and compare
 * audit_token_to_pid() against the expected pid. A raw pid carries a reuse
 * race (pid recycled between resolve and use); the audit token pins identity.
 *
 * Returns true only if the token resolves and matches.
 */
bool validate_task_audit_token(task_t task, pid_t expect_pid) {
    if (task == MACH_PORT_NULL) {
        return false;
    }

    audit_token_t token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t kr = task_info(task, TASK_AUDIT_TOKEN,
                                 reinterpret_cast<task_info_t>(&token), &count);
    if (kr != KERN_SUCCESS) {
        os_log_error(hk_log(),
            "HKGameTask: task_info(TASK_AUDIT_TOKEN) failed: %d", kr);
        return false;
    }

    pid_t got = audit_token_to_pid(token);
    if (got != expect_pid) {
        os_log_error(hk_log(),
            "HKGameTask: audit-token pid mismatch (got %d, expected %d) — "
            "possible pid reuse; rejecting handle", got, expect_pid);
        return false;
    }
    return true;
}
}  // namespace

extern "C" kern_return_t HKGameTaskGet(pid_t pid, HKGameTaskHandle *out) {
    if (out == nullptr) {
        return KERN_INVALID_ARGUMENT;
    }
    out->pid   = pid;
    out->task  = MACH_PORT_NULL;
    out->valid = false;

    /* HK-UNCERTAIN(task-for-pid): acquiring a CONTROL-level task port for a
     * FOREIGN process is the privileged step. The correct production path is
     * unverified:
     *   - task_for_pid(mach_task_self(), pid, &task) needs SIP-disabled + root
     *     OR the (Apple-gated) task_for_pid-allow / cs.debugger entitlement.
     *   - Under a System Extension the path may differ (the ES client does NOT
     *     itself grant task ports).
     * Per guardrail #13 we do NOT guess the entitlement/IRQL-equivalent contract.
     * Until verified on a SIP-disabled dev box (and the production entitlement is
     * confirmed), acquisition is a no-op returning KERN_NOT_SUPPORTED so the
     * pollers run as designed but skip the privileged read.
     * (docs: Apple developer docs (developer.apple.com/forums/thread/734461 and
     * developer.apple.com/documentation/bundleresources/entitlements/
     * com.apple.security.cs.debugger) confirm task_for_pid requires BOTH
     * com.apple.security.cs.debugger on the caller AND com.apple.security.
     * get-task-allow on the target. An ES client does NOT automatically hold
     * these. Still needs on-box confirmation + Apple approval for non-tool use.)
     * When un-stubbing:
     *   1. resolve the port (task_for_pid or the granted equivalent),
     *   2. validate_task_audit_token(task, pid),
     *   3. on success set out->task / out->valid = true.
     * The validation helper below is already wired so step 2 is review-complete.
     */
    (void)validate_task_audit_token;  /* used once the acquisition is un-stubbed */

    os_log(hk_log(),
        "HKGameTask: privileged task acquisition is stubbed (HK-UNCERTAIN: "
        "task_for_pid entitlement/SIP path unverified) — poller no-op for pid %d",
        pid);
    return KERN_NOT_SUPPORTED;
}

extern "C" void HKGameTaskRelease(HKGameTaskHandle *handle) {
    if (handle == nullptr || !handle->valid || handle->task == MACH_PORT_NULL) {
        if (handle != nullptr) {
            handle->task  = MACH_PORT_NULL;
            handle->valid = false;
        }
        return;
    }
    /* The task port was obtained with a send right; drop it. */
    kern_return_t kr = mach_port_deallocate(mach_task_self(), handle->task);
    if (kr != KERN_SUCCESS) {
        os_log_error(hk_log(),
            "HKGameTask: mach_port_deallocate failed: %d", kr);
    }
    handle->task  = MACH_PORT_NULL;
    handle->valid = false;
}
