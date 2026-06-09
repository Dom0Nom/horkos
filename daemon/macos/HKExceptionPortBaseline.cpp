/*
 * daemon/macos/HKExceptionPortBaseline.cpp
 * Role: Poll task_get_exception_ports against the validated game task, diff vs a
 *       launch baseline, flag a foreign exception-port owner (signal 113).
 *       Correlated server-side with the ES GET_TASK source.
 * Target platform: macOS only (built behind `if(APPLE)`).
 * Interface: implements HKExcPortCaptureBaseline()/HKExcPortPoll() from the
 *            matching header. Userspace daemon TU (guardrail #4).
 *
 * Guardrail compliance:
 *   #1  No platform #ifdef — CMake selects this TU.
 *   #13 Two distinct uncertainties are flagged rather than guessed:
 *       (a) whether the daemon can read the game's exception ports at all
 *           without a CONTROL-level handle (HKGameTaskHandle is itself stubbed),
 *       (b) resolving a returned exception-port RECEIVE right back to an owning
 *           pid across task boundaries — there is no portable documented API for
 *           that, so owner_pid is emitted as 0 (unresolved) and the server does
 *           the GET_TASK correlation. The DIFF logic (baseline vs current) is
 *           implemented for real; only the owner->pid resolution is left out.
 */

#include "HKExceptionPortBaseline.h"

#include <mach/mach.h>
#include <mach/task.h>
#include <mach/exception_types.h>
#include <string.h>
#include <os/log.h>

namespace {
os_log_t hk_log() {
    static os_log_t log = os_log_create("io.horkos.daemon", "exc-port");
    return log;
}

/*
 * Read the current exception-port set of `task` into parallel arrays. Returns
 * the kern_return_t from task_get_exception_ports. `*count` is in/out: caller
 * sets it to the array capacity (EXC_TYPES_COUNT), the kernel sets it to the
 * number of entries returned.
 *
 * task_get_exception_ports(task, mask, masks[], *count, ports[], behaviors[],
 *                          flavors[]) — masks/ports/behaviors/flavors are
 * parallel out-arrays each of capacity *count. We pass EXC_MASK_ALL to read all.
 */
kern_return_t read_exc_ports(task_t task,
                             exception_mask_t        *masks,
                             mach_msg_type_number_t  *count,
                             mach_port_t             *ports,
                             exception_behavior_t    *behaviors,
                             thread_state_flavor_t   *flavors) {
    return task_get_exception_ports(task, EXC_MASK_ALL,
                                    masks, count, ports, behaviors, flavors);
}
}  // namespace

extern "C" kern_return_t HKExcPortCaptureBaseline(const HKGameTaskHandle *game,
                                                  HKExcPortBaseline      *out_baseline) {
    if (game == nullptr || out_baseline == nullptr) {
        return KERN_INVALID_ARGUMENT;
    }
    memset(out_baseline, 0, sizeof(*out_baseline));

    if (!game->valid || game->task == MACH_PORT_NULL) {
        /* HK-UNCERTAIN(exc-port-read): without a validated CONTROL-level handle
         * (HKGameTaskHandle is stubbed pending the task_for_pid entitlement) we
         * cannot read the game's exception ports. No-op cleanly. */
        return KERN_NOT_SUPPORTED;
    }

    exception_behavior_t  behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    out_baseline->count = EXC_TYPES_COUNT;

    kern_return_t kr = read_exc_ports(game->task,
                                      out_baseline->masks, &out_baseline->count,
                                      out_baseline->ports, behaviors, flavors);
    if (kr != KERN_SUCCESS) {
        os_log_error(hk_log(),
            "HKExcPort: baseline task_get_exception_ports failed: %d", kr);
        out_baseline->captured = false;
        return kr;
    }
    out_baseline->captured = true;
    return KERN_SUCCESS;
}

extern "C" bool HKExcPortPoll(const HKGameTaskHandle  *game,
                              const HKExcPortBaseline *baseline,
                              hk_es_exc_port          *out_event) {
    if (game == nullptr || baseline == nullptr || out_event == nullptr) {
        return false;
    }
    if (!game->valid || game->task == MACH_PORT_NULL || !baseline->captured) {
        return false;  /* no baseline / no handle — nothing to diff */
    }

    exception_mask_t       masks[EXC_TYPES_COUNT];
    mach_port_t            ports[EXC_TYPES_COUNT];
    exception_behavior_t   behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t  flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;

    kern_return_t kr = read_exc_ports(game->task, masks, &count,
                                      ports, behaviors, flavors);
    if (kr != KERN_SUCCESS) {
        os_log_error(hk_log(),
            "HKExcPort: poll task_get_exception_ports failed: %d", kr);
        return false;
    }

    /* Diff: a new/changed port for an overlapping mask is a candidate foreign
     * handler. We compare port names per mask slot against the baseline. A
     * MACH_PORT_NULL->non-null transition, or a different port name for the same
     * mask, is the signal. */
    exception_mask_t changed_mask = 0;
    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        mach_port_t cur = ports[i];
        if (cur == MACH_PORT_NULL) {
            continue;  /* no handler for this slot */
        }
        bool matched_baseline = false;
        for (mach_msg_type_number_t b = 0; b < baseline->count; ++b) {
            if ((baseline->masks[b] & masks[i]) != 0 &&
                baseline->ports[b] == cur) {
                matched_baseline = true;
                break;
            }
        }
        if (!matched_baseline) {
            changed_mask |= masks[i];
        }
    }

    if (changed_mask == 0) {
        return false;
    }

    memset(out_event, 0, sizeof(*out_event));
    out_event->game_pid  = static_cast<uint32_t>(game->pid);
    out_event->mask      = static_cast<uint32_t>(changed_mask);
    /* HK-UNCERTAIN(exc-port-owner): no portable documented API resolves an
     * exception-port RECEIVE right to the owning task's pid across task
     * boundaries. Emit owner_pid=0 (unresolved); the server resolves the owner
     * by correlating with the ES GET_TASK source that acquired the game task. */
    out_event->owner_pid  = 0;
    /* is_foreign: a changed owner that is neither the game's own in-process
     * handler nor Apple diagnostics. We cannot resolve the owner pid here, so we
     * conservatively mark the changed-port event foreign=1 and let the server
     * clear it if the correlated owner turns out to be the game or an Apple
     * diagnostics service. */
    out_event->is_foreign = 1u;

    os_log(hk_log(),
        "HKExcPort: foreign exception-port change on game pid %d (mask 0x%x)",
        game->pid, static_cast<unsigned>(changed_mask));
    return true;
}
