/*
 * daemon/macos/HKExceptionPortBaseline.h
 * Role: Interface for the exception-port poller (signal 113). Declares the
 *       launch-time baseline handle and HKExcPortPoll(), which diffs the game
 *       task's current exception-port set against the baseline and flags a
 *       foreign owner.
 * Target platform: macOS only (CMake `if(APPLE)` gates the TU).
 * Interface: declares the poll entrypoint + baseline handle; daemon TUs only.
 */

#pragma once

#include "HKGameTaskHandle.h"
#include "horkos/event_schema_macos.h"  /* hk_es_exc_port */

#include <mach/mach.h>     /* exception_mask_t, EXC_TYPES_COUNT */
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Snapshot of the game task's exception ports. task_get_exception_ports returns
 * up to EXC_TYPES_COUNT parallel arrays; we keep the masks + the port names so a
 * later poll can detect a newly-installed (changed) port. */
typedef struct HKExcPortBaseline {
    bool                  captured;
    mach_msg_type_number_t count;
    exception_mask_t      masks[EXC_TYPES_COUNT];
    mach_port_t           ports[EXC_TYPES_COUNT];
} HKExcPortBaseline;

/*
 * HKExcPortCaptureBaseline — capture the launch-time exception-port set.
 * No-op (returns KERN_NOT_SUPPORTED) on an invalid game-task handle.
 */
kern_return_t HKExcPortCaptureBaseline(const HKGameTaskHandle *game,
                                       HKExcPortBaseline      *out_baseline);

/*
 * HKExcPortPoll — re-poll and diff against `baseline`. On detecting a changed /
 * newly foreign owner, fills `*out_event` (is_foreign per the diff) and returns
 * true. Returns false when nothing changed or the handle is invalid.
 */
bool HKExcPortPoll(const HKGameTaskHandle  *game,
                   const HKExcPortBaseline *baseline,
                   hk_es_exc_port          *out_event);

#ifdef __cplusplus
}  /* extern "C" */
#endif
