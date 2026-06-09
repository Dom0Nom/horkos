/*
 * daemon/macos/HKGameTaskHandle.h
 * Role: Interface for the validated game-task handle. Centralises the single
 *       privileged task_for_pid-equivalent path and its audit-token validation
 *       so the pollers (113/114/117) share one reviewed acquisition routine.
 * Target platform: macOS only (the implementing TU is gated by `if(APPLE)`).
 * Interface: declares HKGameTaskGet()/HKGameTaskRelease(); included only by the
 *            macOS daemon TUs (HKExceptionPortBaseline / HKThreadIntegrity /
 *            HKTextIntegrity). No platform #ifdef — CMake gates the TU.
 */

#pragma once

#include <mach/mach.h>   /* task_t, mach_port_t, kern_return_t */
#include <sys/types.h>   /* pid_t */
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque, validated handle to the game task. Held by the daemon for the life of
 * a game session; refreshed on restart. The `valid` flag lets pollers no-op
 * cleanly on a stock (non-entitled / SIP-on) system where acquisition fails. */
typedef struct HKGameTaskHandle {
    pid_t      pid;          /* the validated game pid */
    task_t     task;         /* MACH_PORT_NULL if acquisition failed */
    bool       valid;        /* true only after audit-token validation passed */
} HKGameTaskHandle;

/*
 * HKGameTaskGet — resolve and audit-token-validate a privileged handle to the
 * game task identified by `pid`. On success fills `*out` (valid=true). On any
 * failure (no entitlement, SIP, pid mismatch, validation fail) returns the
 * underlying kern_return_t and leaves `out->valid=false, out->task=MACH_PORT_NULL`
 * so callers degrade to a no-op rather than acting on an unvalidated port.
 *
 * The returned task port is owned by the handle; release with HKGameTaskRelease.
 */
kern_return_t HKGameTaskGet(pid_t pid, HKGameTaskHandle *out);

/* HKGameTaskRelease — drop the task-port reference. Safe to call on an invalid
 * handle (no-op). Idempotent. */
void HKGameTaskRelease(HKGameTaskHandle *handle);

#ifdef __cplusplus
}  /* extern "C" */
#endif
