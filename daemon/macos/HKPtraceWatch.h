/*
 * Role: Interface for the P_TRACED transition-edge watcher (signal 116).
 *       Declares HKPtracePoll() and the watcher state holding the last-seen
 *       traced flag so only the untraced->traced edge is reported.
 * Target platform: macOS only (CMake `if(APPLE)` gates the TU).
 * Interface: daemon-only.
 */

#pragma once

#include "horkos/event_schema_macos.h"  /* hk_es_ptrace */

#include <sys/types.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Per-game watcher state. `have_baseline`/`last_traced` give the edge detector
 * its previous sample so steady-state traced is not re-reported every poll. */
typedef struct HKPtraceWatchState {
    pid_t pid;
    bool  have_baseline;
    bool  last_traced;
} HKPtraceWatchState;

/*
 * HKPtracePoll — sample P_TRACED for `state->pid` once.
 *
 * On a 0->1 transition (untraced -> traced) fills `*out_event` and returns true
 * (an edge to emit). Otherwise returns false and leaves `*out_event` untouched.
 *
 * `release_signed` is the build-channel gate: the caller passes 1 only when the
 * game binary is release-signed with no get-task-allow; the field is forwarded
 * to the event so the server applies the channel gate. Self-attach by the game's
 * own crash handler does not set P_TRACED, so it is not reported.
 */
bool HKPtracePoll(HKPtraceWatchState *state,
                  bool                release_signed,
                  hk_es_ptrace       *out_event);

#ifdef __cplusplus
}  /* extern "C" */
#endif
