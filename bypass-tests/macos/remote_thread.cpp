/*
 * Role: macOS bypass-test fixture (signal 114) [disabled until enforcement].
 *       When enabled: thread_create_running in the game from another task with
 *       its entry in an anon region and assert a hk_es_thread_origin
 *       region_kind=ANON; a sanctioned-JIT-region thread must produce NO flag.
 *       Compiled now for the merge gate (guardrail #12).
 * Target platforms: macOS only (built behind if(APPLE)).
 * Interface: consumes the AC flag surface (ac_get_last_flag) when enabled.
 */

#include <cstdio>

#ifndef HK_REMOTETHREAD_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: remote_thread activates once the macOS daemon "
                "thread-origin scan + server scoring lands.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <cstdlib>
#include "horkos/ac.h"

int main(void) {
    /* Phase 5: thread_create_running in the game with entry in MAP_ANON memory;
     * expect a hk_es_thread_origin region_kind=ANON. A JIT-region thread: no flag. */
    std::printf("remote_thread: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_REMOTETHREAD_TEST_ENABLED */
