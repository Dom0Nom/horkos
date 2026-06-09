/*
 * bypass-tests/macos/task_for_pid_control.cpp
 * Role: macOS bypass-test fixture (signals 109/110) [disabled until enforcement].
 *       When enabled: acquire the game's task CONTROL port from a foreign
 *       non-platform process and assert the daemon/server reports a
 *       hk_es_get_task CONTROL event; a NAME-port acquisition in the same test
 *       must produce NO flag (110's "must NOT be flagged"). Compiled now for the
 *       merge gate (guardrail #12); assertions activate once the ES GET_TASK
 *       sink + server scoring correlation path lands.
 * Target platforms: macOS only (built behind if(APPLE)).
 * Interface: consumes the AC flag surface (ac_get_last_flag) when enabled.
 */

#include <cstdio>

#ifndef HK_TASKPORT_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: task_for_pid_control activates once the macOS ES "
                "GET_TASK sink + server scoring lands.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <cstdlib>
#include "horkos/ac.h"

int main(void) {
    /* Phase 5 fills this in: from a foreign non-platform process, task_for_pid()
     * the game for a CONTROL port (expect a hk_es_get_task CONTROL flag), then
     * task_name_for_pid() (expect NO flag). */
    std::printf("task_for_pid_control: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_TASKPORT_TEST_ENABLED */
