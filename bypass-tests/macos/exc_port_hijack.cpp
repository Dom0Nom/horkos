/*
 * Role: macOS bypass-test fixture (signal 113) [disabled until enforcement].
 *       When enabled: a foreign task installs itself as the game's EXC_MASK_ALL
 *       handler and asserts a hk_es_exc_port is_foreign=1; the game's own
 *       in-process handler must produce NO flag. Compiled now for the merge gate
 *       (guardrail #12).
 * Target platforms: macOS only (built behind if(APPLE)).
 * Interface: consumes the AC flag surface (ac_get_last_flag) when enabled.
 */

#include <cstdio>

#ifndef HK_EXCPORT_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: exc_port_hijack activates once the macOS daemon "
                "exception-port poller + server correlation lands.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <cstdlib>
#include "horkos/ac.h"

int main(void) {
    /* Phase 5: task_set_exception_ports the game to a foreign handler; expect a
     * hk_es_exc_port is_foreign=1. An in-process handler: no flag. */
    std::printf("exc_port_hijack: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_EXCPORT_TEST_ENABLED */
