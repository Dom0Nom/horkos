/*
 * bypass-tests/macos/ptrace_attach.cpp
 * Role: macOS bypass-test fixture (signal 116) [disabled until enforcement].
 *       When enabled: ptrace(PT_ATTACHEXC) against a release-signed game and
 *       assert a hk_es_ptrace transition edge with the tracer pid; a dev /
 *       get-task-allow build must produce NO flag. Compiled now for the merge
 *       gate (guardrail #12).
 * Target platforms: macOS only (built behind if(APPLE)).
 * Interface: consumes the AC flag surface (ac_get_last_flag) when enabled.
 */

#include <cstdio>

#ifndef HK_PTRACE_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: ptrace_attach activates once the macOS daemon "
                "P_TRACED watcher + server release-channel gate lands.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <cstdlib>
#include "horkos/ac.h"

int main(void) {
    /* Phase 5: ptrace(PT_ATTACHEXC) a release-signed game; expect a hk_es_ptrace
     * traced edge with tracer pid. A get-task-allow dev build: no flag. */
    std::printf("ptrace_attach: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_PTRACE_TEST_ENABLED */
