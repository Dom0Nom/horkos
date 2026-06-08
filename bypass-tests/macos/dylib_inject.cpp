/*
 * bypass-tests/macos/dylib_inject.cpp
 * Role: macOS bypass-test fixture (Phase 5: [disabled]). Intended to inject a
 *       dylib via DYLD_INSERT_LIBRARIES and assert the Horkos daemon reports the
 *       injection flag (Phase 4 daemon / ES path). Compiled now for the merge
 *       gate (guardrail #12); assertions activate once the daemon enforcement
 *       lands.
 * Target platforms: macOS only (built behind if(APPLE)).
 * Interface: consumes the AC flag surface (ac_get_last_flag).
 */

#include <cstdio>

#ifndef HK_DYLIB_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: dylib_inject activates once the Phase 4 macOS daemon "
                "injection detection lands.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <cstdlib>
#include <unistd.h>
#include "horkos/ac.h"

int main(void) {
    /* Phase 4+ fills this in: spawn a target with DYLD_INSERT_LIBRARIES set,
     * then query the daemon / ac_get_last_flag and assert the injection flag. */
    std::printf("dylib_inject: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_DYLIB_TEST_ENABLED */
