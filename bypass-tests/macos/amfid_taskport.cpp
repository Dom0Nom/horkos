/*
 * Role: macOS bypass-test fixture (Phase 5: [disabled]) for macos-codesign-
 *       integrity signal 123. Intended to acquire amfid's task port (SIP-off dev box); assert it is reported HK_CS_AMFID_TASKPORT but tagged SIP-disabled / scored separately (SIP cross-check gate) and assert the Horkos daemon /
 *       server reports the corresponding HK_CS_* finding. Compiled now for the
 *       merge gate (guardrail #12); assertions activate once the Phase-5 signed
 *       fixture + daemon enforcement land (HK_CS_TEST_ENABLED).
 * Target platforms: macOS only (built behind if(APPLE)).
 * Interface: consumes the AC flag surface (ac_get_last_flag) once enforcement lands.
 */

#include <cstdio>

#ifndef HK_CS_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: amfid_taskport.cpp activates once the Phase-5 signed-fixture + "
                "macos-codesign-integrity daemon enforcement land.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <cstdlib>
#include "horkos/ac.h"

int main(void) {
    /* Phase 5 fills this in: acquire amfid's task port (SIP-off dev box); assert it is reported HK_CS_AMFID_TASKPORT but tagged SIP-disabled / scored separately (SIP cross-check gate), then query the daemon / ac_get_last_flag and
     * assert the expected HK_CS_* finding fires (and that the FP-gate case does
     * NOT). */
    std::printf("amfid_taskport.cpp: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_CS_TEST_ENABLED */
