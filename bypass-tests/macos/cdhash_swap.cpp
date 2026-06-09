/*
 * bypass-tests/macos/cdhash_swap.cpp
 * Role: macOS bypass-test fixture (Phase 5: [disabled]) for macos-codesign-
 *       integrity signal 119. Intended to ad-hoc re-sign a patched executable at the same path; assert HK_CS_CDHASH_MISMATCH fires while an app-translocated clean bundle does NOT (FP-gate proof) and assert the Horkos daemon /
 *       server reports the corresponding HK_CS_* finding. Compiled now for the
 *       merge gate (guardrail #12); assertions activate once the Phase-5 signed
 *       fixture + daemon enforcement land (HK_CS_TEST_ENABLED).
 * Target platforms: macOS only (built behind if(APPLE)).
 * Interface: consumes the AC flag surface (ac_get_last_flag) once enforcement lands.
 */

#include <cstdio>

#ifndef HK_CS_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: cdhash_swap.cpp activates once the Phase-5 signed-fixture + "
                "macos-codesign-integrity daemon enforcement land.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <cstdlib>
#include "horkos/ac.h"

int main(void) {
    /* Phase 5 fills this in: ad-hoc re-sign a patched executable at the same path; assert HK_CS_CDHASH_MISMATCH fires while an app-translocated clean bundle does NOT (FP-gate proof), then query the daemon / ac_get_last_flag and
     * assert the expected HK_CS_* finding fires (and that the FP-gate case does
     * NOT). */
    std::printf("cdhash_swap.cpp: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_CS_TEST_ENABLED */
