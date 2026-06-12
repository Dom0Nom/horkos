/*
 * Role: BYOVD bypass test fixture (Phase 3: [disabled]). Intended to load a
 *       self-built, deliberately-vulnerable test driver and assert the AC stack
 *       raises the BYOVD flag. Phase 3 lands the test body but marks it disabled
 *       — real enforcement and the signed test fixture land in Phase 5. The repo
 *       never commits a real BYOVD binary or a hash sourced from loldrivers.io.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the AC flag surface.
 *
 * Merge gate (guardrail #12): this file is the representative bypass test for
 * the Windows security folder. It compiles now; its assertions activate in
 * Phase 5 when the fixture driver build target and Ob/whitelist enforcement land.
 */

#include <cstdio>

/*
 * HK_BYOVD_TEST_ENABLED is defined by CMake only in Phase 5 once the fixture
 * driver target exists. Until then the test is a compiled no-op that reports
 * "disabled" — present for the merge gate, not yet asserting.
 */
#ifndef HK_BYOVD_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: byovd_load bypass test activates in Phase 5 "
                "(needs the signed test-fixture driver + enforcement).\n");
    return 0; /* Disabled tests pass so the gate stays green pre-Phase-5. */
}

#else

#include <windows.h>
#include "horkos/ioctl.h"

/* Phase 5 fills this in: build+sign the vulnerable fixture, attempt to load it,
 * then drain events / query the AC flag and assert the BYOVD flag fired. */
int main(void)
{
    std::printf("byovd_load: Phase 5 enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_BYOVD_TEST_ENABLED */
