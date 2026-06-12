/*
 * Role: Merge-gate bypass test (guardrail #12) for signal 35 (SSDT range
 *       integrity, win-kernel-driver-integrity). With a Phase-5 self-built,
 *       test-signed fixture that points a KiServiceTable entry OUTSIDE ntoskrnl,
 *       the AC must emit HK_INTEGRITY_SSDT_OUT_OF_IMAGE. Ships DISABLED
 *       (HK_INTEGRITY_TEST_ENABLED undefined): compiled no-op returning 0, exactly
 *       like byovd_load.cpp. Activates when the Phase-5 signed-fixture driver that
 *       can detour an SSDT entry exists. The repo never commits a table-hooking
 *       driver.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the integrity event surface
 *       (HK_EVENT_INTEGRITY_FINDING / HK_INTEGRITY_SSDT_OUT_OF_IMAGE).
 *       HK-TODO(schema): those wire types are kernel-private mirrors until the
 *       Schema phase appends them to event_schema.h; the enabled body references
 *       them through the kernel header placeholders.
 */

#include <cstdio>

#ifndef HK_INTEGRITY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: ssdt_hook_detect activates in Phase 5 (needs the "
                "test-signed SSDT-detour fixture + HK_EVENT_INTEGRITY_FINDING "
                "schema bump).\n");
    return 0; /* Disabled tests pass so the gate stays green pre-enforcement. */
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_INTEGRITY_SSDT_OUT_OF_IMAGE mirror */

/* Phase-5: drain \\.\Horkos, count HK_EVENT_INTEGRITY_FINDING records whose
 * payload.finding == finding. */
static int count_findings(uint32_t finding)
{
    (void)finding;
    return 0;
}

int main(void)
{
    /* Fixture (Phase 5) detours one KiServiceTable entry out of ntoskrnl, then we
     * trigger HK_IOCTL_INTEGRITY_RESCAN and assert the finding fires. */
    if (count_findings(HK_INTEGRITY_SSDT_OUT_OF_IMAGE) < 1) {
        std::printf("ssdt_hook_detect: expected SSDT_OUT_OF_IMAGE not observed.\n");
        return 1;
    }
    std::printf("ssdt_hook_detect: passed.\n");
    return 0;
}

#endif /* HK_INTEGRITY_TEST_ENABLED */
