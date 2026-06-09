/*
 * bypass-tests/win/shadow_ssdt_hook.cpp
 * Role: Merge-gate bypass test (guardrail #12) for signal 209 (shadow SSDT /
 *       W32pServiceTable bounds, win-kernel-syscall-etw-integrity). A Phase-5
 *       test-signed fixture hooks a W32pServiceTable entry; the AC must emit
 *       HK_INTEGRITY_SHADOW_SSDT_OOI. Gated on the shadow-table resolution and the
 *       KeStackAttachProcess pairing being agreed (the highest-risk sensor in this
 *       domain). Ships DISABLED (HK_INTEGRITY_TEST_ENABLED undefined): a compiled
 *       no-op returning 0, like byovd_load.cpp. The repo never commits a
 *       table-hooking driver.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the integrity event surface
 *       (HK_INTEGRITY_SHADOW_SSDT_OOI). HK-TODO(schema): kernel-private mirrors
 *       until the Schema phase appends them. HK-UNCERTAIN(shadow-ssdt): the sensor
 *       itself is default-OFF/UNVERIFIABLE until the unexported shadow-table
 *       location + attach pairing are reviewed on-box.
 */

#include <cstdio>

#ifndef HK_INTEGRITY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: shadow_ssdt_hook activates in Phase 5 (needs the "
                "test-signed W32pServiceTable-hook fixture, the agreed shadow-table "
                "resolution, + HK_EVENT_INTEGRITY_FINDING schema bump).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_INTEGRITY_SHADOW_SSDT_OOI mirror */

static int count_findings(uint32_t finding)
{
    (void)finding;
    return 0;
}

int main(void)
{
    if (count_findings(HK_INTEGRITY_SHADOW_SSDT_OOI) < 1) {
        std::printf("shadow_ssdt_hook: expected SHADOW_SSDT_OOI not observed.\n");
        return 1;
    }
    std::printf("shadow_ssdt_hook: passed.\n");
    return 0;
}

#endif /* HK_INTEGRITY_TEST_ENABLED */
