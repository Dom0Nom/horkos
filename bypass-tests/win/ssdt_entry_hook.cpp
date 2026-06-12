/*
 * Role: Merge-gate bypass test (guardrail #12) for signal 208 (native SSDT entry
 *       bounds, win-kernel-syscall-etw-integrity). A Phase-5 test-signed fixture
 *       repoints one KiServiceTable entry OUTSIDE ntoskrnl; the AC must emit
 *       HK_INTEGRITY_SSDT_ENTRY_OOI. A clean table must NOT fire, and an
 *       unknown-build fixture (out-of-band ServiceLimit) must yield
 *       HK_INTEGRITY_UNVERIFIABLE, not a false positive. Ships DISABLED
 *       (HK_INTEGRITY_TEST_ENABLED undefined): a compiled no-op returning 0, like
 *       byovd_load.cpp. The repo never commits an SSDT-hooking driver.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the integrity event surface
 *       (HK_EVENT_INTEGRITY_FINDING / HK_INTEGRITY_SSDT_ENTRY_OOI / _UNVERIFIABLE).
 *       HK-TODO(schema): those wire types are kernel-private mirrors until the
 *       Schema phase appends them to event_schema.h.
 */

#include <cstdio>

#ifndef HK_INTEGRITY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: ssdt_entry_hook activates in Phase 5 (needs the "
                "test-signed KiServiceTable-detour fixture + "
                "HK_EVENT_INTEGRITY_FINDING schema bump).\n");
    return 0; /* Disabled tests pass so the gate stays green pre-enforcement. */
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_INTEGRITY_SSDT_ENTRY_OOI / _UNVERIFIABLE mirrors */

/* Phase-5: drain \\.\Horkos, count HK_EVENT_INTEGRITY_FINDING records whose
 * payload.finding == finding (after triggering HK_IOCTL_INTEGRITY_RESCAN). */
static int count_findings(uint32_t finding)
{
    (void)finding;
    return 0;
}

int main(void)
{
    /* Hooked entry => SSDT_ENTRY_OOI must fire. */
    if (count_findings(HK_INTEGRITY_SSDT_ENTRY_OOI) < 1) {
        std::printf("ssdt_entry_hook: expected SSDT_ENTRY_OOI not observed.\n");
        return 1;
    }
    std::printf("ssdt_entry_hook: passed.\n");
    return 0;
}

#endif /* HK_INTEGRITY_TEST_ENABLED */
