/*
 * bypass-tests/win/infinity_hook_probe.cpp
 * Role: Merge-gate bypass test (guardrail #12) for signal 211 (infinity-hook
 *       perf-trace callback, win-kernel-syscall-etw-integrity). A Phase-5 fixture
 *       enables the perf-trace callback technique; the AC must emit
 *       HK_INTEGRITY_INFINITY_HOOK only when the WMI_LOGGER_CONTEXT struct layout
 *       is recognized, else HK_INTEGRITY_UNVERIFIABLE; xperf/WPR tracing alone must
 *       NOT fire (the session-census FP gate). Ships DISABLED
 *       (HK_INTEGRITY_TEST_ENABLED undefined): a compiled no-op returning 0, like
 *       byovd_load.cpp.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the integrity event surface
 *       (HK_INTEGRITY_INFINITY_HOOK / _UNVERIFIABLE). HK-TODO(schema): kernel-
 *       private mirrors until the Schema phase appends them.
 *       HK-UNCERTAIN(infinity-hook): the WMI_LOGGER_CONTEXT layout is undocumented;
 *       this activates only once the struct walk is validated.
 */

#include <cstdio>

#ifndef HK_INTEGRITY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: infinity_hook_probe activates in Phase 5 (needs the "
                "perf-trace-callback fixture, a validated WMI_LOGGER_CONTEXT "
                "layout, + HK_EVENT_INTEGRITY_FINDING schema bump).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_INTEGRITY_INFINITY_HOOK / _UNVERIFIABLE mirrors */

static int count_findings(uint32_t finding)
{
    (void)finding;
    return 0;
}

int main(void)
{
    /* Recognized layout => the hook fires; otherwise the sensor must report
     * UNVERIFIABLE rather than a false positive. Either is an acceptable pass for
     * the enabled fixture; a clean state (no finding at all on a recognized
     * layout) is the failure. */
    if (count_findings(HK_INTEGRITY_INFINITY_HOOK) < 1 &&
        count_findings(HK_INTEGRITY_UNVERIFIABLE) < 1) {
        std::printf("infinity_hook_probe: expected INFINITY_HOOK or UNVERIFIABLE "
                    "not observed.\n");
        return 1;
    }
    std::printf("infinity_hook_probe: passed.\n");
    return 0;
}

#endif /* HK_INTEGRITY_TEST_ENABLED */
