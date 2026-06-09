/*
 * bypass-tests/win/etw_session_disable.cpp
 * Role: Merge-gate bypass test (guardrail #12) for signal 215 (ETW logger-session
 *       census, win-kernel-syscall-etw-integrity). A Phase-5 fixture stops a
 *       Horkos-DEPENDENCY provider (NT Kernel Logger / ETW-TI); the AC must emit
 *       HK_INTEGRITY_ETW_SESSION_SUPPR. Stopping an UNRELATED profiling session
 *       (xperf/WPR) must NOT fire — the dependency-set FP gate. Ships DISABLED
 *       (HK_INTEGRITY_TEST_ENABLED undefined): a compiled no-op returning 0, like
 *       byovd_load.cpp.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the integrity event surface
 *       (HK_INTEGRITY_ETW_SESSION_SUPPR). HK-TODO(schema): kernel-private mirrors
 *       until the Schema phase appends them. HK-UNCERTAIN(etw-session-query): the
 *       sensor's kernel logger-table query is unconfirmed, so this activates only
 *       once that surface is wired.
 */

#include <cstdio>

#ifndef HK_INTEGRITY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: etw_session_disable activates in Phase 5 (needs the "
                "dependency-provider stop fixture, a confirmed kernel logger-table "
                "query, + HK_EVENT_INTEGRITY_FINDING schema bump).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_INTEGRITY_ETW_SESSION_SUPPR mirror */

static int count_findings(uint32_t finding)
{
    (void)finding;
    return 0;
}

int main(void)
{
    if (count_findings(HK_INTEGRITY_ETW_SESSION_SUPPR) < 1) {
        std::printf("etw_session_disable: expected ETW_SESSION_SUPPR not "
                    "observed for a dependency-provider stop.\n");
        return 1;
    }
    std::printf("etw_session_disable: passed.\n");
    return 0;
}

#endif /* HK_INTEGRITY_TEST_ENABLED */
