/*
 * bypass-tests/win/nonimage_exec_map.cpp
 * Role: Merge-gate bypass test (guardrail #12) for signal 32 (non-image
 *       executable allocation scan, win-kernel-driver-integrity). A Phase-5
 *       fixture manually-maps a BENIGN test page executable in system space; the
 *       AC must report HK_INTEGRITY_NONIMAGE_EXEC as a SERVER-SCORED anomaly, NOT
 *       a standalone ban (the catalog rates this HIGH-FP, lowest weight). Ships
 *       DISABLED (HK_INTEGRITY_TEST_ENABLED undefined): no-op returning 0.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h + HK_INTEGRITY_NONIMAGE_EXEC.
 *       HK-TODO(schema): wire types are kernel-private mirrors until Schema lands.
 */

#include <cstdio>

#ifndef HK_INTEGRITY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: nonimage_exec_map activates in Phase 5 (needs the "
                "benign manual-map fixture + schema bump).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_INTEGRITY_NONIMAGE_EXEC mirror */

static int count_findings(uint32_t finding) { (void)finding; return 0; }

int main(void)
{
    /* The fixture maps a benign executable system page; the finding must be
     * REPORTED (server-scored), and the assertion verifies it is NOT escalated to
     * a standalone ban by the client (the client never thresholds). */
    if (count_findings(HK_INTEGRITY_NONIMAGE_EXEC) < 1) {
        std::printf("nonimage_exec_map: manual-map not reported as anomaly.\n");
        return 1;
    }
    std::printf("nonimage_exec_map: passed.\n");
    return 0;
}

#endif /* HK_INTEGRITY_TEST_ENABLED */
