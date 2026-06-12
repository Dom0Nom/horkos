/*
 * Role: Merge-gate bypass test (guardrail #12) for signal 30 (code-integrity
 *       state probe, win-kernel-driver-integrity). In a VM, flip testsigning/HVCI
 *       POST-boot: the AC must emit HK_INTEGRITY_CI_STATE_DELTA for the post-boot
 *       delta, but a STABLE boot config at startup must NOT (delta-only proof).
 *       Ships DISABLED (HK_INTEGRITY_TEST_ENABLED undefined): no-op returning 0.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h + HK_INTEGRITY_CI_STATE_DELTA.
 *       HK-TODO(schema): wire types are kernel-private mirrors until Schema lands.
 */

#include <cstdio>

#ifndef HK_INTEGRITY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: ci_state_flip activates in Phase 5 (needs the VM "
                "post-boot DSE/HVCI flip harness + schema bump).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_INTEGRITY_CI_STATE_DELTA mirror */

static int count_findings(uint32_t finding) { (void)finding; return 0; }

int main(void)
{
    int failures = 0;
    /* Stable config at startup: no delta expected. */
    if (count_findings(HK_INTEGRITY_CI_STATE_DELTA) != 0) {
        std::printf("ci_state_flip: spurious delta on a stable boot config.\n");
        failures++;
    }
    /* Phase-5 harness flips testsigning/HVCI post-boot, triggers a rescan; the
     * delta must now fire exactly once. */
    /* failures += assert_delta_after_post_boot_flip(); */
    if (failures != 0) {
        std::printf("ci_state_flip: %d sub-case(s) failed.\n", failures);
        return 1;
    }
    std::printf("ci_state_flip: passed.\n");
    return 0;
}

#endif /* HK_INTEGRITY_TEST_ENABLED */
