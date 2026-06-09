/*
 * bypass-tests/win/kdbg_attach.cpp
 * Role: Merge-gate bypass test (guardrail #12) for signal 33 (kernel-debugger
 *       attach-state probe, win-kernel-driver-integrity). An ATTACHED debugger
 *       must yield HK_INTEGRITY_KDBG_ATTACHED (high weight) while a
 *       boot-debug-ALLOWED-but-detached config yields only
 *       HK_INTEGRITY_KDBG_BOOT_ALLOWED (low weight) — proving the weight split.
 *       Ships DISABLED (HK_INTEGRITY_TEST_ENABLED undefined): no-op returning 0.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h + HK_INTEGRITY_KDBG_*.
 *       HK-TODO(schema): wire types are kernel-private mirrors until Schema lands.
 */

#include <cstdio>

#ifndef HK_INTEGRITY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: kdbg_attach activates in Phase 5 (needs the VM "
                "kd-attach/detach harness + schema bump).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_INTEGRITY_KDBG_ATTACHED / _BOOT_ALLOWED mirrors */

static int count_findings(uint32_t finding) { (void)finding; return 0; }

int main(void)
{
    int failures = 0;
    /* Attached: high-weight finding fires. */
    if (count_findings(HK_INTEGRITY_KDBG_ATTACHED) < 1) {
        std::printf("kdbg_attach: ATTACHED not reported.\n");
        failures++;
    }
    /* Boot-allowed but detached: only the low-weight finding, never ATTACHED. */
    /* failures += assert_boot_allowed_low_weight_only(); */
    if (failures != 0) {
        std::printf("kdbg_attach: %d sub-case(s) failed.\n", failures);
        return 1;
    }
    std::printf("kdbg_attach: passed.\n");
    return 0;
}

#endif /* HK_INTEGRITY_TEST_ENABLED */
