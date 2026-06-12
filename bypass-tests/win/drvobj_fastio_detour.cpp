/*
 * Role: Merge-gate bypass test (guardrail #12) for signal 34 (DRIVER_OBJECT
 *       divergence audit, win-kernel-driver-integrity). A Phase-5 fixture detours
 *       a FastIoDispatch pointer OUT of its owning image: the AC must emit
 *       HK_INTEGRITY_DRVOBJ_DIVERGENCE. The FP-gate proof: a thunk that resolves
 *       into a legitimate signed module (fltmgr.sys) must NOT fire. Ships DISABLED
 *       (HK_INTEGRITY_TEST_ENABLED undefined): compiled no-op returning 0.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h + HK_INTEGRITY_DRVOBJ_DIVERGENCE.
 *       HK-TODO(schema): wire types are kernel-private mirrors until Schema lands.
 */

#include <cstdio>

#ifndef HK_INTEGRITY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: drvobj_fastio_detour activates in Phase 5 (needs the "
                "test-signed FastIo-detour fixture + schema bump).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_INTEGRITY_DRVOBJ_DIVERGENCE mirror */

static int count_findings(uint32_t finding) { (void)finding; return 0; }

int main(void)
{
    int failures = 0;
    /* Case A: detour a FastIoDispatch pointer out of its image -> must fire. */
    if (count_findings(HK_INTEGRITY_DRVOBJ_DIVERGENCE) < 1) {
        std::printf("drvobj_fastio_detour: out-of-image detour not detected.\n");
        failures++;
    }
    /* Case B (FP gate): an fltmgr.sys-resident thunk must NOT fire. The Phase-5
     * fixture leaves a known-good signed thunk in place and we assert ZERO extra
     * findings beyond Case A. */
    /* failures += assert_no_false_positive_on_signed_thunk(); */
    if (failures != 0) {
        std::printf("drvobj_fastio_detour: %d sub-case(s) failed.\n", failures);
        return 1;
    }
    std::printf("drvobj_fastio_detour: passed.\n");
    return 0;
}

#endif /* HK_INTEGRITY_TEST_ENABLED */
