/*
 * bypass-tests/win/callback_strip_sentinel.cpp
 * Role: Merge-gate bypass test (guardrail #12) for signal 31 (callback residency,
 *       self-sentinel half, win-kernel-driver-integrity). A Phase-5 fixture strips
 *       Horkos's own sentinel callback (its Ob registration handle / a Ps* notify
 *       slot); the self-sentinel half must detect the missing slot and emit
 *       HK_INTEGRITY_CALLBACK_NO_IMAGE. The full undocumented OS-array walk is OUT
 *       of scope (plan Risk 1), so this test proves ONLY the documented sentinel.
 *       Ships DISABLED (HK_INTEGRITY_TEST_ENABLED undefined): no-op returning 0.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h + HK_INTEGRITY_CALLBACK_NO_IMAGE.
 *       HK-TODO(schema): wire types are kernel-private mirrors until Schema lands.
 */

#include <cstdio>

#ifndef HK_INTEGRITY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: callback_strip_sentinel activates in Phase 5 (needs "
                "the callback-strip fixture + schema bump).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_INTEGRITY_CALLBACK_NO_IMAGE mirror */

static int count_findings(uint32_t finding) { (void)finding; return 0; }

int main(void)
{
    /* The fixture strips our sentinel; the residency self-check must notice the
     * missing slot and emit. (Full OS-array enumeration is intentionally NOT
     * exercised — it ships OFF per plan Risk 1.) */
    if (count_findings(HK_INTEGRITY_CALLBACK_NO_IMAGE) < 1) {
        std::printf("callback_strip_sentinel: stripped sentinel not detected.\n");
        return 1;
    }
    std::printf("callback_strip_sentinel: passed.\n");
    return 0;
}

#endif /* HK_INTEGRITY_TEST_ENABLED */
