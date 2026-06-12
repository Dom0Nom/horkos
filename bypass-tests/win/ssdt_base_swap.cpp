/*
 * Role: Merge-gate bypass test (guardrail #12) for signal 216 (SSDT descriptor
 *       base-swap, win-kernel-syscall-etw-integrity). A Phase-5 test-signed fixture
 *       redirects KeServiceDescriptorTable.Base to a CLONED, pre-hooked SSDT while
 *       leaving the original entries pristine; the AC must emit
 *       HK_INTEGRITY_SSDT_BASE_SWAP — proving 216 catches the clone-table swap that
 *       per-entry signal 208 alone would miss (the clone's entries pass per-entry
 *       checks but the base moved). Ships DISABLED (HK_INTEGRITY_TEST_ENABLED
 *       undefined): a compiled no-op returning 0, like byovd_load.cpp.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the integrity event surface
 *       (HK_EVENT_INTEGRITY_FINDING / HK_INTEGRITY_SSDT_BASE_SWAP). HK-TODO(schema):
 *       kernel-private mirrors until the Schema phase appends them.
 */

#include <cstdio>

#ifndef HK_INTEGRITY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: ssdt_base_swap activates in Phase 5 (needs the "
                "test-signed clone-table fixture + HK_EVENT_INTEGRITY_FINDING "
                "schema bump).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_INTEGRITY_SSDT_BASE_SWAP mirror */

static int count_findings(uint32_t finding)
{
    (void)finding;
    return 0;
}

int main(void)
{
    if (count_findings(HK_INTEGRITY_SSDT_BASE_SWAP) < 1) {
        std::printf("ssdt_base_swap: expected SSDT_BASE_SWAP not observed "
                    "(216 must catch what 208 misses).\n");
        return 1;
    }
    std::printf("ssdt_base_swap: passed.\n");
    return 0;
}

#endif /* HK_INTEGRITY_TEST_ENABLED */
