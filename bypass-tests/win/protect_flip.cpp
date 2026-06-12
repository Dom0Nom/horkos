/*
 * Role: Merge-gate bypass test (guardrail #12) for signal 71 (page-protection drift,
 *       win-handle-memory-access). A Phase-5 fixture issues VirtualProtectEx RX->RWX
 *       on a shipped (+X) section of the protected target. The AC's page-protect
 *       audit must emit HK_EVENT_PROTECT_DRIFT with HK_PROT_WX_ON_SHIPPED, and — when
 *       a coinciding foreign ProtectVm is seen on the kernel plane — HK_PROT_FOREIGN_
 *       INITIATED. Ships DISABLED (HK_VMWATCH_TEST_ENABLED undefined): a compiled
 *       no-op, like byovd_load.cpp.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the protect-drift surface
 *       (HK_EVENT_PROTECT_DRIFT / HK_PROT_WX_ON_SHIPPED / HK_PROT_FOREIGN_INITIATED).
 *       HK-TODO(schema): the 20-byte payload exceeds the frozen envelope; the type is
 *       a kernel-private mirror until the Schema phase appends it.
 */

#include <cstdio>

#ifndef HK_VMWATCH_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: protect_flip activates in Phase 5 (needs the page-protect "
                "audit report path + the HK_EVENT_PROTECT_DRIFT schema bump).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_EVENT_PROTECT_DRIFT / HK_PROT_FOREIGN_INITIATED mirrors */

/* Phase-5: drain the SDK report queue + \\.\Horkos and count HK_EVENT_PROTECT_DRIFT
 * records whose flags carry HK_PROT_FOREIGN_INITIATED (the foreign VirtualProtectEx). */
static int count_foreign_protect_flips(void)
{
    return 0;
}

int main(void)
{
    if (count_foreign_protect_flips() < 1) {
        std::printf("protect_flip: expected HK_PROT_FOREIGN_INITIATED drift not "
                    "observed.\n");
        return 1;
    }
    std::printf("protect_flip: passed.\n");
    return 0;
}

#endif /* HK_VMWATCH_TEST_ENABLED */
