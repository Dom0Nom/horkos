/*
 * Role: Merge-gate bypass test (guardrail #12) for signal 72 (alloc->protect->write
 *       staging, win-handle-memory-access). A Phase-5 fixture performs the ordered
 *       remote triad — VirtualAllocEx, VirtualProtectEx(->+X), WriteProcessMemory —
 *       against the protected target inside one window. The AC's staging assembler
 *       must collapse that to exactly ONE HK_EVENT_VM_ACCESS with HK_VM_STAGING_SEQ
 *       set (and NOT three separate staging events). Ships DISABLED
 *       (HK_VMWATCH_TEST_ENABLED undefined): a compiled no-op, like byovd_load.cpp.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the VM-access surface
 *       (HK_EVENT_VM_ACCESS / HK_VM_STAGING_SEQ). HK-TODO(schema): the wire type is a
 *       kernel-private mirror until the Schema phase appends it. The assembler logic
 *       itself is host-tested in tests/unit/test_vm_access_logic.cpp.
 */

#include <cstdio>

#ifndef HK_VMWATCH_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: staging_sequence activates in Phase 5 (needs the PPL/ELAM "
                "ETW-TI VM consumer driving the staging assembler + the "
                "HK_EVENT_VM_ACCESS schema bump).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_EVENT_VM_ACCESS / HK_VM_STAGING_SEQ mirrors */

/* Phase-5: drain \\.\Horkos, count HK_EVENT_VM_ACCESS records whose flags carry
 * HK_VM_STAGING_SEQ. The ordered triad must collapse to EXACTLY one. */
static int count_staging_events(void)
{
    return 0;
}

int main(void)
{
    const int n = count_staging_events();
    if (n != 1) {
        std::printf("staging_sequence: expected exactly one staging event, got %d.\n", n);
        return 1;
    }
    std::printf("staging_sequence: passed.\n");
    return 0;
}

#endif /* HK_VMWATCH_TEST_ENABLED */
