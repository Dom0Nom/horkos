/*
 * bypass-tests/win/vm_write_codecave.cpp
 * Role: Merge-gate bypass test (guardrail #12) for signal 64 (external VM write into
 *       a code section, win-handle-memory-access). A Phase-5 test-signed fixture
 *       issues WriteProcessMemory into a +X (IMAGE_SCN_MEM_EXECUTE) section of the
 *       protected target; the AC must emit HK_EVENT_VM_ACCESS with HK_VM_WRITE +
 *       HK_VM_REMOTE and the resolved target_section_flags carrying IMAGE_SCN_MEM_
 *       EXECUTE (the section-flag classifier resolved the target VA). Ships DISABLED
 *       (HK_VMWATCH_TEST_ENABLED undefined): a compiled no-op, like byovd_load.cpp.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the VM-access surface. HK-TODO
 *       (schema): the wire types are kernel-private mirrors until the Schema phase.
 */

#include <cstdio>

#ifndef HK_VMWATCH_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: vm_write_codecave activates in Phase 5 (needs the PPL/ELAM "
                "ETW-TI VM consumer + the HK_EVENT_VM_ACCESS schema bump).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_EVENT_VM_ACCESS / HK_VM_WRITE / section-flag bits */

/* Phase-5: drain \\.\Horkos, count HK_EVENT_VM_ACCESS records that are a remote write
 * AND whose target_section_flags resolved an executable section. */
static int count_codecave_writes(void)
{
    return 0;
}

int main(void)
{
    if (count_codecave_writes() < 1) {
        std::printf("vm_write_codecave: expected remote write into +X section not "
                    "observed (section-flag bit unset?).\n");
        return 1;
    }
    std::printf("vm_write_codecave: passed.\n");
    return 0;
}

#endif /* HK_VMWATCH_TEST_ENABLED */
