/*
 * bypass-tests/win/vm_read_external.cpp
 * Role: Merge-gate bypass test (guardrail #12) for signal 64 (external VM read,
 *       win-handle-memory-access). A Phase-5 test-signed fixture issues
 *       ReadProcessMemory against the protected target; the AC must emit an
 *       HK_EVENT_VM_ACCESS record with the ReadVm (HK_VM_READ) + HK_VM_REMOTE bits.
 *       Ships DISABLED (HK_VMWATCH_TEST_ENABLED undefined): a compiled no-op that
 *       returns 0, exactly like byovd_load.cpp. The repo never commits an external
 *       memory-reader; activation needs the ETW-TI VM consumer (PPL/ELAM) and the
 *       HK_EVENT_VM_ACCESS schema bump, neither of which exists pre-Schema.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the VM-access event surface
 *       (HK_EVENT_VM_ACCESS / HK_VM_READ / HK_VM_REMOTE). HK-TODO(schema): those wire
 *       types are kernel-private mirrors until the Schema phase appends them.
 */

#include <cstdio>

#ifndef HK_VMWATCH_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: vm_read_external activates in Phase 5 (needs the PPL/ELAM "
                "ETW-TI VM consumer + the HK_EVENT_VM_ACCESS schema bump).\n");
    return 0; /* Disabled tests pass so the gate stays green pre-enforcement. */
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_EVENT_VM_ACCESS / HK_VM_READ / HK_VM_REMOTE mirrors */

/* Phase-5: drain \\.\Horkos, count HK_EVENT_VM_ACCESS records whose access_kind has
 * HK_VM_READ and whose flags have HK_VM_REMOTE, against the protected pid. */
static int count_remote_reads(void)
{
    return 0;
}

int main(void)
{
    /* External ReadProcessMemory => a remote ReadVm must be observed. */
    if (count_remote_reads() < 1) {
        std::printf("vm_read_external: expected remote ReadVm not observed.\n");
        return 1;
    }
    std::printf("vm_read_external: passed.\n");
    return 0;
}

#endif /* HK_VMWATCH_TEST_ENABLED */
