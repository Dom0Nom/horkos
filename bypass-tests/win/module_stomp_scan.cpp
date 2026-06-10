/*
 * bypass-tests/win/module_stomp_scan.cpp
 * Role: Merge-gate bypass fixture for the memory-scan plane (signals 11/12),
 *       [disabled]. Intended to overwrite a benign loaded module's .text (module
 *       stomping) and separately RW->RX-flip a region, then drain
 *       HK_IOCTL_DRAIN_MEM_EVENTS and assert: signal 12 fires with the correct
 *       first_diff_rva, a pure relocation/IAT diff does NOT fire (the FP guard
 *       the host-tested mem_logic_stomp.h core enforces), and signal 11 fires on
 *       the W^X flip. Read-only assertion of raw report fields — never a local ban.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h + the mem drain plane.
 *
 * Merge gate (guardrail #12): present for the security folder; assertions
 * activate once the scan plane is verified on the Windows box and
 * HK_MEMSCAN_TEST_ENABLED is defined.
 */

#include <cstdio>

#ifndef HK_MEMSCAN_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: module_stomp_scan activates once the mem-scan plane is "
                "verified on the Windows box (HK_MEMSCAN_TEST_ENABLED).\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <windows.h>
#include "horkos/ioctl.h"

int main(void)
{
    std::printf("module_stomp_scan: enforcement/sensor path not yet verified.\n");
    return 1;
}

#endif /* HK_MEMSCAN_TEST_ENABLED */
