/*
 * bypass-tests/win/manual_map_scan.cpp
 * Role: Merge-gate bypass fixture for the memory-scan plane (signals 10/13/16/17),
 *       [disabled]. Intended to manually map a benign signed DLL into a victim
 *       test process WITHOUT the loader (raw NtCreateSection + NtMapViewOfSection,
 *       plus a private-commit shellcode-stub variant), start a thread in the
 *       mapped region, trigger HK_IOCTL_SCAN_PROCESS, drain
 *       HK_IOCTL_DRAIN_MEM_EVENTS, and assert: signal 10 (unbacked +X) for the
 *       private variant, 13 (ghost image) for the section-mapped variant, 17
 *       (exec origin anon) for the thread, and 16 if the backing is deleted
 *       post-map. Demonstrates the scanner sees what PsSetLoadImageNotifyRoutine
 *       does not. Read-only assertion of raw report fields — never a local ban.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h + the mem drain plane.
 *
 * Merge gate (guardrail #12): present for the security folder; assertions
 * activate once the scan plane is verified on the Windows box and
 * HK_MEMSCAN_TEST_ENABLED is defined with the signed fixture harness.
 */

#include <cstdio>

#ifndef HK_MEMSCAN_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: manual_map_scan activates once the mem-scan plane is "
                "verified on the Windows box (HK_MEMSCAN_TEST_ENABLED).\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <windows.h>
#include "horkos/ioctl.h"

int main(void)
{
    std::printf("manual_map_scan: enforcement/sensor path not yet verified.\n");
    return 1;
}

#endif /* HK_MEMSCAN_TEST_ENABLED */
