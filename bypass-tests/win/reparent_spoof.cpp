/*
 * Role: Merge-gate bypass fixture for process-genealogy (signals 199/201),
 *       [disabled]. Intended to spawn a child via CreateProcess with
 *       UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) forging a
 *       launcher PID as the parent, then drain events and assert
 *       HK_PROC_FLAG_REPARENT_SUSPECT (199) fires because the TRUE creator
 *       (this test) differs from the declared parent; with a rundll32 proxy in the
 *       chain, assert HK_PROC_FLAG_LOLBIN_ANCESTOR (201, set server-side). Must
 *       demonstrate true_creator != declared_parent is caught. Read-only
 *       assertion of raw report fields — never a local ban.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h + the create-ex flag surface.
 *
 * Merge gate (guardrail #12): present for the security folder; assertions activate
 * once the genealogy sensors are verified on the box and HK_GENEALOGY_TEST_ENABLED
 * is defined. Ships disabled like byovd_load.cpp.
 */

#include <cstdio>

#ifndef HK_GENEALOGY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: reparent_spoof activates once the process-genealogy "
                "sensors are verified on the Windows box (HK_GENEALOGY_TEST_ENABLED).\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <windows.h>
#include "horkos/ioctl.h"

int main(void)
{
    std::printf("reparent_spoof: sensor/enforcement path not yet verified on-box.\n");
    return 1;
}

#endif /* HK_GENEALOGY_TEST_ENABLED */
