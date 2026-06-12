/*
 * Role: Merge-gate bypass test (memory-integrity-selfcheck signal 148, Windows).
 *       Intended to set a hardware breakpoint on a critical function via
 *       SetThreadContext, then spoof usermode GetThreadContext to read back clean, and
 *       assert the kernel-side DR read (148) flags the DR landing in our .text where
 *       the usermode view was lied to.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: drives the AC flag surface + the kernel DR self-read.
 *
 * Merge gate (guardrail #12): representative bypass test for the kernel-context DR
 * audit. Compiles now as a DISABLED no-op; assertions activate with the Phase-5
 * fixture harness + the kernel DR self-read path (HK_SELF_READ_DEBUG_REGS).
 */

#include <cstdio>

#ifndef HK_SELFCHECK_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: self_hwbp bypass test activates in Phase 5 "
                "(needs the fixture harness + the kernel DR self-read path).\n");
    return 0;
}

#else

#include <windows.h>
#include "horkos/ioctl.h"

int main(void)
{
    std::printf("self_hwbp: Phase 5 kernel DR self-read path not yet implemented.\n");
    return 1;
}

#endif /* HK_SELFCHECK_TEST_ENABLED */
