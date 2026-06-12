/*
 * Role: Merge-gate bypass test (timing-side-channels signal 159, Windows). A present debugger / exception-port interposer that swallows-and-reinjects the decoy 0xCC; must demonstrate signal 159 detects the multi-modal latency inflation even with correct re-injection.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: drives the AC timing flag surface
 *       (ac/include/horkos/timing/timing_signals.h). Asserts the raw report field the
 *       sensor produces, never a client-side ban (ban authority is server-side).
 *
 * Merge gate (guardrail #12): compiles now as a DISABLED no-op; assertions activate with
 * the Phase-5 fixture harness. The repo never commits a real bypass/hooking tool.
 */

#include <cstdio>

#ifndef HK_TIMING_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: exc_hook bypass test activates in Phase 5 (needs the timing fixture harness).\n");
    return 0;
}

#else

int main(void)
{
    std::printf("exc_hook: Phase 5 timing fixture not yet implemented.\n");
    return 1;
}

#endif /* HK_TIMING_TEST_ENABLED */
