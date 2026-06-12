/*
 * Role: Merge-gate bypass test (timing-side-channels signals 154 + 161, Windows).
 *       Intended to arm a real DR0-DR3 hardware breakpoint / set EFLAGS.TF on a guarded
 *       decoy and demonstrate that signal 154 (foreign-resolver attribution with a live
 *       DR6 bit) AND signal 161 (uniform-cadence guard-fault burst) fire — and that the
 *       histogram is SHIPPED, not locally banned (all ban authority is server-side).
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: drives the AC timing flag surface (ac/include/horkos/timing/timing_signals.h)
 *       + the shared first-chain VEH/decoy. Asserts the raw report fields, never a ban.
 *
 * Merge gate (guardrail #12): representative bypass test for the VEH/guard-page family.
 * Compiles now as a DISABLED no-op; assertions activate with the Phase-5 fixture harness
 * that arms a real HW breakpoint / single-step over the decoy. The repo never commits a
 * real stepping tool.
 */

#include <cstdio>

#ifndef HK_TIMING_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: hw_bp_stepper bypass test activates in Phase 5 "
                "(needs the fixture harness + the shared first-chain VEH/decoy path).\n");
    return 0;
}

#else

int main(void)
{
    /* Phase 5: arm DR0 on the decoy, drive timing_collect_all, and assert
     * report.veh (foreign_resolver + dr6_stepbit) and report.guard.uniform_cadence
     * fired AND that the report was shipped (no client-side ban). */
    std::printf("hw_bp_stepper: Phase 5 timing fixture not yet implemented.\n");
    return 1;
}

#endif /* HK_TIMING_TEST_ENABLED */
