/*
 * Role: Merge-gate bypass test (timing-side-channels signal 160, macOS). Intended to
 *       install a foreign Mach exception port for EXC_BREAKPOINT (LLDB-style) and
 *       demonstrate that signal 160 flags the non-self / non-system owner — AND that the
 *       ES auth event was STILL replied to within the kernel deadline (guardrail #7
 *       assertion: the audit never gates the reply).
 * Target platforms: macOS only (built behind if(APPLE)).
 * Interface: drives the ES exception-port audit (HkExceptionPortAudit) + the AC flag
 *       surface. Asserts the raw owner classification AND the ES-reply invariant, never
 *       a client-side ban.
 *
 * Merge gate (guardrail #12): compiles now as a DISABLED no-op; assertions activate with
 * the Phase-5 ES fixture + the foreign-task exception-port resolution (HK-UNCERTAIN in
 * ExceptionPortAudit.mm until the ES-client task-port acquisition is confirmed on-box).
 * The repo never commits a real debugger fixture.
 */

#include <cstdio>

#ifndef HK_TIMING_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: macos lldb_exc_port bypass test activates in Phase 5 "
                "(needs the ES fixture + the foreign-task exception-port resolution).\n");
    return 0;
}

#else

int main(void)
{
    /* Phase 5: install a foreign EXC_BREAKPOINT port, drive an exec through ES, and
     * assert (a) HkExceptionPortAudit classifies the owner FOREIGN/breakpoint_foreign,
     * and (b) the ES AUTH event was replied to before its deadline regardless. */
    std::printf("lldb_exc_port (macos): Phase 5 ES exception-port fixture not yet implemented.\n");
    return 1;
}

#endif /* HK_TIMING_TEST_ENABLED */
