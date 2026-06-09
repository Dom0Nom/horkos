/*
 * bypass-tests/linux/timing/hw_bp_perf.cpp
 * Role: Merge-gate bypass test (timing-side-channels signal 158, Linux). Intended to
 *       open a PERF_TYPE_BREAKPOINT perf event on a guarded symbol from OUTSIDE the
 *       game's thread group and demonstrate that signal 158's census counts it — and
 *       that it is AUDIT-ONLY on Steam Deck Game Mode (no local ban; ban authority is
 *       server-side).
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the eBPF HW-breakpoint census drain. Asserts the raw census count,
 *       never a ban.
 *
 * Merge gate (guardrail #12): compiles now as a DISABLED no-op; assertions activate with
 * the Phase-5 loader harness + the eBPF census attach (HK-UNCERTAIN in the .bpf.c until
 * the perf_event_open/breakpoint-install attach point is confirmed on the target BTF).
 * The activated body uses only perf_event_open on its OWN synthetic guarded symbol.
 */

#include <cstdio>

#ifndef HK_TIMING_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: linux hw_bp_perf bypass test activates in Phase 5 "
                "(needs the loader harness + the eBPF HW-breakpoint census attach).\n");
    return 0;
}

#else

int main(void)
{
    std::printf("hw_bp_perf (linux): Phase 5 eBPF census drain not yet implemented.\n");
    return 1;
}

#endif /* HK_TIMING_TEST_ENABLED */
