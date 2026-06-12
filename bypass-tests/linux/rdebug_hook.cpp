/*
 * Role: Linux bypass-test fixture (merge gate, guardrail #12) for signal 88
 *       (_r_debug r_brk / RELRO). Demonstrates: repoint _r_debug.r_brk outside
 *       the ld.so VMA (no tracer) -> signal 88 fires; with a ptrace tracer
 *       attached -> suppressed (proves the tracer FP gate). The tracer-suppression
 *       half is the load-bearing assertion. Compiled now for the gate; assertions
 *       activate once rdebug_sample + RDebugCheck land on-box.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event sink (signal 88) once it lands.
 */

#include <cstdio>

#ifndef HK_RDEBUG_HOOK_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: rdebug_hook activates once rdebug_sample + RDebugCheck "
                "land on-box (signal 88 default-OFF; /proc/pid/mem read flagged).\n");
    return 0;
}

#else

int main(void) {
    /* On-box fill-in:
     *   1. Overwrite _r_debug.r_brk to an address outside ld.so's VMA; trigger
     *      the sample; assert HK_EVENT_RDEBUG_ANOMALY fired.
     *   2. Attach a ptrace tracer; repeat; assert NO event (tracer suppression). */
    std::printf("rdebug_hook: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_RDEBUG_HOOK_TEST_ENABLED */
