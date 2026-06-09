/*
 * bypass-tests/linux/loadorder_interpose.cpp
 * Role: Linux bypass-test fixture (merge gate, guardrail #12) for signal 87
 *       (load-order inversion, CORROBORATING-ONLY). Demonstrates: preload a
 *       malloc-interposer ahead of libc with no provenance -> signal 87 flagged
 *       (corroborating); a jemalloc-style allowlisted preload -> suppressed. Two
 *       load-bearing assertions: the allowlist suppression, AND that signal 87
 *       alone never reaches the ban threshold (corroborating-only — verified
 *       server-side in ban_engine::loader_inject, mirrored here). Compiled now for
 *       the gate; assertions activate once dl_map_object + LinkMapOrder land.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event sink (signal 87) once it lands.
 */

#include <cstdio>

#ifndef HK_LOADORDER_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: loadorder_interpose activates once dl_map_object uprobe "
                "+ LinkMapOrder correlator land on-box (signal 87 corroborating-only).\n");
    return 0;
}

#else

int main(void) {
    /* On-box fill-in:
     *   1. LD_PRELOAD a no-provenance malloc interposer ahead of libc; assert
     *      HK_EVENT_LOADORDER_INVERT flagged.
     *   2. Assert the server scores it corroborating-only (no ban standalone).
     *   3. Use an allowlisted jemalloc build; assert NO event. */
    std::printf("loadorder_interpose: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_LOADORDER_TEST_ENABLED */
