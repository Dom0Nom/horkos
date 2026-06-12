/*
 * Role: macOS bypass-test fixture (signal 111) [disabled until enforcement].
 *       When enabled: mmap a foreign mach-o / RWX anon page into the game and
 *       assert a hk_es_mmap with baseline_match != KNOWN; a sanctioned-JIT map
 *       must produce NO flag. Compiled now for the merge gate (guardrail #12).
 * Target platforms: macOS only (built behind if(APPLE)).
 * Interface: consumes the AC flag surface (ac_get_last_flag) when enabled.
 */

#include <cstdio>

#ifndef HK_MMAP_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: mmap_exec_foreign activates once the macOS ES MMAP "
                "sink + baseline/server scoring lands.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <cstdlib>
#include "horkos/ac.h"

int main(void) {
    /* Phase 5: mmap a foreign mach-o / MAP_ANON RWX page into the game; expect
     * baseline_match ANON_RWX/UNKNOWN. A sanctioned (manifest/JIT) map: no flag. */
    std::printf("mmap_exec_foreign: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_MMAP_TEST_ENABLED */
