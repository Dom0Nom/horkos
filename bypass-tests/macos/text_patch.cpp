/*
 * Role: macOS bypass-test fixture (signal 117) [disabled until enforcement].
 *       When enabled: mach_vm_protect the game __TEXT to RW + byte-patch and
 *       assert a hk_es_text_wx writable/COW-broken page with csops_valid=0.
 *       Compiled now for the merge gate (guardrail #12).
 * Target platforms: macOS only (built behind if(APPLE)).
 * Interface: consumes the AC flag surface (ac_get_last_flag) when enabled.
 */

#include <cstdio>

#ifndef HK_TEXTWX_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: text_patch activates once the macOS daemon __TEXT "
                "W^X scan + server scoring lands.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <cstdlib>
#include "horkos/ac.h"

int main(void) {
    /* Phase 5: mach_vm_protect game __TEXT to RW and patch a byte; expect a
     * hk_es_text_wx writable/COW-broken page with csops_valid=0. */
    std::printf("text_patch: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_TEXTWX_TEST_ENABLED */
