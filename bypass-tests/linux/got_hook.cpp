/*
 * bypass-tests/linux/got_hook.cpp
 * Role: Linux bypass-test fixture (merge gate, guardrail #12) for signal 83
 *       (GOT/PLT redirection). Demonstrates: overwrite a .got.plt slot to a RWX
 *       trampoline -> signal 83 fires; an IFUNC slot left untouched -> no event
 *       (proves IFUNC exclusion). The IFUNC-exclusion half is the load-bearing
 *       assertion. Compiled now for the gate; assertions activate once the
 *       got_sample uprobe + GotPltMap correlator land on-box.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event sink (signal 83) once it lands.
 */

#include <cstdio>

#ifndef HK_GOT_HOOK_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: got_hook activates once the got_sample uprobe + "
                "GotPltMap correlator land on-box (signal 83 default-OFF).\n");
    return 0;
}

#else

int main(void) {
    /* On-box fill-in:
     *   1. Resolve a .got.plt slot of a benign import; mprotect RW; repoint it at
     *      a self-mapped RWX trampoline page.
     *   2. Trigger the sample uprobe; assert HK_EVENT_GOT_ANOMALY fired with
     *      HK_GOT_FLAG_RWX_TARGET/_ANON_TARGET.
     *   3. Leave an IFUNC (R_*_IRELATIVE) slot untouched; assert NO event for it
     *      (IFUNC exclusion proven). */
    std::printf("got_hook: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_GOT_HOOK_TEST_ENABLED */
