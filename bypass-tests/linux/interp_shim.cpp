/*
 * bypass-tests/linux/interp_shim.cpp
 * Role: Linux bypass-test fixture (merge gate, guardrail #12) for signal 84
 *       (PT_INTERP mismatch). Demonstrates: launch via a patched ld.so path ->
 *       signal 84 fires; a patchelf'd PT_INTERP resolvable via the (mock)
 *       container manifest -> suppressed (proves the manifest FP gate). The
 *       manifest-suppression half is the load-bearing assertion. Compiled now for
 *       the gate; assertions activate once interp_entry + InterpCheck land on-box.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event sink (signal 84) once it lands.
 */

#include <cstdio>

#ifndef HK_INTERP_SHIM_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: interp_shim activates once interp_entry uprobe + "
                "InterpCheck correlator (container-manifest resolver) land on-box.\n");
    return 0;
}

#else

int main(void) {
    /* On-box fill-in:
     *   1. patchelf --set-interpreter a shim ld.so with an unknown build-id;
     *      launch; assert HK_EVENT_INTERP_MISMATCH fired.
     *   2. Feed the mock manifest the shim's build-id as an accepted
     *      pressure-vessel loader; relaunch; assert NO event (manifest gate). */
    std::printf("interp_shim: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_INTERP_SHIM_TEST_ENABLED */
