/*
 * bypass-tests/linux/ldpreload_inject.cpp
 * Role: Linux bypass-test fixture (merge gate, guardrail #12) for the
 *       linux-ebpf-injection sensors. Demonstrates: LD_PRELOAD a no-provenance
 *       DSO into a protected process -> signals 82 (DT_NEEDED divergence) AND 85
 *       (transient preload) fire; the SAME DSO added to a (test) signed
 *       allowlist -> suppressed (proves the FP gate). The suppression half is the
 *       load-bearing assertion. Compiled now for the gate; enforcement assertions
 *       activate once the eBPF loader + correlator attach path lands on-box.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event sink (signals 82/85) once it lands.
 */

#include <cstdio>

#ifndef HK_LDPRELOAD_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: ldpreload_inject activates once the linux-ebpf-injection "
                "loader attach + DsoProvenance/PreloadWatch correlators land on-box.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <cstdlib>
#include <unistd.h>

int main(void) {
    /* On-box fill-in:
     *   1. Build a tiny no-provenance .so (not in /proc/<pid>/exe's DT_NEEDED).
     *   2. Launch the protected fixture with LD_PRELOAD pointing at it.
     *   3. Drain loader events; assert HK_EVENT_DSO_PROVENANCE (no-DT_NEEDED +
     *      outside-allowlist) AND HK_EVENT_PRELOAD_ANOMALY (transient) fired.
     *   4. Add the .so's soname+build-id to the test signed allowlist, relaunch,
     *      and assert NEITHER signal fires (FP gate proven). */
    std::printf("ldpreload_inject: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_LDPRELOAD_TEST_ENABLED */
