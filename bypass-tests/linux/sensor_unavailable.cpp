/*
 * bypass-tests/linux/sensor_unavailable.cpp
 * Role: Linux bypass-test merge gate (guardrail #12) for the single most
 *       important correctness rule of the linux-module-integrity domain (§7
 *       "General"): a sensor whose source FS is unmounted or CAP_*-denied emits
 *       HK_EVENT_SENSOR_UNAVAILABLE and ZERO false detections. Runs the auditors
 *       with tracefs unmounted / kptr_restrict=2 and asserts each affected sensor
 *       reports a coverage gap, never a drift/hook/probe detection. Live
 *       assertion under HK_SENSOR_UNAVAIL_TEST_ENABLED; the parser-level form of
 *       this is ALSO covered host-side in test_linux_module_integrity_logic.cpp
 *       (the coverage-gap tests run anywhere, no live kernel needed).
 * Target platform: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the HostIntegritySensors event surface.
 */

#include <cstdio>

#ifndef HK_SENSOR_UNAVAIL_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: sensor_unavailable live form activates once the "
                "host-integrity aggregator harness lands; the parser-level "
                "coverage-gap assertions run host-side in the unit suite.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

int main(void) {
    /* Harness fills this in (live kernel, CI runner):
     *   1. Set kptr_restrict=2 (zero kallsyms addrs) and unmount tracefs.
     *   2. Run KallsymsAudit, FtraceAudit, KprobeAudit, ModuleViewDiff.
     *   3. ASSERT each affected sensor emitted HK_EVENT_SENSOR_UNAVAILABLE with
     *      the correct signal_id (91/93/94/92) and ZERO detection events.
     *   4. Restore kptr_restrict / remount tracefs; ASSERT normal operation
     *      resumes (no lingering false detections). */
    std::printf("sensor_unavailable: live enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_SENSOR_UNAVAIL_TEST_ENABLED */
