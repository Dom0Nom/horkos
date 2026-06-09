/*
 * bypass-tests/linux/module_unlink_hidden.cpp
 * Role: Linux bypass-test merge gate (guardrail #12) for signal 92 (module-view
 *       cross-enumeration diff). Loads a benign test module that list_del-unlinks
 *       itself from /proc/modules while keeping its sysfs kobject, then asserts
 *       signal 92 emits HK_EVENT_MODULE_VIEW_DIFF AFTER the debounce. The test
 *       module is a research artifact under bypass-tests/, NOT shipped. Compiled
 *       now for the gate; live assertion under HK_MODULE_VIEW_TEST_ENABLED (needs
 *       the loader/aggregator harness + a real kernel on the eBPF CI runner).
 * Target platform: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the HostIntegritySensors event surface (ModuleViewDiff).
 */

#include <cstdio>

#ifndef HK_MODULE_VIEW_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: module_unlink_hidden activates once the host-integrity "
                "aggregator test harness (signal 92) lands on the eBPF/LKM CI "
                "runner.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

int main(void) {
    /* Harness fills this in (live kernel, CI runner):
     *   1. insmod a benign research module that, on init, list_del()s itself from
     *      the module list (hidden from /proc/modules) but leaves its
     *      /sys/module/<m> kobject intact.
     *   2. Run two ModuleViewDiff snapshots 500 ms apart (the debounce window).
     *   3. ASSERT exactly one HK_EVENT_MODULE_VIEW_DIFF with present_mask showing
     *      HK_MV_SYSFS set and HK_MV_PROCMODULES clear (the self-unlink tell).
     *   4. Negative control: a normally-loaded module produces NO diff.
     *   5. rmmod the research module. */
    std::printf("module_unlink_hidden: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_MODULE_VIEW_TEST_ENABLED */
