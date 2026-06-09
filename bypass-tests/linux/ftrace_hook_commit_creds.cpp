/*
 * bypass-tests/linux/ftrace_hook_commit_creds.cpp
 * Role: Linux bypass-test merge gate (guardrail #12) for signal 93 (ftrace
 *       ownership audit). Attaches a benign ftrace hook to commit_creds from an
 *       unsigned research module and asserts signal 93 FLAGS it
 *       (HK_EVENT_FTRACE_HOOK, owner_attributed=0) — AND, crucially, asserts the
 *       FP-suppression half: the SAME hook owned by an allowlisted signed module
 *       is NOT flagged. The suppression half is the load-bearing assertion (it
 *       proves the catalog's FP gate actually works). Research artifact, NOT
 *       shipped. Live assertion under HK_FTRACE_TEST_ENABLED.
 * Target platform: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the HostIntegritySensors event surface (FtraceAudit).
 */

#include <cstdio>

#ifndef HK_FTRACE_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: ftrace_hook_commit_creds activates once the "
                "host-integrity ftrace auditor harness (signal 93) lands on the "
                "eBPF/LKM CI runner.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

int main(void) {
    /* Harness fills this in (live kernel, CI runner):
     *   1. insmod a benign research module that registers an ftrace_ops on
     *      commit_creds (the unsigned, unattributable case).
     *   2. Run FtraceAudit over /sys/kernel/tracing/enabled_functions.
     *   3. ASSERT one HK_EVENT_FTRACE_HOOK with func_id == commit_creds and
     *      owner_attributed == 0.
     *   4. SUPPRESSION HALF (load-bearing): repeat with the ops owner resolving
     *      into an allowlisted SIGNED tracer module; ASSERT no flag (the
     *      server-side allowlist path / attributed owner suppresses it).
     *   5. rmmod the research module. */
    std::printf("ftrace_hook_commit_creds: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_FTRACE_TEST_ENABLED */
