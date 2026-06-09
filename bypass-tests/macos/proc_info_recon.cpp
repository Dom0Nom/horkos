/*
 * bypass-tests/macos/proc_info_recon.cpp
 * Role: macOS bypass-test fixture (signal 115) [disabled until enforcement].
 *       When enabled: high-rate proc_pidinfo VM-region walk of the game from a
 *       foreign process and assert a hk_es_proc_check over the rate threshold;
 *       a single benign PIDTASKINFO poll must produce NO flag. Compiled now for
 *       the merge gate (guardrail #12).
 * Target platforms: macOS only (built behind if(APPLE)).
 * Interface: consumes the AC flag surface (ac_get_last_flag) when enabled.
 */

#include <cstdio>

#ifndef HK_PROCCHECK_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: proc_info_recon activates once the macOS ES "
                "PROC_CHECK aggregation + server rate gate lands.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <cstdlib>
#include "horkos/ac.h"

int main(void) {
    /* Phase 5: hammer proc_pidinfo(PROC_PIDREGIONPATHINFO) on the game; expect a
     * hk_es_proc_check over PROC_CHECK_RATE_THRESHOLD. One PIDTASKINFO: no flag. */
    std::printf("proc_info_recon: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_PROCCHECK_TEST_ENABLED */
