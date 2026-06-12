/*
 * Role: Linux bypass-test fixture (merge gate, guardrail #12) for signal 89
 *       (LD_AUDIT). Demonstrates: launch with LD_AUDIT pointing at a
 *       no-provenance module -> signal 89 fires (la_symbind observed via the
 *       _dl_audit_symbind uprobe); an allowlisted audit module -> suppressed
 *       (proves the FP gate). The allowlist-suppression half is the load-bearing
 *       assertion. Compiled now for the gate; assertions activate once
 *       bprm_env + dl_audit land on-box.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event sink (signal 89) once it lands.
 */

#include <cstdio>

#ifndef HK_LD_AUDIT_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: ld_audit_inject activates once bprm_env (LSM) + "
                "dl_audit uprobe land on-box.\n");
    return 0;
}

#else

int main(void) {
    /* On-box fill-in:
     *   1. Launch the fixture with LD_AUDIT pointing at a no-provenance module;
     *      assert HK_EVENT_PRELOAD_ANOMALY with HK_LI_LD_AUDIT_ACTIVE fired
     *      (la_symbind observed, no allowlisted LD_AUDIT at exec).
     *   2. Add the audit module to the test allowlist; relaunch; assert NO event. */
    std::printf("ld_audit_inject: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_LD_AUDIT_TEST_ENABLED */
