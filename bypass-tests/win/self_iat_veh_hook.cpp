/*
 * bypass-tests/win/self_iat_veh_hook.cpp
 * Role: Merge-gate bypass test (memory-integrity-selfcheck signals 149/150/153,
 *       Windows). Intended to hook a scoped IAT slot, install a VEH ahead of ours, and
 *       append a TLS callback, then assert: 149 fires with the slot RVA + displaced
 *       target; 150 fires on the ordered-ahead VEH; 153 fires on the extra TLS
 *       callback; AND a benign signed-overlay-style IAT redirect whose target resolves
 *       into an allow-listed module does NOT fire (the FP guard).
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: drives the AC flag surface + the self-event drain.
 *
 * Merge gate (guardrail #12): representative bypass test for the userspace-format
 * self-integrity sensors. Compiles now as a DISABLED no-op; assertions activate with
 * the Phase-5 fixture harness + the server signed-overlay allow-list. The repo never
 * commits a real IAT/VEH/TLS hooking tool.
 */

#include <cstdio>

#ifndef HK_SELFCHECK_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: self_iat_veh_hook bypass test activates in Phase 5 "
                "(needs the fixture harness + the server signed-overlay allow-list "
                "for the FP-guard half).\n");
    return 0;
}

#else

#include <windows.h>
#include "horkos/ioctl.h"

int main(void)
{
    std::printf("self_iat_veh_hook: Phase 5 IAT/VEH/TLS audit path not yet implemented.\n");
    return 1;
}

#endif /* HK_SELFCHECK_TEST_ENABLED */
