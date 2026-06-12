/*
 * Role: Merge-gate bypass test (guardrail #12) for signal 210 (IA32_LSTAR per-CPU
 *       validation, win-kernel-syscall-etw-integrity). A Phase-5 test-signed
 *       fixture rewrites IA32_LSTAR on ONE CPU; the AC must emit
 *       HK_INTEGRITY_LSTAR_CPU_DIVERGE (the version-independent half) and, once the
 *       absolute expected value resolves, HK_INTEGRITY_LSTAR_MISMATCH. A clean
 *       KVA-shadow box (expected == KiSystemCall64Shadow) must NOT false-positive.
 *       Ships DISABLED (HK_INTEGRITY_TEST_ENABLED undefined): a compiled no-op
 *       returning 0, like byovd_load.cpp. The repo never commits an MSR-rewriting
 *       driver.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the integrity event surface
 *       (HK_INTEGRITY_LSTAR_CPU_DIVERGE / _LSTAR_MISMATCH). HK-TODO(schema):
 *       kernel-private mirrors until the Schema phase appends them.
 */

#include <cstdio>

#ifndef HK_INTEGRITY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: lstar_repoint activates in Phase 5 (needs the "
                "test-signed per-CPU LSTAR-rewrite fixture + "
                "HK_EVENT_INTEGRITY_FINDING schema bump).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_INTEGRITY_LSTAR_* mirrors */

static int count_findings(uint32_t finding)
{
    (void)finding;
    return 0;
}

int main(void)
{
    /* Per-CPU divergence is the always-safe half and must fire on a one-CPU
     * repoint regardless of KVA-shadow detection. */
    if (count_findings(HK_INTEGRITY_LSTAR_CPU_DIVERGE) < 1) {
        std::printf("lstar_repoint: expected LSTAR_CPU_DIVERGE not observed.\n");
        return 1;
    }
    std::printf("lstar_repoint: passed.\n");
    return 0;
}

#endif /* HK_INTEGRITY_TEST_ENABLED */
