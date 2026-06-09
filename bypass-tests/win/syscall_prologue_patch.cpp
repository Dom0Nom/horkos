/*
 * bypass-tests/win/syscall_prologue_patch.cpp
 * Role: Merge-gate bypass test (guardrail #12) for signal 213 (syscall-entry
 *       prologue tamper, win-kernel-syscall-etw-integrity). A Phase-5 test-signed
 *       fixture inline-patches KiSystemCall64; the AC must emit
 *       HK_INTEGRITY_SYSCALL_PROLOGUE — AND, critically, a clean machine whose
 *       prologue window already carries retpoline/KVA-shadow/hotpatch boot self-
 *       patching must NOT fire (the boot-self-patch FP-gate proof). Ships DISABLED
 *       (HK_INTEGRITY_TEST_ENABLED undefined): a compiled no-op returning 0, like
 *       byovd_load.cpp.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the integrity event surface
 *       (HK_INTEGRITY_SYSCALL_PROLOGUE). HK-TODO(schema): kernel-private mirrors
 *       until the Schema phase appends them.
 */

#include <cstdio>

#ifndef HK_INTEGRITY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: syscall_prologue_patch activates in Phase 5 (needs the "
                "test-signed prologue-patch fixture, a validated stable-window "
                "baseline, + HK_EVENT_INTEGRITY_FINDING schema bump).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_INTEGRITY_SYSCALL_PROLOGUE mirror */

static int count_findings(uint32_t finding)
{
    (void)finding;
    return 0;
}

int main(void)
{
    if (count_findings(HK_INTEGRITY_SYSCALL_PROLOGUE) < 1) {
        std::printf("syscall_prologue_patch: expected SYSCALL_PROLOGUE not "
                    "observed.\n");
        return 1;
    }
    std::printf("syscall_prologue_patch: passed.\n");
    return 0;
}

#endif /* HK_INTEGRITY_TEST_ENABLED */
