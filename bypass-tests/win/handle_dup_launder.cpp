/*
 * Role: Merge-gate bypass test (guardrail #12) for signal 66 (DuplicateHandle source
 *       laundering, win-handle-memory-access). A Phase-5 fixture opens a process
 *       handle to the protected target in broker A, then DuplicateHandle's it into B
 *       so B never appears as the create-path opener. The AC's Ob post-op provenance
 *       (HkObPostCallback + the provenance ring) must emit HK_EVENT_HANDLE_PROVENANCE
 *       with HK_HND_DUP_LAUNDERED because the dup's root opener (A) — or rather the
 *       laundering chain — is not accounted for in the create log. Ships DISABLED
 *       (HK_VMWATCH_TEST_ENABLED undefined): a compiled no-op, like byovd_load.cpp.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the handle-provenance surface
 *       (HK_EVENT_HANDLE_PROVENANCE / HK_HND_DUP_LAUNDERED). HK-TODO(schema): the
 *       24-byte payload exceeds the frozen envelope and the type is a kernel-private
 *       mirror until the Schema phase grows HK_EVENT_PAYLOAD_MAX and appends it.
 */

#include <cstdio>

#ifndef HK_VMWATCH_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: handle_dup_launder activates in Phase 5 (needs the Ob "
                "post-op provenance emit + the HK_EVENT_HANDLE_PROVENANCE schema bump, "
                "incl. the HK_EVENT_PAYLOAD_MAX growth for the 24-byte payload).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_EVENT_HANDLE_PROVENANCE / HK_HND_DUP_LAUNDERED mirrors */

/* Phase-5: drain \\.\Horkos, count HK_EVENT_HANDLE_PROVENANCE records whose flags
 * carry HK_HND_DUP_LAUNDERED. */
static int count_laundered_dups(void)
{
    return 0;
}

int main(void)
{
    if (count_laundered_dups() < 1) {
        std::printf("handle_dup_launder: expected HK_HND_DUP_LAUNDERED not observed.\n");
        return 1;
    }
    std::printf("handle_dup_launder: passed.\n");
    return 0;
}

#endif /* HK_VMWATCH_TEST_ENABLED */
