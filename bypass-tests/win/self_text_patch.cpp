/*
 * bypass-tests/win/self_text_patch.cpp
 * Role: Merge-gate bypass test (memory-integrity-selfcheck signals 145/146/152,
 *       Windows). Intended to inline-patch our OWN .text and install a
 *       self-read-restoring NtReadVirtualMemory hook, then assert: signal 145
 *       hash_inproc looks CLEAN but hash_kernel/hash_disk diverge (the kernel foreign
 *       read defeats the hook); signal 146 shows the page went private/CoW; signal 152
 *       shows the kernel PTE write-bit vs usermode-RX disagreement. Proves self-hashing
 *       alone is insufficient and the kernel path catches the restore-on-read hook.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: drives the large-record self-read drain + the AC flag surface.
 *
 * Merge gate (guardrail #12): this file is the representative bypass test for the
 * memory-integrity-selfcheck kernel-corroborated sensors. It compiles now as a
 * DISABLED no-op; its assertions activate when the Phase-5 signed fixture harness +
 * the HK_IOCTL_SELF_READ_VA caller-identity gate + the large-record drain plane land.
 * The repo never commits a real self-read-restoring hook.
 */

#include <cstdio>

#ifndef HK_SELFCHECK_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: self_text_patch bypass test activates in Phase 5 "
                "(needs the signed fixture harness + the HK_IOCTL_SELF_READ_VA "
                "caller-identity gate + the large-record self-read drain plane).\n");
    return 0; /* Disabled tests pass so the gate stays green pre-Phase-5. */
}

#else

#include <windows.h>
#include "horkos/ioctl.h"

/* Phase 5 fills this in: inline-patch our own .text, install the self-read-restoring
 * NtReadVirtualMemory hook, drive a self-check pass, and assert hash_inproc clean
 * while hash_kernel/hash_disk diverge (145), the page is private/CoW (146), and the
 * kernel PTE write-bit vs usermode-RX split (152). */
int main(void)
{
    std::printf("self_text_patch: Phase 5 kernel self-read path not yet implemented.\n");
    return 1;
}

#endif /* HK_SELFCHECK_TEST_ENABLED */
