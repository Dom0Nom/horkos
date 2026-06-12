/*
 * Role: Merge-gate bypass test (memory-integrity-selfcheck signals 145/146/152,
 *       macOS). Intended to mach_vm_write-patch our OWN __TEXT, then assert the daemon
 *       mach_vm_region_recurse SM_COW (146) + mach_vm_read divergence (145) path flags
 *       it where an in-process self-read would be spoofable.
 * Target platforms: macOS only (built behind if(APPLE)).
 * Interface: drives the AC flag surface (ac/include/horkos/ac.h) + the daemon self-read.
 *
 * Merge gate (guardrail #12): representative bypass test for the macOS self-integrity
 * daemon self-read sensors. Compiles now as a DISABLED no-op; assertions activate with
 * the Phase-5 fixture + the daemon self-task mach_vm_* path (once entitlement-free
 * self introspection is confirmed). The repo never commits a real self-patching tool.
 */

#include <cstdio>

#ifndef HK_SELFCHECK_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: macos self_text_patch bypass test activates in Phase 5 "
                "(needs the fixture + the daemon self-task mach_vm_* self-read path).\n");
    return 0;
}

#else

int main(void)
{
    std::printf("self_text_patch (macos): Phase 5 daemon self-read path not yet implemented.\n");
    return 1;
}

#endif /* HK_SELFCHECK_TEST_ENABLED */
