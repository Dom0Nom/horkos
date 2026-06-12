/*
 * Role: Merge-gate bypass test (memory-integrity-selfcheck signals 145/146/152,
 *       Linux). Intended to process_vm_writev/ptrace-patch our OWN .text, then assert
 *       the eBPF foreign read (145) + soft-dirty (146) + exec-VMA mprotect (152) path
 *       flags it where an in-process self-read would be spoofable.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the AC flag surface + the eBPF self-read drain.
 *
 * Merge gate (guardrail #12): representative bypass test for the Linux self-integrity
 * kernel-corroborated sensors. Compiles now as a DISABLED no-op; assertions activate
 * with the Phase-5 loader harness + the eBPF/LKM self-read path. The repo never
 * commits a real self-patching tool.
 */

#include <cstdio>

#ifndef HK_SELFCHECK_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: linux self_text_patch bypass test activates in Phase 5 "
                "(needs the loader harness + the eBPF/LKM self-read path).\n");
    return 0;
}

#else

int main(void)
{
    std::printf("self_text_patch (linux): Phase 5 eBPF self-read path not yet implemented.\n");
    return 1;
}

#endif /* HK_SELFCHECK_TEST_ENABLED */
