/*
 * Role: Linux bypass-test fixture (merge gate, guardrail #12) for signal 86
 *       (fileless dlopen). Demonstrates: memfd_create + dlopen("/proc/self/fd/N")
 *       of an exec DSO -> signal 86 fires; a file-backed gconv-style dlopen -> no
 *       event (proves the file-backed suppression). The file-backed-suppression
 *       half is the load-bearing assertion. Compiled now for the gate; assertions
 *       activate once dlopen_uprobe + DlopenBacking land on-box.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event sink (signal 86) once it lands.
 */

#include <cstdio>

#ifndef HK_MEMFD_DLOPEN_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: memfd_dlopen activates once dlopen_uprobe + "
                "DlopenBacking correlator land on-box.\n");
    return 0;
}

#else

int main(void) {
    /* On-box fill-in:
     *   1. memfd_create an executable DSO, write it, dlopen("/proc/self/fd/N").
     *   2. Assert HK_EVENT_DLOPEN_BACKING fired (memfd/anon-exec backing).
     *   3. dlopen a real on-disk file-backed DSO; assert NO event. */
    std::printf("memfd_dlopen: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_MEMFD_DLOPEN_TEST_ENABLED */
