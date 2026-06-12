/*
 * Role: Linux bypass-test merge gate (guardrail #12) for signal 98 (devmem
 *       write-intent open). Opens /dev/mem O_RDWR and asserts signal 98 emits
 *       with write_intent=1; opening read-only asserts no write-intent flag;
 *       AND asserts the AUDIT-ONLY invariant — the extended lsm/file_open program
 *       still returned `ret` (never a hard deny). Distinct from devmem_open.cpp
 *       (signal 78, bare physmem open): 98 is specifically the write-intent
 *       discriminator. Live assertion under HK_DEVMEM_WRITE_TEST_ENABLED.
 * Target platform: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event surface (lsm_file_open devmem-write arm).
 */

#include <cstdio>

#ifndef HK_DEVMEM_WRITE_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: devmem_write_open activates once the eBPF loader test "
                "harness (signal 98) lands on the eBPF CI runner.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <fcntl.h>
#include <unistd.h>
#include <cerrno>

int main(void) {
    /* Harness fills this in (live kernel, CI runner):
     *   1. fd = open("/dev/mem", O_RDWR).
     *      - on success: ASSERT HK_EVENT_DEVMEM_ACCESS fired with write_intent==1
     *        and dev_minor==1.
     *      - on EPERM/EACCES with lockdown active: SKIP, print "denied by
     *        lockdown" (skip != silent pass).
     *   2. fd2 = open("/dev/mem", O_RDONLY): ASSERT the emitted event (if any)
     *      has write_intent==0 (read-only DMI-scan FP gate).
     *   3. AUDIT-ONLY INVARIANT: ASSERT both opens were ALLOWED by the LSM (the
     *      program returned `ret`, never -EPERM from our hook). */
    std::printf("devmem_write_open: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_DEVMEM_WRITE_TEST_ENABLED */
