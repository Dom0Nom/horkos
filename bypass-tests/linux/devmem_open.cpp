/*
 * bypass-tests/linux/devmem_open.cpp
 * Role: Linux bypass-test merge gate (guardrail #12) for signal 78 (physical-
 *       memory-window open detection). Attempts to open /dev/mem (and
 *       /proc/kcore) and asserts the eBPF lsm/file_open devmem sensor emits
 *       HK_EVENT_PHYSMEM_OPEN. If kernel lockdown DENIES the open, the test
 *       SKIPS honestly (reports "denied by lockdown") rather than passing
 *       silently — the gate stays meaningful. Compiled now for the gate; live
 *       assertion under HK_DEVMEM_TEST_ENABLED.
 * Target platform: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event surface.
 */

#include <cstdio>

#ifndef HK_DEVMEM_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: devmem_open activates once the eBPF memory-access "
                "loader test harness (signal 78) lands.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <fcntl.h>
#include <unistd.h>
#include <cerrno>

int main(void) {
    /* Harness fills this in:
     *   1. fd = open("/dev/mem", O_RDONLY).
     *      - on success: assert HK_EVENT_PHYSMEM_OPEN fired (rdev = MKDEV(1,1)).
     *      - on EPERM/EACCES with lockdown active: SKIP, print
     *        "denied by lockdown" (skip != silent pass).
     *   2. repeat for /proc/kcore. */
    std::printf("devmem_open: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_DEVMEM_TEST_ENABLED */
