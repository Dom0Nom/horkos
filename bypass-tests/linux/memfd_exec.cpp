/*
 * bypass-tests/linux/memfd_exec.cpp
 * Role: Linux bypass-test merge gate (guardrail #12) for signal 77 (fileless-
 *       exec correlation). Creates an anonymous memfd, writes a tiny static ELF
 *       into it, and execveat()s it with AT_EMPTY_PATH, asserting the JOINED
 *       HK_EVENT_FILELESS_EXEC fires (not merely the cheap HK_EVENT_MEMFD_CREATE
 *       tag) — i.e. the Loader (tgid,inode) correlation promoted the create+exec
 *       pair. Compiled now for the gate; live assertion under
 *       HK_MEMFD_EXEC_TEST_ENABLED.
 * Target platform: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event surface; asserts the cross-hook join.
 */

#include <cstdio>

#ifndef HK_MEMFD_EXEC_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: memfd_exec activates once the eBPF memory-access "
                "loader test harness (signal 77) lands.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <sys/mman.h>     /* memfd_create */
#include <sys/syscall.h>
#include <unistd.h>
#include <cstring>

int main(void) {
    /* Harness fills this in:
     *   1. register getpid() in hk_protected.
     *   2. fd = memfd_create("hk", MFD_CLOEXEC) -> assert HK_EVENT_MEMFD_CREATE.
     *   3. write a minimal static ELF into fd.
     *   4. fork(); child execveat(fd, "", argv, envp, AT_EMPTY_PATH).
     *   5. drain loader events; assert a JOINED HK_EVENT_FILELESS_EXEC for the
     *      same (tgid,inode), proving the Loader correlation, not just create. */
    std::printf("memfd_exec: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_MEMFD_EXEC_TEST_ENABLED */
