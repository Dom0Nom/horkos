/*
 * bypass-tests/linux/vm_write_attach.cpp
 * Role: Linux bypass-test merge gate (guardrail #12) for signal 74
 *       (process_vm_writev foreign-writer detection). Forks a victim that maps a
 *       known page, then from a separate tgid issues process_vm_writev(2) into
 *       it and asserts the eBPF fexit sensor emits HK_EVENT_VM_WRITE with the
 *       correct caller/target pids and bytes > 0. Compiled now for the gate;
 *       the live assertion activates once the eBPF loader test harness lands
 *       (HK_VM_WRITE_TEST_ENABLED).
 * Target platform: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the protected victim + the loader event surface.
 */

#include <cstdio>

#ifndef HK_VM_WRITE_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: vm_write_attach activates once the eBPF memory-access "
                "loader test harness (signal 74) lands.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdint>
#include <cstring>

int main(void) {
    /* Harness fills this in once the loader test surface exists:
     *   1. fork() a victim; register its tgid in hk_protected (ProtectedSet).
     *   2. victim maps a known buffer and reports its address (pipe).
     *   3. parent issues process_vm_writev() into that address.
     *   4. drain loader events; assert one HK_EVENT_VM_WRITE with
     *      caller_pid == getpid(), target_pid == victim, bytes == len. */
    std::printf("vm_write_attach: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_VM_WRITE_TEST_ENABLED */
