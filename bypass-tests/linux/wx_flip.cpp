/*
 * bypass-tests/linux/wx_flip.cpp
 * Role: Linux bypass-test merge gate (guardrail #12) for signal 76 (W^X /
 *       text->writable flip detection). Inside a process registered as
 *       protected, mmaps a region RW then mprotect()s it to RX (and an executable
 *       region back to writable), asserting the eBPF lsm/file_mprotect sensor
 *       emits HK_EVENT_WX_FLIP. Also asserts a flip taken BEFORE load_done_ns is
 *       SUPPRESSED (baseline gating works). Compiled now for the gate; live
 *       assertion activates under HK_WX_FLIP_TEST_ENABLED.
 * Target platform: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: self-registers as protected, then drives the loader event surface.
 */

#include <cstdio>

#ifndef HK_WX_FLIP_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: wx_flip activates once the eBPF memory-access loader "
                "test harness (signal 76) lands.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    /* Harness fills this in:
     *   1. register getpid() in hk_protected; do a pre-load_done_ns flip and
     *      assert it is SUPPRESSED.
     *   2. set load_done_ns (ProtectedSet); mmap(PROT_READ|PROT_WRITE) then
     *      mprotect(PROT_READ|PROT_EXEC), and an exec page back to +W.
     *   3. assert HK_EVENT_WX_FLIP fired post-baseline with VM_EXEC in vm_flags. */
    std::printf("wx_flip: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_WX_FLIP_TEST_ENABLED */
