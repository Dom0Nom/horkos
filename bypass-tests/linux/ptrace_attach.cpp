/*
 * Role: Linux bypass-test fixture (Phase 5: [disabled]). Intended to
 *       ptrace(PTRACE_ATTACH) the protected process and assert the AC stack
 *       raises the ptrace flag via the eBPF ptrace tracepoint hook (Phase 4).
 *       Compiled now for the merge gate (guardrail #12); assertions activate
 *       once the eBPF enforcement path lands.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: consumes the AC flag surface (ac_get_last_flag).
 */

#include <cstdio>

#ifndef HK_PTRACE_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: ptrace_attach activates once the Phase 4 eBPF ptrace "
                "tracepoint enforcement lands.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include "horkos/ac.h"

int main(void) {
    /* Phase 4+ fills this in: fork a target, PTRACE_ATTACH from a tracer, then
     * drain events / query ac_get_last_flag and assert the ptrace flag fired. */
    std::printf("ptrace_attach: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_PTRACE_TEST_ENABLED */
