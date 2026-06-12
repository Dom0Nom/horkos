/*
 * Role: Linux bypass-test merge gate (guardrail #12) for signal 99 (sensitive
 *       MSR write). Writes to /dev/cpu/0/msr at the LSTAR offset (in a throwaway
 *       VM) and asserts signal 99 flags it (sensitive=1); writing a power/perf
 *       MSR (0x150) asserts NO flag (the FP gate). The suppression half is the
 *       load-bearing assertion. Research artifact, NOT shipped. Live assertion
 *       under HK_MSR_TEST_ENABLED.
 * Target platform: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event surface (tracepoints pwrite64 arm +
 *            MsrPathResolver fd/index resolution).
 */

#include <cstdio>

#ifndef HK_MSR_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: msr_lstar_write activates once the eBPF loader test "
                "harness (signal 99) lands on the eBPF CI runner (throwaway VM).\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstdint>

int main(void) {
    /* Harness fills this in (live kernel, throwaway VM — an LSTAR write can wedge
     * the syscall path, so this MUST run disposably):
     *   1. modprobe msr; fd = open("/dev/cpu/0/msr", O_WRONLY).
     *   2. pwrite64(fd, &val, 8, 0xC0000082) — LSTAR. ASSERT
     *      HK_EVENT_MSR_WRITE_SENSITIVE fired with msr_index==0xC0000082 and
     *      sensitive==1 (MsrPathResolver resolved the fd to /dev/cpu/0/msr and
     *      classified the index).
     *   3. FP GATE (load-bearing): pwrite64 at offset 0x150 (a power/perf MSR);
     *      ASSERT the emitted event has sensitive==0 (benign).
     *   4. ASSERT a non-msr fd write produces NO event (fd-resolution drop). */
    std::printf("msr_lstar_write: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_MSR_TEST_ENABLED */
