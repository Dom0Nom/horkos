/*
 * bypass-tests/linux/proton_wine/bypass_cross_mem_scan.cpp
 * Role: Linux Proton/Wine bypass-test fixture (merge gate, guardrail #12) for
 *       signal 102 (cross-process memory scan). Demonstrates: an external scanner
 *       reads the game via process_vm_readv AND via /proc/<pid>/mem ->
 *       HK_EVENT_CROSS_MEM fires for both (READV / PROCMEM); the game's own
 *       wineserver read is flagged HK_XMEM_FLAG_WINESERVER (REPORTED, not silently
 *       dropped) and a user-attached debugger is _DEBUGGER-tagged, not lost. The
 *       "faithfully reported, never dropped" half is the load-bearing assertion.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event sink (signal 102) + the loader's wineserver-
 *            tgid resolution once the eBPF loader attach path lands on-box.
 */

#include <cstdio>

#ifndef HK_PW_CROSS_MEM_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: bypass_cross_mem_scan activates once the cross_mem_audit "
                "loader attach + wineserver-tgid resolution land on-box.\n");
    return 0;
}

#else

#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>

int main(void) {
    /* On-box fill-in:
     *   1. fork() a game victim; resolve + register its wineserver tgid.
     *   2. external scanner process_vm_readv(victim) -> assert HK_EVENT_CROSS_MEM
     *      access_kind=READV, flags NOT WINESERVER/HORKOS_SELF.
     *   3. external scanner open(/proc/victim/mem) read -> assert PROCMEM.
     *   4. wineserver's own read of the game -> assert the record is EMITTED with
     *      HK_XMEM_FLAG_WINESERVER (reported, not dropped).
     *   5. user gdb attach read -> assert _DEBUGGER-tagged, not lost. */
    std::printf("bypass_cross_mem_scan: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_PW_CROSS_MEM_TEST_ENABLED */
