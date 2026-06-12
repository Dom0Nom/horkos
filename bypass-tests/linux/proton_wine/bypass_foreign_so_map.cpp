/*
 * Role: Linux Proton/Wine bypass-test fixture (merge gate, guardrail #12) for
 *       signal 101 (off-tree PROT_EXEC mapping). Demonstrates: LD_PRELOAD/dlopen a
 *       cheat SO from /tmp, and a memfd_create + mmap PROT_EXEC reflective load ->
 *       HK_EVENT_FOREIGN_MAP fires with HK_MAP_OFF_TREE / _MEMFD; an on-allowlist
 *       overlay SO (MangoHud) does NOT flag (FP gate — load-bearing assertion).
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event sink (signal 101) + PrefixMapAudit once the
 *            eBPF loader attach path lands on-box.
 */

#include <cstdio>

#ifndef HK_PW_FOREIGN_MAP_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: bypass_foreign_so_map activates once the mmap_exec_audit "
                "loader attach + PrefixMapAudit off-tree classifier land on-box.\n");
    return 0;
}

#else

#include <cstdlib>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    /* On-box fill-in:
     *   1. dlopen a cheat .so from /tmp -> assert HK_EVENT_FOREIGN_MAP / _OFF_TREE.
     *   2. memfd_create + write ELF + mmap PROT_EXEC -> assert _MEMFD.
     *   3. Map MangoHud (on overlay allowlist) -> assert NO off-tree flag. FP gate. */
    std::printf("bypass_foreign_so_map: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_PW_FOREIGN_MAP_TEST_ENABLED */
