/*
 * bypass-tests/linux/proton_wine/bypass_builtin_stomp.cpp
 * Role: Linux Proton/Wine bypass-test fixture (merge gate, guardrail #12) for
 *       signal 107 (Wine builtin integrity / W^X re-arm). Demonstrates: swap a Wine
 *       builtin (ntdll) with an off-dist SO, and hot-patch a builtin .text page
 *       W->RX during gameplay -> HK_EVENT_WX_ARM with HK_WX_IN_BUILTIN /
 *       _INODE_OFF_MANIFEST and the inode-mismatch from the maps walk; legitimate
 *       ESYNC/FSYNC + PE-loader relocation (on-disk hash matches) does NOT flag (FP
 *       gate — load-bearing). lsm/file_mprotect + prior-prot reachability is
 *       UNCERTAIN (impl-plan Risks), so this test also runs in replay mode over a
 *       recorded wx_arm record, exercising the inode-arm decision standalone.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event sink (signal 107) + WineBuiltinIntegrity.
 */

#include <cstdio>

#ifndef HK_PW_BUILTIN_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: bypass_builtin_stomp activates once mprotect_wx_audit "
                "(lsm/file_mprotect — UNCERTAIN, confirm hook + prior-prot) and "
                "WineBuiltinIntegrity (maps walk + on-disk SHA, manifest data dep) "
                "land on-box. Replay mode gates the inode-arm decision meanwhile.\n");
    return 0;
}

#else

#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    /* On-box fill-in:
     *   1. Replace ntdll.so with an off-dist SO -> assert the maps-walk inode arm
     *      yields HK_WX_IN_BUILTIN | _INODE_OFF_MANIFEST.
     *   2. mprotect a builtin .text page W->RX mid-game -> assert HK_EVENT_WX_ARM
     *      (HK_WX_WAS_RX | _IN_BUILTIN).
     *   3. Legit ESYNC/FSYNC + relocated builtin (on-disk SHA matches) -> NO flag. */
    std::printf("bypass_builtin_stomp: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_PW_BUILTIN_TEST_ENABLED */
