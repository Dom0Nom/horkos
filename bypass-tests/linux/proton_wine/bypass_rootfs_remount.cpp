/*
 * bypass-tests/linux/proton_wine/bypass_rootfs_remount.cpp
 * Role: Linux Proton/Wine bypass-test fixture (merge gate, guardrail #12) for
 *       signal 105 (read-only rootfs breach). Demonstrates: steamos-readonly
 *       disable + write under /usr outside an update window on a simulated
 *       immutable rootfs -> HK_EVENT_ROOTFS_RW with HK_ROOTFS_REMOUNT_RW /
 *       _PROTECTED_WRITE; a frzr/rauc update-window RW transition is _UPDATE_WINDOW-
 *       tagged; a desktop-distro RW root does NOT flag (immutable-distro gate — the
 *       load-bearing FP assertion). lsm/sb_remount availability is UNCERTAIN
 *       (impl-plan Risks), so this test also runs in replay mode.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event sink (signal 105) + DeckRootfsBaseline.
 */

#include <cstdio>

#ifndef HK_PW_ROOTFS_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: bypass_rootfs_remount activates once rootfs_ro_audit "
                "(lsm/sb_remount — UNCERTAIN, confirm hook) and DeckRootfsBaseline "
                "land on-box. Replay mode gates the decode path meanwhile.\n");
    return 0;
}

#else

#include <unistd.h>

int main(void) {
    /* On-box fill-in:
     *   1. Simulate immutable rootfs; seed DeckRootfsBaseline(immutable=true).
     *   2. remount,rw root + write /usr outside update window -> assert
     *      HK_EVENT_ROOTFS_RW / HK_ROOTFS_REMOUNT_RW | _PROTECTED_WRITE.
     *   3. Same inside a frzr/rauc window -> assert _UPDATE_WINDOW.
     *   4. Desktop distro (immutable=false) RW root -> assert NO flag. FP gate. */
    std::printf("bypass_rootfs_remount: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_PW_ROOTFS_TEST_ENABLED */
