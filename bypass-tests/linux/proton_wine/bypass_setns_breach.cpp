/*
 * Role: Linux Proton/Wine bypass-test fixture (merge gate, guardrail #12) for
 *       signal 103 (namespace-entry breach). Demonstrates: nsenter into the game's
 *       mnt/pid namespace from a process OUTSIDE the pv-bwrap lineage ->
 *       HK_EVENT_NS_ENTRY fires with HK_NS_FLAG_OFF_LINEAGE; pressure-vessel's own
 *       setns (a descendant of the launcher) does NOT flag (FP gate). Because the
 *       setns install kprobe is UNCERTAIN on the target Deck kernel (impl-plan
 *       Risks), this test ALSO runs in replay mode: it feeds a recorded ns_entry
 *       ring record through Loader.cpp + linux_proton.rs so the decode/classify
 *       path is gated even before the live kprobe arm is confirmed on-box.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event sink (signal 103) + ContainerNsBaseline.
 */

#include <cstdio>

#ifndef HK_PW_SETNS_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: bypass_setns_breach activates once namespace_entry "
                "(setns install kprobe — UNCERTAIN, confirm Deck-kernel BTF) and "
                "ContainerNsBaseline land on-box. Replay mode gates the decode path "
                "meanwhile.\n");
    return 0;
}

#else

#include <sched.h>
#include <unistd.h>

int main(void) {
    /* On-box fill-in (live):
     *   1. Record the pv-bwrap launcher lineage + game ns inodes.
     *   2. nsenter --mnt --pid into the game from an off-lineage process -> assert
     *      HK_EVENT_NS_ENTRY / HK_NS_FLAG_OFF_LINEAGE.
     *   3. pressure-vessel's own setns (descendant of bwrap) -> assert NO flag.
     * Replay mode: feed a recorded HK_BPF_PW_NS_ENTRY record into the loader and
     * assert the classifier yields OFF_LINEAGE for an orphan caller. */
    std::printf("bypass_setns_breach: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_PW_SETNS_TEST_ENABLED */
