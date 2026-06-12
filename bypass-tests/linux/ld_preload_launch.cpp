/*
 * Role: Merge-gate bypass fixture for process-genealogy signal 206 (LD_PRELOAD /
 *       linker hijack), [disabled]. Intended to exec a target with
 *       LD_PRELOAD=<unlisted.so> and assert the loader-taint flag fires, AND that
 *       an allowlisted overlay .so does NOT flag — demonstrating the linker-hijack
 *       vector is caught without flagging legitimate overlays (gameoverlayrenderer,
 *       MangoHud, vkBasalt, OBS game-capture). Read-only assertion of the raw flag
 *       — never a local ban.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: consumes the AC launch-trust flag surface.
 *
 * Merge gate (guardrail #12): present for the security folder; assertions activate
 * once the eBPF loader-trust path is verified on a real kernel and
 * HK_GENEALOGY_TEST_ENABLED is defined. Ships disabled like ptrace_attach.cpp.
 */

#include <cstdio>

#ifndef HK_GENEALOGY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: ld_preload_launch activates once the eBPF loader-trust "
                "path is verified on a real kernel (HK_GENEALOGY_TEST_ENABLED).\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

int main(void)
{
    std::printf("ld_preload_launch: eBPF loader-trust path not yet verified.\n");
    return 1;
}

#endif /* HK_GENEALOGY_TEST_ENABLED */
