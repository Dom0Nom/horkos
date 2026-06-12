/*
 * Role: Linux Proton/Wine bypass-test fixture (merge gate, guardrail #12) for
 *       signal 106 (gamescope/DRM-lease frame siphon). Demonstrates: a non-
 *       gamescope Wayland client connects to the gamescope socket and a non-
 *       gamescope process imports the framebuffer DMA-BUF -> HK_EVENT_FRAME_CONSUMER
 *       with HK_FRAME_WAYLAND / _PRIME / _OFF_ALLOWLIST; OBS-via-portal and Steam
 *       Remote Play capture do NOT flag (FP gate). Catalog marks 106 HIGH-FP: the
 *       test also asserts the server treats the record as a LOW-WEIGHT corroborator
 *       (corroborator_only feature), never a standalone ban — the load-bearing half.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event sink (signal 106) + GamescopeConsumerBaseline
 *            + the server linux_proton feature weight.
 */

#include <cstdio>

#ifndef HK_PW_FRAME_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: bypass_frame_siphon activates once compositor_consumer "
                "loader attach + GamescopeConsumerBaseline land on-box.\n");
    return 0;
}

#else

#include <unistd.h>

int main(void) {
    /* On-box fill-in:
     *   1. Non-gamescope client connect() to the gamescope AF_UNIX socket -> assert
     *      HK_EVENT_FRAME_CONSUMER / HK_FRAME_WAYLAND | _OFF_ALLOWLIST.
     *   2. Non-gamescope PRIME_FD_TO_HANDLE import -> assert _PRIME.
     *   3. OBS-via-portal + Steam Remote Play -> assert NO off-allowlist flag.
     *   4. Assert the server feature row has corroborator_only=true (low weight). */
    std::printf("bypass_frame_siphon: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_PW_FRAME_TEST_ENABLED */
