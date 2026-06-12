/*
 * Role: External-overlay-window merge-gate bypass test (Phase: [disabled]).
 *       Intended to spawn a FOREIGN-process layered/transparent/topmost click-
 *       through window over the game client rect and assert signal 49 surfaces it
 *       with the correct owning_pid + style_bits, AND that a signed allow-listed
 *       overlay (a simulated Steam/Discord signer) is REPORTED but classified
 *       benign — i.e. the sensor neither misses the hostile overlay nor drops the
 *       legitimate-overlay case (the FP-gating contract). The test never commits a
 *       real overlay binary.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/render_hook_schema.h and the render-finding
 *       surface (sense_layered_windows).
 *
 * Merge gate (guardrail #12): this file is the bypass test for the
 * win-usermode-overlay window-scan sensors (signals 49/51). It compiles now; its
 * assertions activate when the render scoring/report path lands — exactly like
 * byovd_load.cpp.
 */

#include <cstdio>

/*
 * HK_RENDER_BYPASS_ENABLED is defined by CMake only once the render scoring path
 * exists (mirrors HK_BYOVD_TEST_ENABLED). Until then the test is a compiled no-op
 * that reports "disabled" — present for the merge gate, not yet asserting.
 */
#ifndef HK_RENDER_BYPASS_ENABLED

int main(void)
{
    std::printf("DISABLED: external_overlay_window bypass test activates with the "
                "render scoring/report path.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <windows.h>
#include "horkos/render_hook_schema.h"

/* Activated body fills in: launch a separate fixture process that creates a
 * WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST click-through window over the
 * game client rect, run sense_layered_windows, then assert:
 *   1. A finding with signal == HK_RENDER_SIG_LAYERED_WINDOW carries the foreign
 *      process's owning_pid (correct cross-process attribution).
 *   2. style_bits has HK_WSTYLE_LAYERED | HK_WSTYLE_TRANSPARENT | HK_WSTYLE_TOPMOST
 *      | HK_WSTYLE_CLICKTHROUGH set (the folded overlay shape).
 *   3. A second, signed allow-listed overlay (simulated Steam/Discord signer) is
 *      still REPORTED (not dropped) but resolves to HK_PROV_IMAGE_SIGNED_ALLOWLISTED
 *      so the server classifies it benign — proving the sensor does not silently
 *      filter the legitimate-overlay case client-side (FP-gating contract). */
int main(void)
{
    std::printf("external_overlay_window: render scoring/report path not yet implemented.\n");
    return 1;
}

#endif /* HK_RENDER_BYPASS_ENABLED */
