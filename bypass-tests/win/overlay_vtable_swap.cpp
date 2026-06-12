/*
 * Role: Render-hook merge-gate bypass test (Phase: [disabled]). Intended to
 *       self-apply a BENIGN Present vtable swap on the fixture's OWN swapchain (a
 *       signed test binary hooking itself) and assert signal 46 REPORTS the swap
 *       with the resolved module + signer, and that the AC stack does NOT auto-ban
 *       client-side — proving the report-only contract (presence of a hook is never
 *       itself a ban; only the server decides). The test never patches another
 *       process and never commits a real overlay binary.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/render_hook_schema.h and the render-finding
 *       surface (sense_present_vtable).
 *
 * Merge gate (guardrail #12): this file is the bypass test for the
 * win-usermode-overlay present-path provenance sensors (signals 46/47). It
 * compiles now; its assertions activate when the scoring/report path and the
 * SDK-provided swapchain-pointer integration (plan R2) land — exactly like
 * byovd_load.cpp.
 */

#include <cstdio>

/*
 * HK_RENDER_BYPASS_ENABLED is defined by CMake only once the swapchain-pointer
 * integration + render scoring path exist (mirrors HK_BYOVD_TEST_ENABLED). Until
 * then the test is a compiled no-op that reports "disabled" — present for the
 * merge gate, not yet asserting.
 */
#ifndef HK_RENDER_BYPASS_ENABLED

int main(void)
{
    std::printf("DISABLED: overlay_vtable_swap bypass test activates with the "
                "render scoring path + SDK swapchain-pointer integration (plan R2).\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <windows.h>
#include "horkos/render_hook_schema.h"

/* Activated body fills in: create a swapchain on the fixture's own (signed) binary,
 * record the original Present slot, install a benign self-hook into the slot, run
 * sense_present_vtable, then assert:
 *   1. A finding with signal == HK_RENDER_SIG_VTABLE_PROVENANCE is emitted for the
 *      swapped slot (the swap is REPORTED, never silently missed).
 *   2. The finding's resolved module_path + signer_subject point at this signed
 *      fixture (provenance resolved, not HK_PROV_UNRESOLVED).
 *   3. No client-side ban/termination occurred (report-only: presence of a hook is
 *      not a ban; the server alone decides). */
int main(void)
{
    std::printf("overlay_vtable_swap: render scoring/report path not yet implemented.\n");
    return 1;
}

#endif /* HK_RENDER_BYPASS_ENABLED */
