/*
 * bypass-tests/win/synthetic_input_provenance.cpp
 * Role: Input-provenance merge-gate bypass test (Phase: [disabled]). Intended to
 *       self-issue a BENIGN SendInput burst (including a KEYEVENTF_UNICODE event)
 *       into the test's OWN window and assert that signals 55 and 63 REPORT it with
 *       HK_INFLAG_HDEVICE_NULL / HK_INFLAG_NO_SCANCODE and the resolved verdict, and
 *       that the AC stack does NOT auto-ban client-side — proving the report-only
 *       contract (a synthetic event is never itself a ban; the server decides). It
 *       also asserts that a SendInput while a simulated accessibility/remote-session
 *       flag is set is reported as HK_INPUT_SRC_ACCESSIBILITY_GATED, not raw SYNTHETIC
 *       (the FP-gating contract). The test issues input only into its own process and
 *       never commits a real injection tool.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/input_prov_schema.h and the input-finding
 *       surface (sense_rawinput_provenance / sense_synthetic_artifact).
 *
 * Merge gate (guardrail #12): this file is the bypass test for the
 * win-input-automation raw-input/synthetic-artifact sensors (signals 55/63). It
 * compiles now; its assertions activate when the input scoring/report path + SDK
 * WM_INPUT/LL-hook stream integration land — exactly like byovd_load.cpp.
 */

#include <cstdio>

/*
 * HK_INPUT_BYPASS_ENABLED is defined by CMake only once the input scoring/report
 * path + the SDK WM_INPUT / LL-hook stream integration exist (mirrors
 * HK_BYOVD_TEST_ENABLED / HK_RENDER_BYPASS_ENABLED). Until then the test is a
 * compiled no-op that reports "disabled" — present for the merge gate, not yet
 * asserting.
 */
#ifndef HK_INPUT_BYPASS_ENABLED

int main(void)
{
    std::printf("DISABLED: synthetic_input_provenance bypass test activates with the "
                "input scoring/report path + SDK WM_INPUT/LL-hook integration.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <windows.h>
#include "horkos/input_prov_schema.h"

/* Activated body fills in: register the fixture's own RIDEV_INPUTSINK raw-input sink,
 * SendInput a benign burst (one KEYEVENTF_UNICODE event), pump WM_INPUT, run
 * sense_rawinput_provenance + sense_synthetic_artifact, then assert:
 *   1. A signal-55 finding reports HK_INFLAG_HDEVICE_NULL with a ratio (event_count /
 *      anomaly_count), and a signal-63 finding reports HK_INFLAG_NO_SCANCODE — the
 *      synthetic input is REPORTED, never silently missed.
 *   2. With NO accessibility/remote flag, the verdict is HK_INPUT_SRC_SYNTHETIC;
 *      with a simulated SM_REMOTESESSION / accessibility flag set, the SAME burst is
 *      reported as HK_INPUT_SRC_ACCESSIBILITY_GATED (the FP-gating contract holds).
 *   3. No client-side ban/termination occurred (report-only: a synthetic event is not
 *      a ban; the server alone decides). */
int main(void)
{
    std::printf("synthetic_input_provenance: input scoring/report path not yet implemented.\n");
    return 1;
}

#endif /* HK_INPUT_BYPASS_ENABLED */
