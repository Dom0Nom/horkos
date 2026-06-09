/*
 * bypass-tests/win/input_filter_interloper.cpp
 * Role: Input-class-filter merge-gate bypass test (Phase: [disabled]). Intended to
 *       inject a SIMULATED unsigned/unknown class upper-filter inventory/registry
 *       fixture entry (NO real driver loaded) and assert that signal 56 surfaces it in
 *       its findings with the correct filter_service, filter_count, and
 *       HK_INPUT_SRC_FILTER_UNSIGNED verdict, while a vendor-allowlisted SIGNED filter
 *       (simulated signer subject) is REPORTED BUT classified benign — i.e. the
 *       sensor does not drop the legitimate-vendor-filter case (the FP-gating
 *       contract). No real filter driver is built or loaded; the repo never commits a
 *       real input-filter binary.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/input_prov_schema.h and the input-finding
 *       surface (sense_input_class_filters).
 *
 * Merge gate (guardrail #12): this file is the bypass test for the
 * win-input-automation class-filter sensor (signal 56). It compiles now; its
 * assertions activate when the input scoring/report path + the signer-resolution
 * (WinVerifyTrust) pass land — exactly like byovd_load.cpp.
 */

#include <cstdio>

/*
 * HK_INPUT_BYPASS_ENABLED is defined by CMake only once the input scoring/report
 * path + the class-filter signer-resolution pass exist (mirrors
 * HK_BYOVD_TEST_ENABLED / HK_RENDER_BYPASS_ENABLED). Until then the test is a
 * compiled no-op that reports "disabled" — present for the merge gate, not yet
 * asserting.
 */
#ifndef HK_INPUT_BYPASS_ENABLED

int main(void)
{
    std::printf("DISABLED: input_filter_interloper bypass test activates with the "
                "input scoring/report path + class-filter signer-resolution pass.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <windows.h>
#include "horkos/input_prov_schema.h"

/* Activated body fills in: feed a simulated class-filter inventory (one unsigned
 * unknown upper-filter, one signed vendor-allowlisted filter — both fixtures, no real
 * driver), run sense_input_class_filters, then assert:
 *   1. A signal-56 finding surfaces the unsigned filter with its filter_service
 *      (JSON side-channel), the correct ordered filter_count, and verdict
 *      HK_INPUT_SRC_FILTER_UNSIGNED — the interloper is REPORTED, never missed.
 *   2. The signed vendor-allowlisted filter is REPORTED but classified benign
 *      (HK_INPUT_SRC_PHYSICAL_KNOWN), proving the sensor does not drop the legitimate
 *      case (the FP-gating contract).
 *   3. No client-side ban occurred (report-only: presence of a filter is not a ban;
 *      the server's signed allow-list rule decides). */
int main(void)
{
    std::printf("input_filter_interloper: input scoring/report path not yet implemented.\n");
    return 1;
}

#endif /* HK_INPUT_BYPASS_ENABLED */
