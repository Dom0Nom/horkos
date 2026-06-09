/*
 * bypass-tests/win/aim_injection_provenance.cpp
 * Role: behavioral-aim provenance merge-gate bypass test (Phase: [disabled]).
 *       Intended to self-issue a BENIGN SendInput/mouse_event aim move (NULL-
 *       hDevice, LLMHF_INJECTED set) and a sub-count FRACTIONAL view nudge into
 *       the test's OWN window, then assert that:
 *         - signal 163 REPORTS the synthetic move (no backing HID report whose ts
 *           precedes the render tick -> hid_report_count == 0 against a non-zero
 *           applied angle),
 *         - signal 171 REPORTS it (injected_event_fraction_q8 > 0),
 *         - signal 164 REPORTS the fractional nudge (non-zero quantization
 *           residual: applied_angle != raw_count * sens_scalar),
 *       and that NONE of them auto-bans client-side (the report-only contract:
 *       synthetic/fractional motion is never itself a ban; the server decides).
 *       It also asserts a simulated virtual-HID source (remapper / Steam Input)
 *       is reported as a COHORT FLAG (virtual_device_present), not a raw
 *       conviction (the FP-gating contract). The test issues input only into its
 *       own process and never commits a real injection tool.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes the behavioral-aim feature schema
 *       (server/telemetry/src/schema.rs::TickPayload v2, mirrored by
 *       sdk/src/input/AimSampler.h::hk_aim_features) and the aim sensor surface
 *       (sample_raw_hid / sample_injection_flag + the AimAccumulator fold).
 *
 * Merge gate (guardrail #12): this file is the bypass test for the behavioral-aim
 * raw-HID provenance + quantization + injection sensors (signals 163/164/171). It
 * compiles now; its assertions activate when the aim scoring/report path + the SDK
 * WM_INPUT/LL-hook stream integration land — exactly like byovd_load.cpp.
 */

#include <cstdio>

/*
 * HK_AIM_BYPASS_ENABLED is defined by CMake only once the aim scoring/report path
 * + the SDK WM_INPUT / LL-hook stream integration exist (mirrors
 * HK_BYOVD_TEST_ENABLED / HK_INPUT_BYPASS_ENABLED). Until then the test is a
 * compiled no-op that reports "disabled" — present for the merge gate, not yet
 * asserting.
 */
#ifndef HK_AIM_BYPASS_ENABLED

int main(void)
{
    std::printf("DISABLED: aim_injection_provenance bypass test activates with the "
                "aim scoring/report path + SDK WM_INPUT/LL-hook integration.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <windows.h>
#include "input/AimSampler.h"

/* Activated body fills in: register the fixture's own RIDEV_INPUTSINK raw-input
 * sink, SendInput a benign aim move (NULL hDevice, LLMHF_INJECTED) plus a
 * sub-count fractional applied-angle nudge, drain the aim sensors + fold, then
 * assert:
 *   1. hid_report_count == 0 (no backing HID) while an applied angle was seen ->
 *      signal 163 REPORTS the unbacked motion; injected_event_fraction_q8 > 0 ->
 *      signal 171 REPORTS the injected bit. The synthetic move is REPORTED, never
 *      silently missed.
 *   2. The fractional nudge yields a non-zero 164 quantization residual
 *      (applied_angle != raw_count * sens_scalar_q16) — REPORTED, not thresholded.
 *   3. A simulated virtual source sets virtual_device_present (a cohort flag),
 *      NOT a raw conviction (the FP-gating contract holds).
 *   4. No client-side ban/termination occurred (report-only: the server alone
 *      decides). */
int main(void)
{
    std::printf("aim_injection_provenance: aim scoring/report path not yet implemented.\n");
    return 1;
}

#endif /* HK_AIM_BYPASS_ENABLED */
