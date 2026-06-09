/*
 * sdk/src/backends/win/SyntheticInputArtifactWin.cpp
 * Role: Signal 63 (win-input-automation). Synthetic-input desktop/journal-artifact
 *       sensor. In the game's OWN LL-hook path, reads GetMessageExtraInfo() and the
 *       KBDLLHOOKSTRUCT.scanCode/flags (and MSLLHOOKSTRUCT): physical HID input
 *       populates a driver-stamped extra-info and a real scan code, while SendInput
 *       with KEYEVENTF_UNICODE or scan-code-less synthesis leaves a gap. Gates to
 *       gameplay context (HK_INFLAG_GAMEPLAY_CONTEXT) and correlates with the
 *       LLMHF_INJECTED baseline rather than acting on extra-info alone (catalog FP:
 *       clipboard paste, IME composition, OSK, Unicode entry, localized layouts all
 *       legitimately produce scan-code-less KEYEVENTF_UNICODE). Treats unknown
 *       extra-info as a SOFT flag fused server-side, never a standalone client verdict.
 * Target platforms: Windows userspace. Guardrail #1: GetMessageExtraInfo / LL-hook
 *       reads confined here; the bitmask folding is the pure fold_synthetic_flags in
 *       InputSensorWin.h (host-tested).
 * Interface: implements hk::sdk::win::sense_synthetic_artifact. Shares the game's own
 *       LL-hook install path with signal 59 (LowLevelHookChainWin.cpp).
 */

#include "InputSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace win {

int sense_synthetic_artifact(std::vector<hk_input_finding>& out)
{
    /* HK-UNCERTAIN(llhook-timeout): this sensor reads the scan-code / extra-info /
     * injected baseline from the SAME game-owned WH_*_LL hook callback as signal 59,
     * so it inherits the same unverified LowLevelHooksTimeout constraint (the callback
     * must do strictly O(1) work and chain promptly, and the re-arm semantics are not
     * confirmed on-box). The hook install is therefore deferred with signal 59 rather
     * than guessed (guardrail #13). The verified per-event folding, once the hook is
     * confirmed safe, is pure and host-tested:
     *
     *   SyntheticArtifactInput sa{};
     *   sa.scancode_zero    = (k->scanCode == 0);          // KEYEVENTF_UNICODE / synthesized
     *   sa.extrainfo_unknown = !known_driver_stamp(GetMessageExtraInfo());
     *   sa.llmhf_injected   = (k->flags & (LLKHF_INJECTED|LLKHF_LOWER_IL_INJECTED)) != 0;
     *   sa.gameplay_context = sdk_in_combat_text_not_expected();
     *   finding.flags = fold_synthetic_flags(sa);          // SOFT flags only
     *   // The verdict is NOT decided here: scan-code/extra-info gaps are fused
     *   // server-side with the gameplay-context + injected baseline. The client
     *   // emits the flags; the server (catalog mandate) decides.
     *   out.push_back(finding);
     *
     * The "known physical driver extra-info stamp" set is NOT enumerable as a fixed
     * list, so extrainfo_unknown is a soft flag, never a standalone verdict. With the
     * LL-hook install deferred (R3), there is no per-event stream to fold this tick. */
    (void)out;
    (void)&fold_synthetic_flags; /* keep the pure core referenced from this TU */
    return 0; /* HK-UNCERTAIN(llhook-timeout): shares signal-59 hook install; deferred */
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
