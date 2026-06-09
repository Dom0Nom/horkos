/*
 * sdk/src/backends/win/LowLevelHookChainWin.cpp
 * Role: Signal 59 (win-input-automation). Low-level-hook chain-participation sensor.
 *       Installs the GAME's OWN WH_MOUSE_LL / WH_KEYBOARD_LL hooks and measures the
 *       call-out delay around CallNextHookEx (a foreign hook earlier in the chain
 *       adds measurable per-event latency) -> llhook_latency_ns, plus the
 *       MSLLHOOKSTRUCT/KBDLLHOOKSTRUCT injected-flag baseline (LLMHF_INJECTED /
 *       LLMHF_LOWER_IL_INJECTED). Observes ONLY the game's own input stream — it
 *       installs its own hook, never hooks a foreign process and never unhooks one.
 *       A verdict is reported only when the foreign hook owner is unsigned/unknown;
 *       Discord/Steam/GeForce overlays, OBS, push-to-talk, AHK legitimately install
 *       LL hooks, so the signed-module allow-list join is server-side (catalog).
 * Target platforms: Windows userspace. Guardrail #1: SetWindowsHookEx /
 *       CallNextHookEx confined here.
 * Interface: implements hk::sdk::win::sense_llhook_chain.
 */

#include "InputSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace win {

int sense_llhook_chain(std::vector<hk_input_finding>& out)
{
    /* HK-UNCERTAIN(llhook-timeout): a WH_*_LL hook callback runs under a system
     * timeout (HKLM\Control Panel\Desktop\LowLevelHooksTimeout, commonly cited
     * default ~300 ms) after which Windows silently removes the hook and may stop
     * calling it. Two things are NOT verified on-box and must NOT be guessed
     * (guardrail #13):
     *   1. The exact current-OS timeout semantics and whether a removed hook is
     *      re-armed or simply dropped — the re-arm strategy (re-Set on WM input or on
     *      a watchdog) depends on this.
     *   2. Whether the llhook_latency_ns measurement (QueryPerformanceCounter
     *      before/after CallNextHookEx) is itself slow enough to TRIGGER the removal
     *      it is trying to observe — i.e. the measurement must fit inside the budget.
     * Until both are confirmed on a real box, this sensor neither installs the hook
     * nor measures latency. The verified callback shape, once confirmed, is:
     *
     *   LRESULT CALLBACK LowLevelKbd(int code, WPARAM w, LPARAM l) {
     *       if (code == HC_ACTION) {
     *           const KBDLLHOOKSTRUCT* k = (const KBDLLHOOKSTRUCT*)l;
     *           // O(1) ONLY: read k->flags injected baseline, stamp a QPC sample.
     *           injected_baseline |= (k->flags & (LLKHF_INJECTED|LLKHF_LOWER_IL_INJECTED));
     *       }
     *       LARGE_INTEGER a; QueryPerformanceCounter(&a);
     *       LRESULT r = CallNextHookEx(nullptr, code, w, l);  // chain promptly
     *       LARGE_INTEGER b; QueryPerformanceCounter(&b);
     *       record_latency(b.QuadPart - a.QuadPart);          // accumulate, no work here
     *       return r;
     *   }
     *
     * The owner correlation (foreign hook earlier in the chain) joins against the
     * already-implemented module inventory from the kernel PsSetLoadImageNotifyRoutine
     * path via the existing AC module surface — no new kernel coupling. That join +
     * the signed allow-list are server-side; the client reports llhook_latency_ns +
     * the LLMHF_INJECTED baseline only. */
    (void)out;
    return 0; /* HK-UNCERTAIN(llhook-timeout): hook install/latency deferred pending on-box verification */
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
