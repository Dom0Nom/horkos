/*
 * sdk/src/input/backends/win/InjectionFlagWin.cpp
 * Role: Windows OS-injection-bit aim sensor (catalog signal 171). Over the GAME'S
 *       OWN low-level mouse hook (WH_MOUSE_LL), reads MSLLHOOKSTRUCT.flags
 *       (LLMHF_INJECTED / LLMHF_LOWER_IL_INJECTED) per aim-moving event and emits
 *       the injected fraction (injected_event_fraction_q8, Q0.8). Remappers,
 *       on-screen keyboards, KVM/streaming and Steam Input all set the injected
 *       bit; this SEGREGATES COHORTS, it does not convict — the client ships the
 *       fraction graded and the server decides (catalog high-FP gate).
 * Target platforms: Windows userspace. Guardrail #1: the WH_MOUSE_LL Win32 path is
 *       confined here. USERMODE only (no WDK); not the kernel plane (guardrail #4).
 * Interface: implements hk::sdk::aim::sample_injection_flag from
 *       input/AimSampler.h. Catalog slot 171. Observes only the game's own input
 *       stream; never injects.
 *
 * HK-UNCERTAIN(ll-hook-timeout): a WH_MOUSE_LL callback runs under the system
 * LowLevelHooksTimeout (HKLM\Control Panel\Desktop, commonly cited ~300 ms), after
 * which Windows SILENTLY REMOVES the hook and may stop calling it. I am NOT certain
 * of the exact current-OS timeout semantics, nor whether a timed-out hook is
 * re-armed automatically or simply dropped (and thus whether a re-install watchdog
 * is required). Per guardrail #13 this is NOT guessed: the hook INSTALL and the
 * re-arm watchdog are left unimplemented below; the callback body that reads
 * MSLLHOOKSTRUCT.flags is written O(1) and CallNextHookEx-prompt as a documented
 * shape, but it is never wired to a live SetWindowsHookEx here. Confirm the
 * documented LowLevelHooksTimeout behaviour and the re-arm strategy on-box before
 * installing the hook. (Usermode, not a BSOD risk — a detection-validity
 * uncertainty; same as win-input-automation.md R3.)
 */

#include "input/AimSampler.h"

#include "platform.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace aim {

/*
 * Documented callback SHAPE for the live wiring (NOT installed here — see the
 * HK-UNCERTAIN note). It must do strictly O(1) work and CallNextHookEx promptly
 * or Windows removes the hook under LowLevelHooksTimeout. It only READS the
 * injected bit into a lock-free per-tick counter pair owned by the SDK; it must
 * never block, allocate, or take a lock.
 *
 *   LRESULT CALLBACK LowLevelMouseProc(int code, WPARAM wp, LPARAM lp) {
 *       if (code == HC_ACTION) {
 *           const MSLLHOOKSTRUCT* ms = reinterpret_cast<const MSLLHOOKSTRUCT*>(lp);
 *           if (wp == WM_MOUSEMOVE) {                 // aim-moving events only
 *               ++g_aim_event_count;                  // atomic, relaxed
 *               if (ms->flags & (LLMHF_INJECTED | LLMHF_LOWER_IL_INJECTED))
 *                   ++g_aim_injected_count;           // atomic, relaxed
 *           }
 *       }
 *       return CallNextHookEx(nullptr, code, wp, lp); // prompt, unconditional
 *   }
 *
 * sample_injection_flag() below then folds those two counters into the Q0.8
 * fraction per tick and resets them. Until the hook is installed (pending the
 * timeout confirmation) the counters never advance and the fraction stays 0.
 */

bool sample_injection_flag(hk_aim_features* out)
{
    if (out == nullptr) {
        return false;
    }

    /* HK-UNCERTAIN(ll-hook-timeout): the WH_MOUSE_LL hook is not installed (see
     * file header). With no live per-event injected/total counters this tick,
     * leave injected_event_fraction_q8 at its 0 default — the server reads "no
     * injection signal", never a fabricated fraction.
     *
     * The live fold, once the hook is safely armed:
     *   uint32_t total    = g_aim_event_count.exchange(0, relaxed);
     *   uint32_t injected = g_aim_injected_count.exchange(0, relaxed);
     *   if (total > 0) {
     *       uint32_t q8 = (injected * 256u + total / 2u) / total;
     *       out->injected_event_fraction_q8 = (uint16_t)(q8 > 255u ? 255u : q8);
     *   }
     * (virtual_device_present is the cross-platform analog filled by the Linux
     *  uinput / macOS source-state backends; on Windows the injected bit carries
     *  171, so it is left at default here.) */
    (void)out;
    return false; /* hook not armed: no 171 sample this tick */
}

} } } // namespace hk::sdk::aim

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
