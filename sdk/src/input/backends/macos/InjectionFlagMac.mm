/*
 * sdk/src/input/backends/macos/InjectionFlagMac.mm
 * Role: macOS OS-injection-source aim sensor (catalog signal 171). Over the same
 *       listen-only CGEventTap as the 170 sensor, distinguishes hardware vs.
 *       CGEventPost-synthesized mouse motion via CGEventGetIntegerValueField
 *       (kCGMouseEventSubtype / kCGEventSourceStateID) and emits the injected
 *       fraction (injected_event_fraction_q8, Q0.8). KVM/streaming (Parsec, Steam
 *       Remote Play), remappers and Steam Input set the synthesized source — this
 *       SEGREGATES COHORTS, it does not convict (catalog high-FP gate).
 * Target platforms: macOS userspace. Guardrail #1: the CoreGraphics source-field
 *       reads are confined to this backend. Guardrail #4/#7: passive CG tap,
 *       userspace, no ES auth reply owed.
 * Interface: implements hk::sdk::aim::sample_injection_flag from
 *       input/AimSampler.h. Catalog slot 171.
 *
 * HK-UNCERTAIN(macos-cg-injection-source): whether
 * CGEventGetIntegerValueField(kCGMouseEventSubtype) and kCGEventSourceStateID
 * RELIABLY distinguish hardware vs. CGEventPost-synthesized mouse motion across
 * macOS versions — and whether all synthetic paths set a stable, queryable source
 * state — is NOT something I am certain of (plan R4). Per guardrail #13 the bit is
 * not relied upon here: the field-read shape is documented but no tap is wired, and
 * the macOS injected fraction is treated as best-effort, leaving the cross-platform
 * Windows/Linux 171 signals to carry the weight. Also gated by the same TCC grant
 * as the 170/163 macOS sensors (plan R5) — ungranted leaves the fraction at default.
 * (docs: kCGEventSourceStateID (field 45) and kCGEventSourceStateHIDSystemState (1)
 * ARE in the public SDK (CoreGraphics/CGEventTypes.h). kCGMouseEventSubtype (field 7)
 * is also public. CGEventSource.h documents that kCGEventSourceStateHIDSystemState
 * reflects hardware event sources. The RELIABILITY of these fields for distinguishing
 * synthesized events across all CGEventPost paths on macOS 12-15 remains unconfirmed —
 * still needs on-box testing; also blocked by TCC Input Monitoring grant (R5))
 */

#include "input/AimSampler.h"

#include "platform.h"

#if defined(HK_PLATFORM_MACOS) || defined(__APPLE__)

#import <Foundation/Foundation.h>
#include <stdint.h>

namespace hk { namespace sdk { namespace aim {

bool sample_injection_flag(hk_aim_features* out)
{
    if (out == nullptr) {
        return false;
    }

    /* HK-UNCERTAIN(macos-cg-injection-source): no CGEventTap is wired and the
     * source-state bit's cross-version reliability is unconfirmed (see header —
     * docs note appended there).
     * The live fold, once the tap is installed and the field semantics are
     * confirmed on the target macOS:
     *
     *   // in the listen-only mouse-move callback, per aim event:
     *   //   int64_t srcState = CGEventGetIntegerValueField(ev,
     *   //                          kCGEventSourceStateID);
     *   //   bool synth = (srcState != kCGEventSourceStateHIDSystemState);
     *   //   ++g_aim_event_count; if (synth) ++g_aim_injected_count;
     *   uint32_t total    = take_and_reset(g_aim_event_count);
     *   uint32_t injected = take_and_reset(g_aim_injected_count);
     *   if (total > 0) {
     *       uint32_t q8 = (injected * 256u + total / 2u) / total;
     *       out->injected_event_fraction_q8 = (uint16_t)(q8 > 255u ? 255u : q8);
     *   }
     *
     * With no tap / unconfirmed semantics, leave injected_event_fraction_q8 at
     * default — best-effort on macOS per R4; the server reads no macOS injection
     * signal rather than a fabricated fraction. virtual_device_present is the
     * Linux uinput analog and is not a macOS signal here. */
    (void)out;
    return false; /* no CG source-state sample this tick (R4/R5) */
}

} } } // namespace hk::sdk::aim

#endif /* HK_PLATFORM_MACOS || __APPLE__ */
