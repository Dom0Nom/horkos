/*
 * Role: macOS cursor/synthetic-source provenance sensor (catalog signal 170
 *       analog). A LISTEN-ONLY CGEventTap checks the synthetic-source flag
 *       (kCGEventSourceStateID) on mouse-move events to populate the 170 cursor-
 *       confinement features' divergence/source proxy. The tap drops no events and
 *       emits none, so it owes NO EndpointSecurity-style auth reply (guardrail #7
 *       governs the ES SystemExtension, not a passive CG tap) — it lives in the
 *       userspace SDK, not the ES plane (guardrail #4).
 * Target platforms: macOS userspace. Guardrail #1: the CoreGraphics event-tap reads
 *       are confined to this backend.
 * Interface: implements hk::sdk::aim::sample_cursor_confinement from
 *       input/AimSampler.h. Catalog slot 170. Listen-only; never modifies, drops,
 *       or injects an event.
 *
 * HK-UNCERTAIN(macos-tcc-input-monitoring): a passive CGEventTapCreate listen-only
 * tap requires the Accessibility / Input-Monitoring (TCC) grant — NOT the Apple-
 * approved EndpointSecurity entitlement (plan R5). The not-granted path MUST leave
 * the 170 features at default and never crash. The grant-state check + the tap
 * create/run-loop attach are SDK bring-up integration; per guardrail #13 they are
 * not assumed here.
 * (docs: CGEvent.h (CoreGraphics.framework) states that taps at kCGSessionEventTap
 * may only receive key up/down events if Accessibility is enabled; mouse events are
 * less explicit but Apple's privacy framework (TCC) requires Input Monitoring for
 * any event tap since macOS 10.15 — documented at developer.apple.com/documentation/
 * coregraphics/quartz_event_services. kCGEventTapOptionListenOnly is in public SDK.
 * Still needs on-box TCC grant state and AXIsProcessTrusted() check.)
 */

#include "input/AimSampler.h"

#include "platform.h"

#if defined(HK_PLATFORM_MACOS) || defined(__APPLE__)

#import <Foundation/Foundation.h>
#include <stdint.h>

namespace hk { namespace sdk { namespace aim {

bool sample_cursor_confinement(hk_aim_features* out)
{
    if (out == nullptr) {
        return false;
    }

    /* HK-UNCERTAIN(macos-tcc-input-monitoring): no CGEventTap is installed this
     * tick (see file header — docs note appended there). macOS has no
     * GetClipCursor/CURSORINFO analog, so the 170 fields are sourced from the
     * tap's per-event synthetic-source proxy:
     *
     *   CGEventMask mask = CGEventMaskBit(kCGEventMouseMoved)
     *                    | CGEventMaskBit(kCGEventLeftMouseDragged)
     *                    | CGEventMaskBit(kCGEventRightMouseDragged);
     *   CFMachPortRef tap = CGEventTapCreate(
     *       kCGSessionEventTap, kCGTailAppendEventTap,
     *       kCGEventTapOptionListenOnly,    // LISTEN-ONLY: drops/changes nothing
     *       mask, &OnMouseEvent, ctx);
     *   if (!tap) { ... TCC not granted: leave 170 at default, return false ... }
     *   // in OnMouseEvent: a synthesized event reads as kCGEventSourceStateID !=
     *   // kCGEventSourceStateHIDSystemState — that proxy feeds the divergence/
     *   // source signal (see InjectionFlagMac for the R4 caveat on this field's
     *   // cross-version reliability).
     *
     * With no tap, leave clip_rect_ok / cursor_hidden / raw_vs_abs_divergence_px /
     * focus_active at default — the server reads "no 170 sample", never a
     * fabricated disturbance, and an ungranted-TCC box no-ops per R5. */
    (void)out;
    return false; /* no CGEventTap this tick: no 170 sample */
}

} } } // namespace hk::sdk::aim

#endif /* HK_PLATFORM_MACOS || __APPLE__ */
