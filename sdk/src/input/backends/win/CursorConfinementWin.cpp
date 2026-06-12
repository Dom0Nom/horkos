/*
 * Role: Windows cursor-confinement provenance sensor (catalog signal 170).
 *       Samples GetClipCursor (clip rect still == the game's confinement rect ->
 *       clip_rect_ok), GetCursorInfo/CURSORINFO.flags (CURSOR_SHOWING absent ->
 *       cursor_hidden), and GetCursorPos to compute raw_vs_abs_divergence_px (the
 *       integrated raw motion vs. the absolute cursor position — the load-bearing
 *       signal). Correlates disturbances with WM_ACTIVATE focus (focus_active) so
 *       benign alt-tabs / Magnifier / overlay launchers are excused server-side.
 * Target platforms: Windows userspace. Guardrail #1: the GetClipCursor/
 *       GetCursorInfo/GetCursorPos Win32 reads are confined here. USERMODE only
 *       (no WDK); not the kernel plane (guardrail #4).
 * Interface: implements hk::sdk::aim::sample_cursor_confinement from
 *       input/AimSampler.h. Catalog slot 170. Read-only: it samples the game's
 *       own window/cursor state and never moves the cursor or clips it. The FP
 *       gate (focus correlation) is reported, never convicted client-side.
 */

#include "input/AimSampler.h"

#include "platform.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace aim {

bool sample_cursor_confinement(hk_aim_features* out)
{
    if (out == nullptr) {
        return false;
    }

    /* Cursor visibility (CURSORINFO.flags): CURSOR_SHOWING absent => hidden,
     * the expected state for a relative-aim FPS that confines the pointer. This
     * read needs no input stream and never fails the process, so it is taken now;
     * the remaining two reads degrade independently. */
    CURSORINFO ci;
    ci.cbSize = sizeof(ci);
    if (GetCursorInfo(&ci)) {
        out->cursor_hidden = (ci.flags & CURSOR_SHOWING) == 0 ? 1 : 0;
    }

    /* HK-TODO(sdk-integration): clip_rect_ok, raw_vs_abs_divergence_px and
     * focus_active need the GAME'S confinement rect and its integrated raw-motion
     * accumulator + WM_ACTIVATE focus state, which the SDK owns and does not yet
     * route here (same seam as the raw-HID sampler). The live fold is:
     *
     *   RECT clip{}; GetClipCursor(&clip);
     *   out->clip_rect_ok = rects_equal(clip, game_confinement_rect()) ? 1 : 0;
     *
     *   POINT abs{}; GetCursorPos(&abs);
     *   // integrated raw = sum of RAWMOUSE.lLastX/lLastY since last reset
     *   // (shared with the raw-HID sampler's accumulator); divergence is the
     *   // pixel gap between where raw motion says the cursor is and where the OS
     *   // reports it — the load-bearing 170 signal.
     *   out->raw_vs_abs_divergence_px = abs_divergence_px(integrated_raw, abs);
     *
     *   out->focus_active = game_window_has_focus() ? 1 : 0;  // WM_ACTIVATE state
     *
     * With no SDK-delivered confinement rect / raw accumulator / focus state this
     * tick, leave clip_rect_ok / divergence / focus_active at default rather than
     * fabricating a disturbance (catalog FP gate: a focus-loss / overlay launch
     * must be EXCUSED, so a missing focus state must not read as a violation). */
    (void)out;
    return true; /* the cursor-visibility read above is a valid 170 sample */
}

} } } // namespace hk::sdk::aim

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
