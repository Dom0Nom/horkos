/*
 * Role: Signal 50 (win-usermode-overlay). Consumer-side cloaked DWM-thumbnail
 *       screen-mirror sensor. Source-side DwmRegisterThumbnail is NOT enumerable,
 *       so detection is consumer-side correlation: enumerate candidate top-level
 *       windows, check DWMWA_CLOAKED + DwmIsCompositionEnabled, and flag a foreign
 *       cloaked non-shell window whose update cadence tracks the game frame rate
 *       (reported as cadence_drift_ns). The shell/signed-capture-tool filter is
 *       server-side. Read-only.
 * Target platforms: Windows userspace. Guardrail #1: dwmapi/user32 use confined
 *       here.
 * Interface: implements hk::sdk::render::sense_dwm_thumbnail.
 */

#include "RenderSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>
#include <dwmapi.h>

namespace hk { namespace sdk { namespace render {

int sense_dwm_thumbnail(std::vector<hk_render_finding>& out)
{
    /* Sequence (read-only):
     *   1. DwmIsCompositionEnabled() — if composition is off, no DWM mirror is
     *      possible; emit nothing.
     *   2. EnumWindows over visible top-level windows; for each foreign window
     *      (GetWindowThreadProcessId != self), read DWMWA_CLOAKED.
     *   3. A cloaked, foreign, non-shell window is a thumbnail-consumer candidate.
     *      The shell windows (dwm.exe / explorer.exe) and signed capture tools are
     *      NOT filtered client-side — that allow-list is server-side (catalog).
     *   4. Correlate the candidate's update cadence against the game frame timeline
     *      across ticks; emit cadence_drift_ns when it tracks the frame rate. A
     *      single tick cannot establish cadence, so the per-tick sample only
     *      records the candidate; the drift is filled once a multi-tick window
     *      exists.
     *
     * HK-UNCERTAIN(thumbnail-cadence-window): robustly distinguishing a
     * frame-tracking mirror from an ordinary cloaked background window needs a
     * multi-tick cadence baseline whose exact window/statistics model is server-side
     * (plan R4 — mirror cadence is as baseline-sensitive as frame stats). The
     * client must ship raw cadence only; no client-side threshold. Left inert
     * until the server cadence-correlation plumbing lands, to avoid false-positives
     * on legitimate cloaked windows. */
    (void)out;
    return 0;
}

} } } // namespace hk::sdk::render

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
