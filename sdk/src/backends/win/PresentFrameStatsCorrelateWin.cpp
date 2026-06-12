/*
 * Role: Signal 48 (win-usermode-overlay). DXGI frame-statistics drift sensor:
 *       samples IDXGISwapChain::GetFrameStatistics (PresentCount,
 *       PresentRefreshCount, SyncQPCTime, SyncRefreshCount) and GetLastPresentCount
 *       on the tick, correlates against the render-thread QueryPerformanceCounter
 *       timeline, and emits cadence_drift_ns ONLY. The baseline envelope
 *       (per-title, per-GPU-driver, VRR/G-Sync/DLSS-FG aware) lives server-side;
 *       the client never thresholds (plan R4). Read-only.
 * Target platforms: Windows userspace. Guardrail #1: DXGI use confined here.
 * Interface: implements hk::sdk::render::sense_present_framestats.
 */

#include "RenderSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace render {

int sense_present_framestats(std::vector<hk_render_finding>& out)
{
    /* Sequence (read-only, raw drift only):
     *   1. From the SDK-provided IDXGISwapChain* (same R2 acquisition question as
     *      signal 46 — the swapchain pointer is owned by the game and handed to the
     *      SDK), call GetFrameStatistics(&stats).
     *   2. DXGI_ERROR_FRAME_STATISTICS_DISJOINT is the ROUTINE "no clean sample
     *      this tick" return (mode switch / occlusion) — handled as no-sample, NOT
     *      an anomaly. Any other failure => no finding this tick.
     *   3. Correlate stats.SyncQPCTime against the render-thread
     *      QueryPerformanceCounter timeline to derive a signed drift; convert QPC
     *      ticks to ns via QueryPerformanceFrequency.
     *   4. Emit a finding with signal = 48 and cadence_drift_ns = <signed drift>;
     *      all other numeric fields 0. NO thresholding — the per-title/per-driver
     *      VRR/DLSS-FG baseline is server-side (plan R4); a frame-generation user
     *      legitimately desyncs cadence and must not be flagged client-side.
     *
     * Left inert until the SDK-provided swapchain pointer integration (R2) lands;
     * shipping a half-correlation with a client-side threshold would false-positive
     * on frame-generation users, so no drift is emitted without the real baseline
     * plumbing on the server. */
    (void)out;
    return 0;
}

} } } // namespace hk::sdk::render

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
