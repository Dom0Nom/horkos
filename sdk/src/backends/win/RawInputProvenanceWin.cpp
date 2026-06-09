/*
 * sdk/src/backends/win/RawInputProvenanceWin.cpp
 * Role: Signal 55 (win-input-automation). Raw-input source-handle correlation-gap
 *       sensor. For each WM_INPUT the game receives, reads RAWINPUTHEADER.hDevice
 *       and reconciles it against the shared inventory: counts NULL-hDevice and
 *       unknown-hDevice events and reports the RATIO over a window (catalog mandate:
 *       report the ratio, never a single event). Gates NULL-hDevice as benign when
 *       an approved accessibility/remote-session flag is set (OSK, Steam Input, AHK
 *       remappers, RDP/VNC legitimately produce NULL hDevice — plan R7).
 * Target platforms: Windows userspace. Guardrail #1: raw-input + session Win32
 *       confined here. The verdict + ratio logic is the pure classify_input_source /
 *       ratio_window_reportable in InputSensorWin.h (host-tested).
 * Interface: implements hk::sdk::win::sense_rawinput_provenance.
 */

#include "InputSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace win {

int sense_rawinput_provenance(const RawInputInventory& inv,
                              std::vector<hk_input_finding>& out)
{
    /* The accessibility/remote-session gate is resolvable now without any input
     * stream — it is a process/session property. We read it up front so the ratio
     * folding below classifies a NULL/unknown window correctly the moment the live
     * WM_INPUT stream is wired in. */
    const bool remote_session = GetSystemMetrics(SM_REMOTESESSION) != 0;

    /* HK-TODO(sdk-integration): the per-event NULL/unknown-hDevice counts come from
     * the game's OWN WM_INPUT handler, which the SDK does not yet route into the
     * sensors (the same integration seam the render present-path sensors document).
     * Once the SDK delivers each WM_INPUT's RAWINPUTHEADER.hDevice, the folding is:
     *
     *   RatioWindow w{};                       // per hDevice-class window
     *   for each WM_INPUT this window:
     *       ++w.event_count;
     *       hDevice == NULL        -> flags |= HK_INFLAG_HDEVICE_NULL, ++w.anomaly_count
     *       hDevice not in `inv`   -> flags |= HK_INFLAG_HDEVICE_UNKNOWN, ++w.anomaly_count
     *   if (ratio_window_reportable(w, kMinEvents)) {
     *       InputSourceInput si{};
     *       si.hdevice_null/hdevice_unknown = ...;
     *       si.accessibility_gate = remote_session || approved_accessibility;
     *       finding.verdict = classify_input_source(si);
     *       finding.event_count = w.event_count; finding.anomaly_count = w.anomaly_count;
     *       out.push_back(finding);            // server scores the ratio; client never bans
     *   }
     *
     * With no live WM_INPUT stream this tick, there is nothing to reconcile: emit
     * nothing rather than fabricating a window (catalog FP gate). */
    (void)inv;
    (void)remote_session;
    (void)out;
    return 0; /* no SDK-delivered WM_INPUT stream this tick: nothing observed */
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
