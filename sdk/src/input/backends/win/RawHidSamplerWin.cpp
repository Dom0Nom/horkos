/*
 * sdk/src/input/backends/win/RawHidSamplerWin.cpp
 * Role: Windows raw-HID aim sampler (catalog signals 163/164/165). Drains the
 *       GAME'S OWN raw-input sink (RegisterRawInputDevices RIDEV_INPUTSINK +
 *       GetRawInputData reading RAWMOUSE.lLastX/lLastY) into platform-free
 *       hk_hid_sample records, each stamped with QueryPerformanceCounter. The
 *       platform-neutral AimAccumulator.fold_tick then derives the 163 provenance
 *       deltas, the 165 inter-arrival moments, and the 171 injected fraction. The
 *       quantization scalar/applied angle (164) and the engine-state fields
 *       (166-169) are supplied by the SDK tick from the game's own state, not here.
 * Target platforms: Windows userspace. Guardrail #1: all Win32 raw-input + QPC is
 *       confined to this backend; the fold/decision is platform-free in
 *       AimAccumulator.cpp / aim_kinematics.rs (host-tested). USERMODE only (no
 *       WDK, no driver) — this is the SDK input thread, not the kernel plane
 *       (guardrail #4).
 * Interface: implements hk::sdk::aim::sample_raw_hid from input/AimSampler.h.
 *       Reads only the game's own raw-input sink; never injects, never hooks a
 *       foreign process. Catalog slots 163/164/165.
 */

#include "input/AimSampler.h"

#include "platform.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace aim {

uint32_t sample_raw_hid(hk_hid_sample* samples, uint32_t cap)
{
    if (samples == nullptr || cap == 0) {
        return 0;
    }

    /* HK-TODO(sdk-integration): the per-report RAWMOUSE counts come from the
     * game's OWN WM_INPUT handler, which the SDK does not yet route into the
     * sensors (the same integration seam RawInputProvenanceWin.cpp documents for
     * signal 55, and the render present-path sensors document for their stream).
     * Once the SDK delivers each WM_INPUT message, the per-message drain is:
     *
     *   UINT size = 0;
     *   // size query first, then data — sized correctly so the input thread does
     *   // O(1) work and never blocks (plan §163 concern):
     *   if (GetRawInputData(hRaw, RID_INPUT, nullptr, &size,
     *                       sizeof(RAWINPUTHEADER)) != 0) return written;
     *   // (caller owns a reused stack/scratch buffer of `size` bytes)
     *   if (GetRawInputData(hRaw, RID_INPUT, buf, &size,
     *                       sizeof(RAWINPUTHEADER)) != size) return written;
     *   const RAWINPUT* ri = reinterpret_cast<const RAWINPUT*>(buf);
     *   if (ri->header.dwType == RIM_TYPEMOUSE &&
     *       (ri->data.mouse.usFlags & MOUSE_MOVE_ABSOLUTE) == 0) {  // relative HID
     *       LARGE_INTEGER qpc; QueryPerformanceCounter(&qpc);
     *       samples[written].raw_dx   = ri->data.mouse.lLastX;
     *       samples[written].raw_dy   = ri->data.mouse.lLastY;
     *       samples[written].ts_ns    = qpc_to_ns(qpc);   // QPC / QPF -> ns
     *       samples[written].injected = 0;  // 171 sets this from MSLLHOOKSTRUCT.flags
     *       ++written;
     *   }
     *
     * The RIDEV_INPUTSINK registration is the GAME'S sink (RegisterRawInputDevices
     * for usage page 0x01 usage 0x02, mouse), shared with the input-provenance
     * sensors — not re-registered here. With no SDK-delivered WM_INPUT stream this
     * tick there is nothing to drain: write nothing rather than fabricating a
     * report (catalog FP gate — a zero-count tick is a true "no HID", not an
     * anomaly). */
    (void)samples;
    (void)cap;
    return 0; /* no SDK-delivered WM_INPUT stream this tick: nothing drained */
}

} } } // namespace hk::sdk::aim

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
