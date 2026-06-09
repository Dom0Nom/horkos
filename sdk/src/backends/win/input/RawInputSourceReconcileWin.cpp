/*
 * sdk/src/backends/win/input/RawInputSourceReconcileWin.cpp
 * Role: Signal 138 — raw-input source-handle reconciliation sensor (device-trust
 *       framing of sibling signal 55). For each WM_INPUT, the RAWINPUTHEADER.hDevice
 *       is reconciled against the enumerated raw-input inventory
 *       (GetRawInputDeviceList + RIDI_DEVICENAME, built by the sibling
 *       RawInputInventoryWin). A NULL/unknown source is GATED by
 *       WTSGetActiveConsoleSessionId + the remote-session flag + the process-context
 *       tag before classification (HK_INPUT_SRC_ACCESSIBILITY_GATED vs _SYNTHETIC), so
 *       RDP/Parsec/Moonlight/on-screen-keyboard resolve to the gated verdict.
 * Target platforms: Windows userspace.
 * Interface: implements hk::sdk::win::sense_rawinput_reconcile from
 *       input/DeviceTrustWin.h; reuses the sibling RawInputInventory + hk_input_finding
 *       (input_prov_schema.h) and the pure classify_input_source core
 *       (InputSensorWin.h). Pairs with win-input-automation 55.
 */

#include "InputSensorWin.h"      /* RawInputInventory, classify_input_source, ratios */
#include "input/DeviceTrustWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>
#include <wtsapi32.h>

#include <vector>

namespace hk { namespace sdk { namespace win {

namespace {

/* True when the active session is remote (RDP) — a NULL/absolute source is then a
 * legitimate remote-desktop injection and resolves to the gated verdict, not
 * synthetic. GetSystemMetrics(SM_REMOTESESSION) is the documented test. */
bool IsRemoteSession()
{
    return GetSystemMetrics(SM_REMOTESESSION) != 0;
}

} // namespace

int sense_rawinput_reconcile(std::vector<hk_input_finding> &out)
{
    /* Build/refresh the shared inventory (the sibling owns the canonical instance; for
     * a standalone tick we rebuild it read-only). On enumeration failure the whole
     * window is UNRESOLVED — never a fabricated synthetic finding. */
    RawInputInventory inv;
    if (!build_rawinput_inventory(inv)) {
        hk_input_finding rec{};
        rec.schema_version = HK_INPUT_SCHEMA_VERSION;
        rec.signal = HK_INPUT_SIG_RAWINPUT_PROVENANCE; /* 55: 138 reuses the 55 record */
        rec.verdict = HK_INPUT_SRC_UNRESOLVED;
        out.push_back(rec);
        return 1;
    }

    /* HK-UNCERTAIN(wm_input-stream-join): the per-WM_INPUT hDevice reconciliation needs
     * the SDK's live WM_INPUT message stream (the game's own RIDEV_INPUTSINK sink),
     * which is integrated by the sibling win-input-automation SDK tick, not present in
     * this scaffolding TU. Until that stream is wired, this sensor classifies the
     * window-level facts it CAN resolve (remote-session gate) and leaves the per-event
     * NULL/unknown-hDevice ratio to the join. Per guardrail #13 the live message-pump
     * join is left a stub; the on-box implementer feeds the WM_INPUT headers here.
     *
     * The classifier below is the testable decision core; the host unit test drives it
     * with synthetic InputSourceInput facts (no live WM_INPUT). */
    const bool remote = IsRemoteSession();

    InputSourceInput facts{};
    facts.query_failed = false;
    facts.hdevice_null = false;       /* set per-event by the WM_INPUT join */
    facts.hdevice_unknown = false;    /* set per-event by the WM_INPUT join */
    facts.accessibility_gate = remote; /* remote session is an approved gate */

    const hk_input_verdict verdict = classify_input_source(facts);
    (void)verdict; /* nothing to report at window level until the per-event join lands */

    return 0;
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
