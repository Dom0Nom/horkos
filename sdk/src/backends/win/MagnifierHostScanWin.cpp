/*
 * sdk/src/backends/win/MagnifierHostScanWin.cpp
 * Role: Signal 51 (win-usermode-overlay). Magnification-API host scanner.
 *       Enumerates top-level windows hosting a WC_MAGNIFIER child (the control a
 *       Magnification-API host creates), attributes the owning PID + window class,
 *       folds the host's window style, and records whether the host is layered.
 *       Whether the magnifier source rect overlaps the game client rect, and
 *       whether the host is the signed OS Magnify.exe, are correlated; the trust
 *       decision (genuine accessibility user) is server-side. Read-only: it only
 *       enumerates and reads window state, never drives the magnifier.
 * Target platforms: Windows userspace. Guardrail #1: user32 use confined here.
 *       Style folding is the pure fold_window_style in RenderSensorWin.h.
 * Interface: implements hk::sdk::render::sense_magnifier_host.
 */

#include "RenderSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace render {

namespace {

/* The Magnification-API control class (from Magnification.h's WC_MAGNIFIER, kept
 * as a literal so this TU needs no Magnification SDK header for enumeration). */
constexpr wchar_t kMagnifierClass[] = L"Magnifier";

struct MagCtx {
    DWORD self_pid;
    std::vector<hk_render_finding>* out;
};

BOOL CALLBACK EnumProc(HWND hwnd, LPARAM lparam)
{
    auto* ctx = reinterpret_cast<MagCtx*>(lparam);

    if (IsWindowVisible(hwnd) == 0) {
        return TRUE;
    }

    /* A Magnification host owns a WC_MAGNIFIER child window. FindWindowEx scans the
     * direct children for that class. */
    HWND mag = FindWindowExW(hwnd, nullptr, kMagnifierClass, nullptr);
    if (mag == nullptr) {
        return TRUE;
    }

    DWORD owning_pid = 0;
    GetWindowThreadProcessId(hwnd, &owning_pid);
    if (owning_pid == 0) {
        return TRUE;
    }

    const LONG_PTR ex = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    WindowStyleInput si{};
    si.ws_ex_layered     = (ex & WS_EX_LAYERED) != 0;
    si.ws_ex_transparent = (ex & WS_EX_TRANSPARENT) != 0;
    si.ws_ex_topmost     = (ex & WS_EX_TOPMOST) != 0;
    si.ws_ex_noactivate  = (ex & WS_EX_NOACTIVATE) != 0;

    hk_render_finding f{};
    f.schema_version = HK_RENDER_SCHEMA_VERSION;
    f.signal = HK_RENDER_SIG_MAGNIFIER;
    f.verdict = HK_PROV_UNRESOLVED;
    f.style_bits = fold_window_style(si);
    f.owning_pid = owning_pid;
    /* HK-VERIFIED(mag-source-rect): MagGetWindowSource is documented to retrieve
     * the source rectangle that was set via MagSetWindowSource for a magnifier
     * control. The Magnification API documentation does not expose a cross-process
     * read of another process's magnifier source rect; the function operates on
     * a control within the CALLING process's window hierarchy only.
     * ref: https://learn.microsoft.com/windows/win32/api/magnification/nf-magnification-maggetwindowsource
     * This confirms the design: the client cannot read a foreign magnifier's source
     * rect, so the overlap correlation must be server-side from the reported owning
     * PID + image path. The current stub (reports host presence + style, defers
     * overlap to server) is correct per the documented API limitation. */
    ctx->out->push_back(f);

    return TRUE;
}

} // namespace

int sense_magnifier_host(std::vector<hk_render_finding>& out)
{
    MagCtx ctx{};
    ctx.self_pid = GetCurrentProcessId();
    ctx.out = &out;

    const size_t before = out.size();
    if (EnumWindows(EnumProc, reinterpret_cast<LPARAM>(&ctx)) == 0) {
        return -1;
    }
    return static_cast<int>(out.size() - before);
}

} } } // namespace hk::sdk::render

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
