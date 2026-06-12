/*
 * Role: Signal 49 (win-usermode-overlay). Foreign layered/transparent/topmost
 *       click-through overlay-window scanner: EnumWindows over visible top-level
 *       windows, reads GWL_EXSTYLE (layered/transparent/topmost/noactivate),
 *       DWMWA_CLOAKED and per-pixel-alpha, intersects each window rect with the
 *       game's client rect, and reports the owning PID + folded style bitmask +
 *       window class for any foreign window covering the game surface. Read-only:
 *       it only enumerates and queries window state, never moves/hides/closes a
 *       window. The foreign+unsigned+covering SCORE is server-side; the client
 *       reports, it does not ban (catalog).
 * Target platforms: Windows userspace. Guardrail #1: user32/dwmapi use confined
 *       here. Style folding + rect overlap are the pure fold_window_style /
 *       rects_overlap in RenderSensorWin.h (host-tested).
 * Interface: implements hk::sdk::render::sense_layered_windows.
 */

#include "RenderSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>
#include <dwmapi.h>

namespace hk { namespace sdk { namespace render {

namespace {

/* The game's own client rect in screen space, resolved once per scan. */
struct GameRect {
    Rect rect{};
    bool valid = false;
    DWORD self_pid = 0;
};

/* Map the foreground/own client rect into screen space. Uses the own main window
 * (the SDK runs in-process); GetClientRect + ClientToScreen. Returns invalid if no
 * usable window. */
GameRect ResolveGameRect()
{
    GameRect g{};
    g.self_pid = GetCurrentProcessId();

    /* The game's render window is the process's foreground/main window. Best-effort:
     * use GetActiveWindow; if null (no message thread here) fall back to invalid and
     * the scan reports all foreign overlays without the covering filter (server can
     * still attribute). */
    HWND hwnd = GetActiveWindow();
    if (hwnd == nullptr) {
        return g;
    }
    RECT rc{};
    POINT tl{0, 0};
    if (GetClientRect(hwnd, &rc) == 0) {
        return g;
    }
    if (ClientToScreen(hwnd, &tl) == 0) {
        return g;
    }
    g.rect.left   = tl.x;
    g.rect.top    = tl.y;
    g.rect.right  = tl.x + (rc.right - rc.left);
    g.rect.bottom = tl.y + (rc.bottom - rc.top);
    g.valid = (g.rect.right > g.rect.left) && (g.rect.bottom > g.rect.top);
    return g;
}

struct ScanCtx {
    GameRect game;
    std::vector<hk_render_finding>* out;
};

BOOL CALLBACK EnumProc(HWND hwnd, LPARAM lparam)
{
    auto* ctx = reinterpret_cast<ScanCtx*>(lparam);

    if (IsWindowVisible(hwnd) == 0) {
        return TRUE;
    }

    DWORD owning_pid = 0;
    GetWindowThreadProcessId(hwnd, &owning_pid);
    /* Skip our own windows; a self overlay is not a foreign injection. */
    if (owning_pid == ctx->game.self_pid || owning_pid == 0) {
        return TRUE;
    }

    const LONG_PTR ex = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);

    WindowStyleInput si{};
    si.ws_ex_layered     = (ex & WS_EX_LAYERED) != 0;
    si.ws_ex_transparent = (ex & WS_EX_TRANSPARENT) != 0;
    si.ws_ex_topmost     = (ex & WS_EX_TOPMOST) != 0;
    si.ws_ex_noactivate  = (ex & WS_EX_NOACTIVATE) != 0;

    /* A plain ordinary app window (not layered, not topmost) is not an overlay
     * candidate; skip early to keep the scan cheap and FP-light. */
    if (!si.ws_ex_layered && !si.ws_ex_topmost) {
        return TRUE;
    }

    BOOL cloaked = FALSE;
    if (SUCCEEDED(DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, &cloaked, sizeof(cloaked)))) {
        si.dwm_cloaked = (cloaked != FALSE);
    }

    if (si.ws_ex_layered) {
        BYTE alpha = 0;
        COLORREF key = 0;
        DWORD flags = 0;
        if (GetLayeredWindowAttributes(hwnd, &key, &alpha, &flags)) {
            si.per_pixel_alpha = (flags & (LWA_ALPHA | LWA_COLORKEY)) != 0;
        } else {
            /* SetLayeredWindowAttributes was not used (UpdateLayeredWindow path) —
             * that is itself the per-pixel-alpha case. */
            si.per_pixel_alpha = true;
        }
    }

    /* Covering test: intersect the window rect with the game client rect. When the
     * game rect could not be resolved, report regardless (server attributes). */
    bool covers = true;
    if (ctx->game.valid) {
        RECT wr{};
        if (GetWindowRect(hwnd, &wr) == 0) {
            return TRUE; /* cannot size this window; skip rather than guess */
        }
        Rect r{wr.left, wr.top, wr.right, wr.bottom};
        covers = rects_overlap(r, ctx->game.rect);
    }
    if (!covers) {
        return TRUE;
    }

    hk_render_finding f{};
    f.schema_version = HK_RENDER_SCHEMA_VERSION;
    f.signal = HK_RENDER_SIG_LAYERED_WINDOW;
    f.verdict = HK_PROV_UNRESOLVED; /* provenance N/A for a pure window finding */
    f.style_bits = fold_window_style(si);
    f.owning_pid = owning_pid;
    ctx->out->push_back(f);

    return TRUE;
}

} // namespace

int sense_layered_windows(std::vector<hk_render_finding>& out)
{
    ScanCtx ctx{};
    ctx.game = ResolveGameRect();
    ctx.out = &out;

    const size_t before = out.size();
    if (EnumWindows(EnumProc, reinterpret_cast<LPARAM>(&ctx)) == 0) {
        /* EnumWindows itself failing is rare; report it as a sensor-failure count
         * rather than a fabricated overlay. */
        return -1;
    }
    return static_cast<int>(out.size() - before);
}

} } } // namespace hk::sdk::render

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
