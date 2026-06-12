/*
 * Role: SDK-internal façade for the Windows render/overlay usermode sensors
 *       (catalog signals 46-54, win-usermode-overlay). Declares the nine sensor
 *       entry points, the shared signed-module-map snapshot type, and the small
 *       PLATFORM-FREE decision cores (provenance classification, window-style
 *       folding, rect overlap) that the host unit tests drive with no live
 *       process / no Win32. The Win32-touching builders/sensors are declared here
 *       and implemented in the *Win.cpp siblings.
 * Target platforms: Windows (userspace). The pure cores are platform-free so they
 *       are host-testable (mirrors ThreadProvenanceWin.h / minifilter_altitude.h).
 * Interface: implemented by ModuleMapWin.cpp + the nine *Win.cpp sensor files;
 *       consumed by the Windows sdk.cpp AC tick. Findings are emitted on the
 *       render JSON plane (render_hook_schema.h), never the kernel ring.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "horkos/render_hook_schema.h"

namespace hk { namespace sdk { namespace render {

/* -------------------------------------------------------------------------
 * Shared signed-module map (signals 46/47/52/54).
 * One entry per loaded module: its mapped VA range, on-disk path, and resolved
 * Authenticode signer subject (empty if unsigned / unverified). Built once per
 * tick by ModuleMapWin.cpp; the provenance classifier consumes it without any
 * platform call so it is host-testable.
 * ------------------------------------------------------------------------- */
struct ModuleEntry {
    uint64_t    base;            /* image base VA */
    uint64_t    size;            /* SizeOfImage; range is [base, base+size) */
    std::string path;            /* on-disk backing path (GetMappedFileName) */
    std::string signer_subject;  /* Authenticode signer CN/subject, empty if none */
    bool        signed_ok;       /* WinVerifyTrust chain valid */
    bool        allowlisted;     /* server-provisioned signer allow-list hit */
};

struct ModuleMap {
    std::vector<ModuleEntry> entries;  /* sorted by base for binary lookup */
};

/* Backing classification of a resolved target VA, captured behind a seam so the
 * pure classifier needs no VirtualQuery. Mirrors MEMORY_BASIC_INFORMATION.Type. */
enum class TargetBacking : uint32_t {
    Unresolved = 0,  /* VirtualQueryEx failed / inconclusive */
    Image      = 1,  /* MEM_IMAGE */
    Mapped     = 2,  /* MEM_MAPPED (data section) */
    Private    = 3   /* MEM_PRIVATE / unbacked */
};

/* Inputs to the provenance verdict for a single resolved target (46/47/52/54).
 * All fields are filled by the platform sensor before calling the pure
 * classifier; the classifier itself touches no OS. */
struct ProvenanceInput {
    TargetBacking backing;          /* MBI.Type of the target VA */
    bool          in_known_module;  /* target VA resolved inside a ModuleMap entry */
    bool          module_signed;    /* that module's Authenticode chain is valid */
    bool          module_allowlisted; /* server allow-list hit for the signer */
};

/* Pure provenance classifier (no platform calls), defined inline so the host unit
 * test exercises the full decision table with no live process (mirrors
 * classify_start_mismatch in ThreadProvenanceWin.h). Deliberately conservative:
 * an unresolved target is HK_PROV_UNRESOLVED, never a fabricated anomaly. */
inline hk_provenance_verdict classify_provenance(const ProvenanceInput &in)
{
    if (in.backing == TargetBacking::Unresolved) {
        return HK_PROV_UNRESOLVED;
    }
    /* Non-image (private RX or mapped-data executable) is the strongest tampering
     * shape: legitimate present-path targets live in MEM_IMAGE module code. */
    if (in.backing != TargetBacking::Image || !in.in_known_module) {
        return HK_PROV_PRIVATE_RX;
    }
    /* Image-backed, inside a known module: the verdict is purely a function of the
     * module's signature + allow-list status. The CLIENT does not decide trust —
     * it reports which bucket the resolved module falls in; the server's signed
     * allow-list rule fuses the rest. */
    if (!in.module_signed) {
        return HK_PROV_IMAGE_UNSIGNED;
    }
    if (in.module_allowlisted) {
        return HK_PROV_IMAGE_SIGNED_ALLOWLISTED;
    }
    return HK_PROV_IMAGE_SIGNED_FOREIGN;
}

/* -------------------------------------------------------------------------
 * Window-style folding + rect overlap (signals 49/51). Pure, host-tested.
 * ------------------------------------------------------------------------- */

/* The GWL_EXSTYLE + DWM-cloak inputs the window scan captures, behind a seam so
 * the bitmask folding is testable with no live HWND. */
struct WindowStyleInput {
    bool ws_ex_layered;       /* WS_EX_LAYERED */
    bool ws_ex_transparent;   /* WS_EX_TRANSPARENT (click-through hit-test) */
    bool ws_ex_topmost;       /* WS_EX_TOPMOST */
    bool ws_ex_noactivate;    /* WS_EX_NOACTIVATE */
    bool dwm_cloaked;         /* DWMWA_CLOAKED true */
    bool per_pixel_alpha;     /* GetLayeredWindowAttributes reports LWA_ALPHA/COLORKEY */
};

/* Fold the raw style inputs into the HK_WSTYLE_* bitmask. CLICKTHROUGH is the
 * derived per-pixel-alpha + transparent combination (a pass-through overlay), not
 * a raw style bit. */
inline uint32_t fold_window_style(const WindowStyleInput &in)
{
    uint32_t bits = 0;
    if (in.ws_ex_layered)     bits |= HK_WSTYLE_LAYERED;
    if (in.ws_ex_transparent) bits |= HK_WSTYLE_TRANSPARENT;
    if (in.ws_ex_topmost)     bits |= HK_WSTYLE_TOPMOST;
    if (in.ws_ex_noactivate)  bits |= HK_WSTYLE_NOACTIVATE;
    if (in.dwm_cloaked)       bits |= HK_WSTYLE_CLOAKED;
    if (in.ws_ex_transparent && in.per_pixel_alpha) {
        bits |= HK_WSTYLE_CLICKTHROUGH;
    }
    return bits;
}

/* A screen-space rectangle (left/top/right/bottom, right/bottom exclusive),
 * matching Win32 RECT semantics so the platform code maps RECT directly. */
struct Rect {
    int32_t left, top, right, bottom;
};

/* True if `a` and `b` overlap by a non-empty area. Empty/degenerate rects never
 * overlap. Used to decide whether a candidate overlay window covers the game's
 * client rect (signal 49) or whether a magnifier source rect overlaps it (51). */
inline bool rects_overlap(const Rect &a, const Rect &b)
{
    const int32_t l = a.left > b.left ? a.left : b.left;
    const int32_t t = a.top > b.top ? a.top : b.top;
    const int32_t r = a.right < b.right ? a.right : b.right;
    const int32_t btm = a.bottom < b.bottom ? a.bottom : b.bottom;
    return (l < r) && (t < btm);
}

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

/* Build the per-process signed-module snapshot shared by 46/47/52/54. Returns
 * false on enumeration failure (caller treats the tick as "no module map"; every
 * dependent sensor then degrades to HK_PROV_UNRESOLVED rather than guessing).
 * Read-only: EnumProcessModulesEx + GetMappedFileName + Authenticode signer. The
 * (_WIN32 fallback in the guard mirrors the other backends/win headers — the SDK
 * has not yet defined HK_PLATFORM_WINDOWS for this TU, but the implementation
 * lives strictly under backends/win/ per guardrail #1.) */
bool build_module_map(ModuleMap &out);

/* The nine sensor entry points. Each appends zero or more hk_render_finding
 * records (plus their string side-channel) to `out` and returns the number
 * appended, or -1 on a sensor-level failure (which is itself reported as an
 * HK_PROV_UNRESOLVED finding, not a silent drop). All are read-only and must not
 * let an exception cross this C++ ABI seam. `module_map` is the shared snapshot
 * for the provenance signals; window/cadence sensors ignore it. */
int sense_present_vtable(const ModuleMap &module_map, std::vector<hk_render_finding> &out);
int sense_present_prologue(const ModuleMap &module_map, std::vector<hk_render_finding> &out);
int sense_present_framestats(std::vector<hk_render_finding> &out);
int sense_layered_windows(std::vector<hk_render_finding> &out);
int sense_dwm_thumbnail(std::vector<hk_render_finding> &out);
int sense_magnifier_host(std::vector<hk_render_finding> &out);
int sense_hookdll_footprint(const ModuleMap &module_map, std::vector<hk_render_finding> &out);
int sense_gdi_pressure(std::vector<hk_render_finding> &out);
int sense_vulkan_layers(const ModuleMap &module_map, std::vector<hk_render_finding> &out);

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */

} } } // namespace hk::sdk::render
