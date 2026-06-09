/*
 * bypass-tests/win/host_memory_editor.cpp
 * Role: Merge-gate bypass test (anti-analysis-environment signal 197, Windows).
 *       The activated body creates an x64dbg-class-named top-level window
 *       (RealGetWindowClassW observable), drives the pure severity-tier core
 *       through the documented escalation info -> tool-present -> handle-open as
 *       the fixture opens a handle to the target process, and exercises the live
 *       Windows host-tool sampler (anti_analysis_sample_host_tools) to confirm it
 *       observes the synthetic window class. Asserts RAW report fields and the
 *       tier ordering only — NEVER a local ban (ban authority is server-side).
 *       SCAFFOLD: ships DISABLED (HK_ANTI_ANALYSIS_BYPASS_ENABLED undefined) — a
 *       compiled no-op that passes, exactly like byovd_load.cpp; the assertions
 *       activate when the /tdd build wires hk_ac into this target (so the pure
 *       core + live sampler symbols resolve) and the kernel whitelist / Ob
 *       handle-record folding land.
 * Target platforms: Windows only (built behind if(WIN32) in
 *       bypass-tests/win/CMakeLists.txt, so the macOS host build skips it).
 * Interface: drives the AC anti-analysis surface for signal 197 (raw report
 *       field + the pure host_tools_severity_tier core), never a local ban.
 *
 * Merge gate (guardrail #12): the bypass test for the signal-197 host-tool
 * fingerprint. The repo never commits a real memory editor or BYOVD driver — the
 * fixture only names a window class and opens a handle to ITS OWN process to
 * stand in for the editor->game handle-open the kernel Ob records would report.
 */

#include <cstdio>

#ifndef HK_ANTI_ANALYSIS_BYPASS_ENABLED

int main(void) {
    std::printf("DISABLED: host_memory_editor bypass test (signal 197) activates "
                "under /tdd (needs hk_ac wired into this target + the kernel "
                "whitelist/Ob handle folding).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/anti_analysis/anti_analysis_signals.h"
#include "horkos/anti_analysis/host_tools.h"

/* The x64dbg main window is a Qt window; "Qt5QWindowIcon" is in the sampler's
 * known-debugger-window-class table. Registering a top-level window of that
 * class makes the live sampler observe a debugger_window_classes hit. */
static const wchar_t kDebuggerWindowClass[] = L"Qt5QWindowIcon";

static HWND create_debugger_class_window(void) {
    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = kDebuggerWindowClass;

    /* If the class already exists (another Qt app), registration fails with
     * ERROR_CLASS_ALREADY_EXISTS — still fine, CreateWindow below will use it. */
    RegisterClassExW(&wc);

    return CreateWindowExW(0, kDebuggerWindowClass, L"x64dbg-bypass-fixture",
                           WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                           320, 240, nullptr, nullptr,
                           GetModuleHandleW(nullptr), nullptr);
}

int main(void) {
    using namespace hk::anti_analysis;

    /* ---- Pure-core tier-transition assertions (info -> tool-present ->
     * handle-open). These mirror the documented severity semantics and are the
     * load-bearing escalation the fixture proves; they need no live tooling. */

    /* info: a generic RE-tool window class, nothing else. */
    const uint32_t t_info = host_tools_severity_tier(1u, 0u, 0u, 0u, 0u);
    if (t_info != HK_AA_HOST_TIER_INFO) {
        std::printf("host_memory_editor: window-class-only tier %u != INFO(1).\n",
                    t_info);
        return 1;
    }

    /* tool-present: a known editor helper / BYOVD driver matched. */
    const uint32_t t_tool = host_tools_severity_tier(1u, 0u, 1u, 1u, 0u);
    if (t_tool != HK_AA_HOST_TIER_TOOL_PRESENT) {
        std::printf("host_memory_editor: driver-match tier %u != TOOL_PRESENT(2).\n",
                    t_tool);
        return 1;
    }

    /* handle-open: the editor opened a handle to the game (kernel Ob record). */
    const uint32_t t_handle = host_tools_severity_tier(1u, 0u, 1u, 1u, 1u);
    if (t_handle != HK_AA_HOST_TIER_HANDLE_OPEN) {
        std::printf("host_memory_editor: handle-open tier %u != HANDLE_OPEN(3).\n",
                    t_handle);
        return 1;
    }

    if (!(t_info < t_tool && t_tool < t_handle)) {
        std::printf("host_memory_editor: tiers not strictly escalating "
                    "(%u,%u,%u).\n", t_info, t_tool, t_handle);
        return 1;
    }

    /* ---- Live-sampler observation: create the x64dbg-class window and confirm
     * the Windows host-tool sampler observes at least one debugger window class.
     * The sampler is read-only and never opens a handle to anything, so its raw
     * tier is at most INFO here (no driver/device/handle artifacts present). */
    HWND w = create_debugger_class_window();

    aa_host_tools rep;
    const int rc = anti_analysis_sample_host_tools(&rep);
    if (rc != HK_AC_OK) {
        std::printf("host_memory_editor: sampler returned %d (not HK_AC_OK).\n", rc);
        if (w != nullptr) {
            DestroyWindow(w);
        }
        return 1;
    }
    if (rep.debugger_window_classes == 0u) {
        std::printf("host_memory_editor: sampler missed the synthetic "
                    "debugger-class window.\n");
        if (w != nullptr) {
            DestroyWindow(w);
        }
        return 1;
    }

    /* The live sampler is read-only: it must NOT have escalated to handle-open on
     * its own (it never opens a handle to the game). Raw tier here reflects only
     * the window-class observation -> INFO. */
    if (rep.severity_tier > HK_AA_HOST_TIER_INFO) {
        std::printf("host_memory_editor: read-only sampler over-escalated to "
                    "tier %u (expected <= INFO).\n", rep.severity_tier);
        if (w != nullptr) {
            DestroyWindow(w);
        }
        return 1;
    }

    /* ---- Fixture opens a handle to the target process (here, its own process
     * standing in for the game). This is the artifact the kernel Ob records would
     * report as opened_handle_to_game; the editor->game handle-open escalates the
     * SERVER-side tier to HANDLE_OPEN. We assert the tier transition through the
     * pure core (the kernel-record fold is the authoritative input), not a local
     * ban. */
    HANDLE self = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                              GetCurrentProcessId());
    const uint32_t handle_open_flag = (self != nullptr) ? 1u : 0u;
    const uint32_t escalated = host_tools_severity_tier(
        rep.debugger_window_classes, rep.known_device_objects,
        rep.suspicious_drivers, rep.byovd_driver_match, handle_open_flag);
    if (self != nullptr) {
        CloseHandle(self);
        if (escalated != HK_AA_HOST_TIER_HANDLE_OPEN) {
            std::printf("host_memory_editor: with handle-open the tier %u != "
                        "HANDLE_OPEN(3).\n", escalated);
            if (w != nullptr) {
                DestroyWindow(w);
            }
            return 1;
        }
    }

    if (w != nullptr) {
        DestroyWindow(w);
    }

    std::printf("host_memory_editor: passed (tier escalation info->tool->handle, "
                "live sampler observed the debugger window class, no local ban).\n");
    return 0;
}

#endif /* HK_ANTI_ANALYSIS_BYPASS_ENABLED */
