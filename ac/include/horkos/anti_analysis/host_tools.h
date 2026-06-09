/*
 * ac/include/horkos/anti_analysis/host_tools.h
 * Role: Signal 197 (memory-editor / debugger host fingerprint) interface.
 *       Declares the per-signal sampler (the C entry point lives in
 *       anti_analysis_signals.h) and the PURE, platform-free decision core that
 *       maps the sampled host-tool observables onto a severity tier. The core
 *       takes already-sampled facts and returns the raw tier the sensor ships;
 *       it has NO platform API and NO I/O, so it is host-unit-tested
 *       (tests/unit/test_anti_analysis_logic.cpp) — the "factor the decision
 *       logic out of the sensor TU into a pure function" requirement (guardrail
 *       #14). The core does not decide a ban: client emits, server decides (and
 *       may override the tier with its allowlists).
 * Target platforms: the pure core is cross (host-tested everywhere); the sampler
 *       (HostToolFingerprint.cpp) is Windows-only — its C entry returns
 *       HK_AC_NOT_IMPLEMENTED off Windows.
 * Interface: implemented by ac/src/anti_analysis/HostToolFingerprint.cpp
 *       (Windows sampler) + ac/src/anti_analysis/anti_analysis_logic.cpp (pure
 *       core); aggregated via anti_analysis_signals.h. Driver attribution reuses
 *       the kernel driver whitelist (kernel/win/src/Whitelist.c) and handle-open
 *       attribution reuses the kernel ObRegisterCallbacks records.
 */

#pragma once

#include <cstdint>

#include "horkos/anti_analysis/anti_analysis_signals.h"

namespace hk {
namespace anti_analysis {

/* -------------------------------------------------------------------------
 * Signal 197 severity tiers. Generic RE tools have legitimate dev uses
 * (catalog medium-FP: x64dbg/HxD/Process Hacker), so presence alone is low; a
 * known cheat-helper BYOVD driver is higher; an actual handle opened to the
 * game process (from the kernel Ob records) is highest.
 * ------------------------------------------------------------------------- */
enum HostToolTier : uint32_t {
    HK_AA_HOST_TIER_NONE        = 0u, /* nothing observed                        */
    HK_AA_HOST_TIER_INFO        = 1u, /* generic RE-tool window/object, no handle */
    HK_AA_HOST_TIER_TOOL_PRESENT= 2u, /* known editor helper / BYOVD driver match */
    HK_AA_HOST_TIER_HANDLE_OPEN = 3u, /* editor opened a handle to the game       */
};

/* 197 severity-tier function (PURE). Inputs are the already-sampled
 * observables:
 *   - `debugger_window_classes`: count of known debugger top-level window classes.
 *   - `known_device_objects`: count of known editor device/symlink names present.
 *   - `suspicious_drivers`: count of editor-helper drivers loaded.
 *   - `byovd_driver_match`: 1 if a loaded driver matched the kernel whitelist
 *     known-bad set (a BYOVD editor driver).
 *   - `opened_handle_to_game`: 1 if the kernel Ob records show an editor opened a
 *     handle to the game process.
 * Tiering (highest wins): an opened handle => HK_AA_HOST_TIER_HANDLE_OPEN; a
 * BYOVD/suspicious-driver match OR a known editor device/symlink object =>
 * HK_AA_HOST_TIER_TOOL_PRESENT; a bare generic RE-tool window class =>
 * HK_AA_HOST_TIER_INFO; nothing => HK_AA_HOST_TIER_NONE. */
uint32_t host_tools_severity_tier(uint32_t debugger_window_classes,
                                  uint32_t known_device_objects,
                                  uint32_t suspicious_drivers,
                                  uint32_t byovd_driver_match,
                                  uint32_t opened_handle_to_game) noexcept;

} // namespace anti_analysis
} // namespace hk
