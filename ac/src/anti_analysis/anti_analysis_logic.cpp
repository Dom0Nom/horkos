/*
 * ac/src/anti_analysis/anti_analysis_logic.cpp
 * Role: Pure, platform-free decision cores for the anti-analysis sensors (catalog
 *       signals 194 + 197). These take already-sampled inputs (observable counts
 *       and flags) and return the raw tier the sensor ships as evidence. NO
 *       platform API, NO I/O — so they are unit-tested host-side
 *       (tests/unit/test_anti_analysis_logic.cpp), the plan's "factor the decision
 *       logic out of the sensor TUs into pure functions" requirement (guardrail
 *       #14). Neither core decides a ban: the client emits, the server decides and
 *       may override the tier with its allowlists.
 * Target platforms: all (compiled into hk_ac and the host unit-test target).
 * Interface: implements the pure cores declared in
 *       horkos/anti_analysis/instrumentation.h and horkos/anti_analysis/host_tools.h.
 */

#include "horkos/anti_analysis/host_tools.h"
#include "horkos/anti_analysis/instrumentation.h"

namespace hk {
namespace anti_analysis {

uint32_t instrumentation_confidence_tier(uint32_t unbacked_rx_threads,
                                         uint32_t runtime_export_match,
                                         uint32_t control_port_listener,
                                         uint32_t jit_module_present) noexcept {
    (void)jit_module_present; /* FP context only — never raises the tier alone. */

    /* Count DISTINCT observables present. The catalog mandates combination:
     * a single observable is informational; two or more escalate to high. */
    uint32_t observables = 0u;
    if (unbacked_rx_threads != 0u) {
        ++observables;
    }
    if (runtime_export_match != 0u) {
        ++observables;
    }
    if (control_port_listener != 0u) {
        ++observables;
    }

    if (observables == 0u) {
        return HK_AA_INSTR_TIER_NONE;
    }
    if (observables == 1u) {
        return HK_AA_INSTR_TIER_INFO;
    }
    return HK_AA_INSTR_TIER_HIGH;
}

uint32_t host_tools_severity_tier(uint32_t debugger_window_classes,
                                  uint32_t known_device_objects,
                                  uint32_t suspicious_drivers,
                                  uint32_t byovd_driver_match,
                                  uint32_t opened_handle_to_game) noexcept {
    /* Highest applicable tier wins. A known editor device/symlink object is a
     * tool-present artifact (a kernel-mode editor helper exposed its device),
     * same tier as a matched suspicious/BYOVD driver; only a bare generic
     * RE-tool window class (legitimate dev tools, catalog medium-FP) is INFO. */
    if (opened_handle_to_game != 0u) {
        return HK_AA_HOST_TIER_HANDLE_OPEN;
    }
    if (byovd_driver_match != 0u || suspicious_drivers != 0u ||
        known_device_objects != 0u) {
        return HK_AA_HOST_TIER_TOOL_PRESENT;
    }
    if (debugger_window_classes != 0u) {
        return HK_AA_HOST_TIER_INFO;
    }
    return HK_AA_HOST_TIER_NONE;
}

} // namespace anti_analysis
} // namespace hk
