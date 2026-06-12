/*
 * Role: Host unit tests for the anti-analysis pure decision cores (catalog
 *       signals 194 + 197). The cores live in hk_ac (anti_analysis_logic.cpp);
 *       this test links hk_ac and exercises them with synthetic observable sets —
 *       no live tooling, no kernel, no OS API. Scaffold coverage: one trivial
 *       passing case per core plus the load-bearing FP/combination edges the
 *       impl-plan calls out (194 single-vs-combined, JIT-context-not-raising;
 *       197 tier ordering). The /tdd phase expands these as the sampler bodies
 *       land.
 * Target platforms: all (host test target).
 * Interface: exercises horkos/anti_analysis/instrumentation.h +
 *       horkos/anti_analysis/host_tools.h pure cores.
 */

#include "horkos/anti_analysis/host_tools.h"
#include "horkos/anti_analysis/instrumentation.h"

#include <gtest/gtest.h>

using namespace hk::anti_analysis;

TEST(AntiAnalysisInstrumentation, NoObservableIsNone) {
    EXPECT_EQ(instrumentation_confidence_tier(0, 0, 0, 0), HK_AA_INSTR_TIER_NONE);
}

TEST(AntiAnalysisInstrumentation, SingleObservableIsInfo) {
    EXPECT_EQ(instrumentation_confidence_tier(1, 0, 0, 0), HK_AA_INSTR_TIER_INFO);
    EXPECT_EQ(instrumentation_confidence_tier(0, 1, 0, 0), HK_AA_INSTR_TIER_INFO);
    EXPECT_EQ(instrumentation_confidence_tier(0, 0, 1, 0), HK_AA_INSTR_TIER_INFO);
}

TEST(AntiAnalysisInstrumentation, CombinedObservablesAreHigh) {
    EXPECT_EQ(instrumentation_confidence_tier(1, 1, 0, 0), HK_AA_INSTR_TIER_HIGH);
    EXPECT_EQ(instrumentation_confidence_tier(1, 1, 1, 0), HK_AA_INSTR_TIER_HIGH);
}

TEST(AntiAnalysisInstrumentation, AllThreeObservablesAreHigh) {
    /* The full Frida-like residency set (unbacked-RX thread + runtime export +
     * control-port listener) escalates to HIGH. */
    EXPECT_EQ(instrumentation_confidence_tier(2, 1, 1, 0), HK_AA_INSTR_TIER_HIGH);
}

TEST(AntiAnalysisInstrumentation, JitContextNeverRaisesTierAlone) {
    /* jit_module_present is FP context: on its own (no real observable) it stays
     * NONE, and it must not push a single observable up to HIGH. */
    EXPECT_EQ(instrumentation_confidence_tier(0, 0, 0, 1), HK_AA_INSTR_TIER_NONE);
    EXPECT_EQ(instrumentation_confidence_tier(1, 0, 0, 1), HK_AA_INSTR_TIER_INFO);
    /* A JIT context concurrent with TWO real observables does not suppress the
     * combination — the tier is driven by the real observables, not the FP flag. */
    EXPECT_EQ(instrumentation_confidence_tier(1, 1, 0, 1), HK_AA_INSTR_TIER_HIGH);
}

TEST(AntiAnalysisHostTools, NothingIsNone) {
    EXPECT_EQ(host_tools_severity_tier(0, 0, 0, 0, 0), HK_AA_HOST_TIER_NONE);
}

TEST(AntiAnalysisHostTools, BareWindowIsInfo) {
    /* A bare generic RE-tool window class (no device/driver/handle) is INFO; a
     * known editor device object is tool-present (asserted below), not INFO. */
    EXPECT_EQ(host_tools_severity_tier(1, 0, 0, 0, 0), HK_AA_HOST_TIER_INFO);
}

TEST(AntiAnalysisHostTools, DriverMatchIsToolPresent) {
    EXPECT_EQ(host_tools_severity_tier(0, 0, 1, 0, 0), HK_AA_HOST_TIER_TOOL_PRESENT);
    EXPECT_EQ(host_tools_severity_tier(1, 1, 0, 1, 0), HK_AA_HOST_TIER_TOOL_PRESENT);
}

TEST(AntiAnalysisHostTools, OpenedHandleIsHighest) {
    EXPECT_EQ(host_tools_severity_tier(0, 0, 0, 0, 1), HK_AA_HOST_TIER_HANDLE_OPEN);
    /* Handle-open dominates a concurrent driver match. */
    EXPECT_EQ(host_tools_severity_tier(1, 1, 1, 1, 1), HK_AA_HOST_TIER_HANDLE_OPEN);
}

/* -------------------------------------------------------------------------
 * Signal 197 — the load-bearing tier-semantics edges the impl-plan (§Signal
 * 197) and the task call out explicitly, asserted against the documented
 * meaning: 0 none; 1 info (generic RE-tool window class only); 2 tool-present
 * (known device object OR suspicious/byovd driver); 3 handle-open (kernel Ob
 * record authoritative). byovd_driver_match implies >= 2.
 * ------------------------------------------------------------------------- */

TEST(AntiAnalysisHostTools, NothingObservedIsTierZero) {
    EXPECT_EQ(host_tools_severity_tier(0, 0, 0, 0, 0), 0u);
}

TEST(AntiAnalysisHostTools, WindowClassOnlyIsTierOne) {
    EXPECT_EQ(host_tools_severity_tier(1, 0, 0, 0, 0), 1u);
}

TEST(AntiAnalysisHostTools, DeviceObjectAloneIsTierTwo) {
    EXPECT_EQ(host_tools_severity_tier(0, 1, 0, 0, 0), HK_AA_HOST_TIER_TOOL_PRESENT);
    EXPECT_EQ(host_tools_severity_tier(0, 1, 0, 0, 0), 2u);
}

TEST(AntiAnalysisHostTools, SuspiciousDriverAloneIsTierTwo) {
    EXPECT_EQ(host_tools_severity_tier(0, 0, 1, 0, 0), 2u);
}

TEST(AntiAnalysisHostTools, ByovdMatchImpliesAtLeastTierTwo) {
    /* A BYOVD helper match alone (no window, no device object, no separate
     * suspicious-driver count, no handle) must still be >= TOOL_PRESENT. */
    EXPECT_GE(host_tools_severity_tier(0, 0, 0, 1, 0), HK_AA_HOST_TIER_TOOL_PRESENT);
    EXPECT_EQ(host_tools_severity_tier(0, 0, 0, 1, 0), 2u);
}

TEST(AntiAnalysisHostTools, HandleOpenIsTierThree) {
    EXPECT_EQ(host_tools_severity_tier(0, 0, 0, 0, 1), 3u);
}

TEST(AntiAnalysisHostTools, HandleOpenWithoutToolArtifactStillTierThree) {
    /* The kernel Ob handle-open record is authoritative: a handle to the game
     * escalates to the top tier even when no usermode window/device/driver
     * artifact was sampled (e.g. the editor cleaned up its window or the driver
     * enumeration was access-denied). */
    EXPECT_EQ(host_tools_severity_tier(0, 0, 0, 0, 1), HK_AA_HOST_TIER_HANDLE_OPEN);
}
