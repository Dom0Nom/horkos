/*
 * tests/unit/test_cs_finding_size.cpp
 * Role: Host-buildable schema-pin test for the macOS code-signing finding wire
 *       payload (macos-codesign-integrity). The plan requires
 *       hk_event_cs_finding == 16 bytes so HK_EVENT_PAYLOAD_MAX stays 16 and the
 *       40-byte hk_event_record / ring layout are UNCHANGED. The CS-finding type
 *       lives in event_schema_cs.h (a macOS-only header, NOT the frozen shared
 *       event_schema.h, mirroring the event_schema_macos.h precedent), so this
 *       test includes it directly and re-pins the shared envelope invariants from
 *       event_schema.h so a future change to either breaks this host test in CI on
 *       every platform.
 * Target platforms: all (event_schema_cs.h is plain C99, no platform headers).
 * Interface: includes horkos/event_schema_cs.h and horkos/event_schema.h.
 */

#include <cstdint>

#include <gtest/gtest.h>
#include <horkos/event_schema_cs.h>
#include <horkos/event_schema.h>

TEST(CsFinding, PayloadIsSixteenBytes)
{
    EXPECT_EQ(sizeof(hk_event_cs_finding), 16u);
}

TEST(CsFinding, FieldLayoutMatchesServerMirror)
{
    // The Rust #[repr(C)] mirror reads {signal_id@0, finding@4, target_pid@8,
    // detail@12}; pin the same offsets here so a reorder breaks the C side too.
    EXPECT_EQ(offsetof(hk_event_cs_finding, signal_id), 0u);
    EXPECT_EQ(offsetof(hk_event_cs_finding, finding), 4u);
    EXPECT_EQ(offsetof(hk_event_cs_finding, target_pid), 8u);
    EXPECT_EQ(offsetof(hk_event_cs_finding, detail), 12u);
}

TEST(CsFinding, SharedHeaderEnvelopeUnchanged)
{
    // The whole point of the macOS-only plane: it must NOT touch the shared
    // record/header envelope. Re-pin them post-addition.
    EXPECT_EQ(sizeof(hk_event_header), 24u);
    EXPECT_EQ(sizeof(hk_event_process_create), 16u);
}

TEST(CsFinding, FindingCodesAreDistinct)
{
    // A copy/paste collision in the HK_CS_* codes would silently mis-route
    // findings server-side; assert they are all distinct.
    const uint32_t codes[] = {
        HK_CS_OK, HK_CS_FLAGS_DRIFT, HK_CS_CDHASH_MISMATCH, HK_CS_DYNAMIC_INVALID,
        HK_CS_INVALIDATED_TAMPER, HK_CS_LV_TEAMID_DIVERGENCE, HK_CS_AMFID_TASKPORT,
        HK_CS_AMFI_POSTURE_WEAK, HK_CS_GATEKEEPER_BYPASS, HK_CS_ENTITLEMENT_DRIFT,
    };
    const size_t n = sizeof(codes) / sizeof(codes[0]);
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            EXPECT_NE(codes[i], codes[j]) << "HK_CS_* code collision at " << i << "," << j;
        }
    }
}
