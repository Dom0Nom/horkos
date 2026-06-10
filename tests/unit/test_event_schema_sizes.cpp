/*
 * tests/unit/test_event_schema_sizes.cpp
 * Role: Verifies event schema struct sizes from C++ side, matching the
 *       static_asserts in event_schema.h. Catches platform-specific padding
 *       divergence that static_assert might miss on a different compiler.
 * Target platforms: all.
 */

#include <gtest/gtest.h>
#include <horkos/event_schema.h>

TEST(EventSchema, HeaderSize) {
    EXPECT_EQ(sizeof(hk_event_header), 24u);
}

TEST(EventSchema, ProcessCreateSize) {
    EXPECT_EQ(sizeof(hk_event_process_create), 16u);
}

TEST(EventSchema, ProcessExitSize) {
    EXPECT_EQ(sizeof(hk_event_process_exit), 16u);
}

TEST(EventSchema, SchemaVersionIsSix) {
    /* v3 added the memory/image-anomaly event family (types 5..13);
     * v4 added the hypervisor kernel-event family (types 14..17);
     * v5 added the process-genealogy create-ex event (type 18, 24 bytes) and
     * grew HK_EVENT_PAYLOAD_MAX 16->24 / hk_event_record 40->48;
     * v6 froze the Linux module-trust (19..28), self-integrity (29..37,
     * renumbered from the old self_wire 14..22 collision), and timing freq-skew
     * (38) discriminant families into hk_event_type. */
    EXPECT_EQ(HK_EVENT_SCHEMA_VERSION, 6u);
}

TEST(EventSchema, FrozenDiscriminantsAreCollisionFree) {
    /* The v6 renumber: self-integrity no longer overlaps the HV or create-ex
     * ranges that previously aliased the provisional self_wire 14..22 macros. */
    EXPECT_EQ(HK_EVENT_SENSOR_UNAVAILABLE, 28);
    EXPECT_EQ(HK_EVENT_SELF_CROSSVIEW, 29);
    EXPECT_EQ(HK_EVENT_SELF_TLS_INIT, 37);
    EXPECT_EQ(HK_EVENT_TIMING_FREQ_SKEW, 38);
    /* The old collision values belong to their rightful owners. */
    EXPECT_EQ(HK_EVENT_HV_SYNTH_MSR, 14);
    EXPECT_EQ(HK_EVENT_PROCESS_CREATE_EX, 18);
}

TEST(EventSchema, ImageLoadSize) {
    EXPECT_EQ(sizeof(hk_event_image_load), 16u);
}

TEST(EventSchema, HandleOpenSize) {
    EXPECT_EQ(sizeof(hk_event_handle_open), 16u);
}
