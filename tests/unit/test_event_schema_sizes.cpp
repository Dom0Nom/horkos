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

TEST(EventSchema, SchemaVersionIsFour) {
    /* v3 added the memory/image-anomaly event family (types 5..13);
     * v4 added the hypervisor/virtualization kernel-event family (types 14..17). */
    EXPECT_EQ(HK_EVENT_SCHEMA_VERSION, 4u);
}

TEST(EventSchema, ImageLoadSize) {
    EXPECT_EQ(sizeof(hk_event_image_load), 16u);
}

TEST(EventSchema, HandleOpenSize) {
    EXPECT_EQ(sizeof(hk_event_handle_open), 16u);
}
