/*
 * tests/unit/test_ioctl_sizes.cpp
 * Role: Compiles the userspace<->kernel IOCTL wire header on the dev host and
 *       verifies every wire struct size from the C++ side. This is the only
 *       host-buildable check of the Phase 3 IOCTL contract (the kernel TUs that
 *       also pin these sizes need a WDK). Catches layout drift before it reaches
 *       a Windows build.
 * Target platforms: all (the header is platform-clean C99).
 */

#include <gtest/gtest.h>
#include <horkos/ioctl.h>

TEST(IoctlWire, EventRecordSize) {
    EXPECT_EQ(sizeof(hk_event_record), 48u); /* v5: payload max grew 16->24. */
}

TEST(IoctlWire, DrainHeaderSize) {
    EXPECT_EQ(sizeof(hk_drain_header), 16u);
}

TEST(IoctlWire, StatusSize) {
    EXPECT_EQ(sizeof(hk_status), 32u);
}

TEST(IoctlWire, PolicySize) {
    EXPECT_EQ(sizeof(hk_policy), 16u);
}

TEST(IoctlWire, ControlCodesDistinct) {
    EXPECT_NE(HK_IOCTL_DRAIN_EVENTS, HK_IOCTL_GET_STATUS);
    EXPECT_NE(HK_IOCTL_GET_STATUS, HK_IOCTL_PUSH_POLICY);
    EXPECT_NE(HK_IOCTL_DRAIN_EVENTS, HK_IOCTL_PUSH_POLICY);
}
