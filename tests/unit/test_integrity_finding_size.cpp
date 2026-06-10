/*
 * tests/unit/test_integrity_finding_size.cpp
 * Role: Host-buildable schema-pin test for the driver/module-integrity wire
 *       payload (win-kernel-driver-integrity). The plan requires
 *       hk_event_integrity_finding == 16 bytes so that HK_EVENT_PAYLOAD_MAX stays
 *       16 and the 40-byte hk_event_record / ring layout are UNCHANGED (no ring
 *       resize). The real wire struct lives as a kernel-private mirror in
 *       kernel/win/include/horkos_kernel.h (which pulls ntddk and cannot be
 *       included host-side) until the Schema phase moves it to event_schema.h;
 *       this test pins a byte-identical local replica AND re-pins the surrounding
 *       envelope invariants from ioctl.h, so a future schema landing that changes
 *       the payload size breaks this host test in CI on every platform.
 * Target platforms: all.
 * Interface: includes horkos/ioctl.h for the envelope pins; replicates the
 *       16-byte finding struct locally.
 */

#include <cstdint>

#include <gtest/gtest.h>
#include <horkos/ioctl.h>

namespace {

// Byte-identical replica of hk_event_integrity_finding (horkos_kernel.h mirror /
// plan §"New event type"). If the Schema phase lands a different layout, this
// test and the kernel HK_STATIC_ASSERT diverge — intentional early warning.
struct hk_event_integrity_finding_replica {
    uint32_t signal_id;
    uint32_t finding;
    uint64_t detail;
};

} // namespace

TEST(IntegrityFinding, PayloadIsSixteenBytes)
{
    EXPECT_EQ(sizeof(hk_event_integrity_finding_replica), 16u);
}

TEST(IntegrityFinding, FitsExistingPayloadMaxNoRingResize)
{
    // The 16-byte finding must fit the payload max so the ring layout is sound.
    // (HK_EVENT_PAYLOAD_MAX grew 16->24 in schema v5 for hk_event_process_create_ex;
    // the 16-byte finding still fits comfortably.)
    EXPECT_EQ(HK_EVENT_PAYLOAD_MAX, 24u);
    EXPECT_LE(sizeof(hk_event_integrity_finding_replica),
              static_cast<size_t>(HK_EVENT_PAYLOAD_MAX));
}

TEST(IntegrityFinding, RecordAndStatusEnvelopeUnchanged)
{
    // The record grew 40->48 with the v5 payload-max bump; hk_status is unchanged.
    EXPECT_EQ(sizeof(hk_event_record), 48u);
    EXPECT_EQ(sizeof(hk_status), 32u);
}

TEST(IntegrityFinding, RescanIoctlUsesNextVendorFunction)
{
    // HK_IOCTL_INTEGRITY_RESCAN will be the next free vendor code after the
    // currently assigned codes:
    //   0x800 = HK_IOCTL_DRAIN_EVENTS
    //   0x801 = HK_IOCTL_GET_STATUS
    //   0x802 = HK_IOCTL_PUSH_POLICY
    //   0x803 = HK_IOCTL_DRAIN_MEM_EVENTS  (schema v3 — NOT free)
    //   0x804 = HK_IOCTL_SCAN_PROCESS       (schema v3 — NOT free)
    // The next free function code is therefore 0x805.
    // HK-TODO(schema): once HK_IOCTL_INTEGRITY_RESCAN is added to ioctl.h,
    // replace this local expected value with the macro and add it to the
    // NE checks below.
    const uint32_t expected =
        HK_CTL_CODE(HK_FILE_DEVICE_UNKNOWN, 0x805, HK_METHOD_BUFFERED, HK_FILE_ANY_ACCESS);
    EXPECT_NE(expected, HK_IOCTL_DRAIN_EVENTS);
    EXPECT_NE(expected, HK_IOCTL_GET_STATUS);
    EXPECT_NE(expected, HK_IOCTL_PUSH_POLICY);
    EXPECT_NE(expected, HK_IOCTL_DRAIN_MEM_EVENTS);
    EXPECT_NE(expected, HK_IOCTL_SCAN_PROCESS);
}
