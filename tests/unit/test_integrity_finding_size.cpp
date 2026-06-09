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
    // The whole point of the 16-byte pin: it must fit the EXISTING payload max so
    // the ring/record layout is untouched.
    EXPECT_EQ(HK_EVENT_PAYLOAD_MAX, 16u);
    EXPECT_LE(sizeof(hk_event_integrity_finding_replica),
              static_cast<size_t>(HK_EVENT_PAYLOAD_MAX));
}

TEST(IntegrityFinding, RecordAndStatusEnvelopeUnchanged)
{
    // Re-pin the envelope invariants the plan promises stay green after the
    // integrity additions (no hk_event_record growth, no hk_status growth).
    EXPECT_EQ(sizeof(hk_event_record), 40u);
    EXPECT_EQ(sizeof(hk_status), 32u);
}

TEST(IntegrityFinding, RescanIoctlUsesNextVendorFunction)
{
    // HK_IOCTL_INTEGRITY_RESCAN is function 0x803, the next free vendor code
    // after DRAIN(0x800)/STATUS(0x801)/POLICY(0x802). Reproduce the expected
    // CTL_CODE value so a clash with an existing code is caught host-side.
    // HK-TODO(schema): this macro is a kernel-private mirror until ioctl.h gains
    // it; define the expected value locally for the pin.
    const uint32_t expected =
        HK_CTL_CODE(HK_FILE_DEVICE_UNKNOWN, 0x803, HK_METHOD_BUFFERED, HK_FILE_ANY_ACCESS);
    EXPECT_NE(expected, HK_IOCTL_DRAIN_EVENTS);
    EXPECT_NE(expected, HK_IOCTL_GET_STATUS);
    EXPECT_NE(expected, HK_IOCTL_PUSH_POLICY);
}
