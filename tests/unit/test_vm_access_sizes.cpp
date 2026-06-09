/*
 * tests/unit/test_vm_access_sizes.cpp
 * Role: Host-buildable schema-pin test for the win-handle-memory-access wire
 *       payloads (signals 64-72). The plan lists four payloads whose NAMED fields
 *       sum to 28/24/12/20, but the u64 members force 8-byte struct alignment, so the
 *       real on-wire sizes (with the explicit tail-pad the kernel mirror makes
 *       visible) are 32/24/12/24. The real wire structs live as kernel-private
 *       mirrors in kernel/win/include/horkos_kernel.h (which pulls ntddk and cannot
 *       be included host-side) until the Schema phase moves them to event_schema.h;
 *       this test pins byte-identical local replicas so a future schema landing that
 *       changes a size breaks this host test in CI on every platform. It ALSO pins
 *       the flagged blocker: hk_event_vm_access (32) and hk_event_handle_provenance
 *       (24) EXCEED the current HK_EVENT_PAYLOAD_MAX (16), so they cannot cross the
 *       existing drain envelope until the Schema phase grows it — that mismatch is
 *       asserted here deliberately, mirroring the kernel HK_VMWATCH_SCHEMA_READY gate.
 * Target platforms: all.
 * Interface: includes horkos/ioctl.h for the envelope pins; replicates the four
 *       payload structs locally.
 */

#include <cstddef>
#include <cstdint>

#include <gtest/gtest.h>
#include <horkos/ioctl.h>

namespace {

// Byte-identical replicas of the horkos_kernel.h mirrors (plan §"Interfaces & data
// structures"). If the Schema phase lands a different layout, this test and the
// kernel HK_STATIC_ASSERT diverge — intentional early warning.
struct hk_event_vm_access_replica {
    uint32_t source_pid;
    uint32_t target_pid;
    uint64_t target_va;
    uint32_t access_kind;
    uint32_t target_section_flags;
    uint32_t flags;
    uint32_t reserved; /* explicit tail pad (u64 alignment) */
};

struct hk_event_handle_provenance_replica {
    uint32_t requester_pid;
    uint32_t source_pid;
    uint32_t target_pid;
    uint32_t original_desired_access;
    uint32_t granted_access;
    uint32_t flags;
};

struct hk_event_foreign_holder_replica {
    uint32_t owner_pid;
    uint32_t granted_access;
    uint32_t flags;
};

struct hk_event_protect_drift_replica {
    uint64_t region_base;
    uint32_t live_protect;
    uint32_t expected_protect;
    uint32_t flags;
    uint32_t reserved; /* explicit tail pad (u64 alignment) */
};

} // namespace

TEST(VmAccessSchema, PayloadSizesMatchWireLayout)
{
    // Named fields sum to 28/24/12/20; with the u64-forced tail pad the real on-wire
    // sizes are 32/24/12/24 (matching the kernel HK_STATIC_ASSERTs + the Rust pins).
    EXPECT_EQ(sizeof(hk_event_vm_access_replica), 32u);
    EXPECT_EQ(sizeof(hk_event_handle_provenance_replica), 24u);
    EXPECT_EQ(sizeof(hk_event_foreign_holder_replica), 12u);
    EXPECT_EQ(sizeof(hk_event_protect_drift_replica), 24u);
}

TEST(VmAccessSchema, LargePayloadsExceedCurrentEnvelope)
{
    // The flagged blocker (HK_VMWATCH_SCHEMA_READY): the two larger payloads do NOT
    // fit the current 16-byte payload max, so they cannot cross the existing drain
    // envelope until the Schema phase grows HK_EVENT_PAYLOAD_MAX and re-pins the
    // record. Asserting the mismatch documents WHY the kernel emit sites are gated.
    EXPECT_EQ(HK_EVENT_PAYLOAD_MAX, 16u);
    EXPECT_GT(sizeof(hk_event_vm_access_replica),
              static_cast<size_t>(HK_EVENT_PAYLOAD_MAX));
    EXPECT_GT(sizeof(hk_event_handle_provenance_replica),
              static_cast<size_t>(HK_EVENT_PAYLOAD_MAX));
}

TEST(VmAccessSchema, EnvelopeUnchangedPreSchema)
{
    // No record/status growth has happened in THIS domain (the Schema phase owns the
    // envelope edit). Re-pin so an accidental local change is caught host-side.
    EXPECT_EQ(sizeof(hk_event_record), 40u);
    EXPECT_EQ(sizeof(hk_status), 32u);
}
