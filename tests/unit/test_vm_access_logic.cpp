/*
 * Role: Host-buildable unit tests for the win-handle-memory-access pure decision
 *       cores (no driver, no Win32): the section-flag classifier + the alloc->protect
 *       ->write staging assembler (VmAccessLogicWin.h, signals 64/72) and the
 *       residency-burst / foreign-holder / protect-drift cores (VmWatchWin.h, signals
 *       65/70/71). Proves the decision tables: in-section classification, ordered-only
 *       staging emit, and the conservative FP-gates (no CPU baseline / own-handle /
 *       signed-allowlisted / non-exec section never fire).
 * Target platforms: host (any).
 * Interface: exercises hk::sdk::vmaccess::{classify_target_section, StagingAssembler,
 *       residency_burst_is_foreign, holder_is_dangerous, protect_is_drift}.
 */

#include <gtest/gtest.h>

#include "backends/win/VmAccessLogicWin.h"
#include "backends/win/VmWatchWin.h"

using namespace hk::sdk::vmaccess;

namespace {

std::vector<SectionRange> SampleCache()
{
    // A module with a +RX .text at [0x1000,0x2000) and a +RW .data at [0x2000,0x3000).
    return {
        SectionRange{0x1000, 0x1000, kScnMemExecute | kScnMemRead},
        SectionRange{0x2000, 0x1000, kScnMemRead | kScnMemWrite},
    };
}

} // namespace

// ---- Section-flag classifier (signal 64/71 input) -------------------------

TEST(VmSectionClassify, VaInTextResolvesExecutable)
{
    auto cache = SampleCache();
    uint32_t f = classify_target_section(cache, 0x1500);
    EXPECT_NE(f & kScnMemExecute, 0u);
    EXPECT_TRUE(target_is_executable(f));
}

TEST(VmSectionClassify, VaInDataIsNotExecutable)
{
    auto cache = SampleCache();
    uint32_t f = classify_target_section(cache, 0x2500);
    EXPECT_EQ(f & kScnMemExecute, 0u);
    EXPECT_FALSE(target_is_executable(f));
}

TEST(VmSectionClassify, VaOutsideAnyModuleIsZero)
{
    auto cache = SampleCache();
    EXPECT_EQ(classify_target_section(cache, 0x9999), 0u);
    EXPECT_FALSE(target_is_executable(0u));
}

TEST(VmSectionClassify, EndOfRangeIsExclusive)
{
    auto cache = SampleCache();
    // 0x2000 is the start of .data, not the (exclusive) end of .text.
    uint32_t f = classify_target_section(cache, 0x2000);
    EXPECT_EQ(f & kScnMemExecute, 0u); // resolved to .data, not .text
}

TEST(VmSectionClassify, ZeroSizeRangeNeverMatches)
{
    std::vector<SectionRange> cache{SectionRange{0x4000, 0, kScnMemExecute}};
    EXPECT_EQ(classify_target_section(cache, 0x4000), 0u);
}

// ---- Staging assembler (signal 72) ----------------------------------------

TEST(VmStaging, OrderedTriadEmitsOnce)
{
    StagingAssembler a;
    EXPECT_FALSE(a.feed(100, VmStage::Alloc, 0));
    EXPECT_FALSE(a.feed(100, VmStage::Protect, 10));
    EXPECT_TRUE(a.feed(100, VmStage::Write, 20)); // completes
    // A second write must not re-emit (progress cleared).
    EXPECT_FALSE(a.feed(100, VmStage::Write, 30));
}

TEST(VmStaging, OutOfOrderDoesNotEmit)
{
    StagingAssembler a;
    // Protect before Alloc: no window open.
    EXPECT_FALSE(a.feed(1, VmStage::Protect, 0));
    EXPECT_FALSE(a.feed(1, VmStage::Write, 5));
    // Alloc then Write (skipping Protect): not complete.
    EXPECT_FALSE(a.feed(1, VmStage::Alloc, 10));
    EXPECT_FALSE(a.feed(1, VmStage::Write, 15));
}

TEST(VmStaging, WindowExpiryDropsSequence)
{
    StagingAssembler a(100); // 100ns window
    EXPECT_FALSE(a.feed(7, VmStage::Alloc, 0));
    EXPECT_FALSE(a.feed(7, VmStage::Protect, 50));
    // Write arrives past the 100ns window -> dropped, no emit.
    EXPECT_FALSE(a.feed(7, VmStage::Write, 250));
}

TEST(VmStaging, PerPidIndependent)
{
    StagingAssembler a;
    EXPECT_FALSE(a.feed(1, VmStage::Alloc, 0));
    EXPECT_FALSE(a.feed(2, VmStage::Alloc, 1));
    EXPECT_FALSE(a.feed(1, VmStage::Protect, 2));
    EXPECT_FALSE(a.feed(2, VmStage::Protect, 3));
    EXPECT_TRUE(a.feed(2, VmStage::Write, 4));  // pid 2 completes
    EXPECT_TRUE(a.feed(1, VmStage::Write, 5));  // pid 1 completes independently
}

TEST(VmStaging, ReAllocResetsProgress)
{
    StagingAssembler a;
    EXPECT_FALSE(a.feed(9, VmStage::Alloc, 0));
    EXPECT_FALSE(a.feed(9, VmStage::Protect, 1));
    // A fresh Alloc resets progress back to stage 1; a following Write is not complete.
    EXPECT_FALSE(a.feed(9, VmStage::Alloc, 2));
    EXPECT_FALSE(a.feed(9, VmStage::Write, 3));
}

// ---- Residency burst (signal 65) ------------------------------------------

TEST(VmResidency, BurstWithNoCpuIsForeign)
{
    ResidencyBurstInput in{};
    in.newly_resident_pages = 200;
    in.owning_cpu_delta_ns = 0;
    in.cpu_delta_valid = true;
    in.burst_threshold = 64;
    EXPECT_TRUE(residency_burst_is_foreign(in));
}

TEST(VmResidency, BurstWithGameCpuIsNotForeign)
{
    ResidencyBurstInput in{};
    in.newly_resident_pages = 200;
    in.owning_cpu_delta_ns = 5'000'000; // game's own threads ran
    in.cpu_delta_valid = true;
    in.burst_threshold = 64;
    EXPECT_FALSE(residency_burst_is_foreign(in));
}

TEST(VmResidency, NoCpuBaselineDefersToKernel)
{
    ResidencyBurstInput in{};
    in.newly_resident_pages = 200;
    in.owning_cpu_delta_ns = 0;
    in.cpu_delta_valid = false; // no baseline -> never attribute foreign
    in.burst_threshold = 64;
    EXPECT_FALSE(residency_burst_is_foreign(in));
}

TEST(VmResidency, BelowThresholdNotABurst)
{
    ResidencyBurstInput in{};
    in.newly_resident_pages = 10;
    in.owning_cpu_delta_ns = 0;
    in.cpu_delta_valid = true;
    in.burst_threshold = 64;
    EXPECT_FALSE(residency_burst_is_foreign(in));
}

// ---- Foreign holder (signal 70) -------------------------------------------

TEST(VmHolder, ForeignVmReadHolderIsDangerous)
{
    ForeignHolderInput in{};
    in.owner_pid = 1234;
    in.game_pid = 7;
    in.granted_access = kProcVmRead;
    in.owner_signed = false;
    uint32_t flags = 0;
    EXPECT_TRUE(holder_is_dangerous(in, &flags));
    EXPECT_NE(flags & kHndDangerousRights, 0u);
    EXPECT_NE(flags & kHndUnsignedOwner, 0u);
}

TEST(VmHolder, OwnHandleIsNeverForeign)
{
    ForeignHolderInput in{};
    in.owner_pid = 7;
    in.game_pid = 7;
    in.granted_access = kProcVmRead | kProcVmWrite;
    uint32_t flags = 0xFFFF;
    EXPECT_FALSE(holder_is_dangerous(in, &flags));
    EXPECT_EQ(flags, 0u);
}

TEST(VmHolder, SignedAllowlistedOwnerExempt)
{
    ForeignHolderInput in{};
    in.owner_pid = 99;
    in.game_pid = 7;
    in.granted_access = kProcVmRead;
    in.owner_signed = true;
    in.owner_allowlisted = true;
    uint32_t flags = 0;
    EXPECT_FALSE(holder_is_dangerous(in, &flags));
}

TEST(VmHolder, NoDangerousRightsDoesNotFire)
{
    ForeignHolderInput in{};
    in.owner_pid = 99;
    in.game_pid = 7;
    in.granted_access = 0x00100000; // SYNCHRONIZE, no VM rights
    uint32_t flags = 0;
    EXPECT_FALSE(holder_is_dangerous(in, &flags));
}

// ---- Protect drift (signal 71) --------------------------------------------

TEST(VmProtect, RwxOnShippedExecIsDrift)
{
    ProtectDriftInput in{};
    in.live_protect = kPageExecuteReadWrite;
    in.section_flags = kScnMemExecute | kScnMemRead; // shipped RX
    uint32_t flags = 0;
    EXPECT_TRUE(protect_is_drift(in, &flags));
    EXPECT_NE(flags & kProtWxOnShipped, 0u);
}

TEST(VmProtect, RwxOnSectionShippedWritableIsNotDrift)
{
    ProtectDriftInput in{};
    in.live_protect = kPageExecuteReadWrite;
    in.section_flags = kScnMemExecute | kScnMemRead | kScnMemWrite; // shipped writable
    uint32_t flags = 0;
    EXPECT_FALSE(protect_is_drift(in, &flags)); // no W^X expectation to violate
}

TEST(VmProtect, RxOnShippedExecIsNotDrift)
{
    ProtectDriftInput in{};
    in.live_protect = 0x20; // PAGE_EXECUTE_READ
    in.section_flags = kScnMemExecute | kScnMemRead;
    uint32_t flags = 0;
    EXPECT_FALSE(protect_is_drift(in, &flags));
}

TEST(VmProtect, NonExecSectionNeverDrifts)
{
    ProtectDriftInput in{};
    in.live_protect = kPageExecuteReadWrite;
    in.section_flags = 0; // not in a tracked +X section
    uint32_t flags = 0;
    EXPECT_FALSE(protect_is_drift(in, &flags));
}
