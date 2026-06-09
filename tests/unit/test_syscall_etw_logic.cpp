/*
 * tests/unit/test_syscall_etw_logic.cpp
 * Role: Host-buildable unit tests for the pure syscall-/ETW-surface decision math
 *       (kernel/win/include/syscall_etw_logic.h, signals 210/212/214/215). Proves:
 *       IDT 64-bit handler reconstruction from the three split offset fields; the
 *       LSTAR expected-value KVA-shadow selector (incl. the unresolved-candidate
 *       => 0 path); the ETW-TI keepalive staleness predicate (no advance, below
 *       floor, wrap-as-advance); and the ETW provider-suppression diff incl. the
 *       FP gate that a NON-dependency disable does NOT alert. No WDK / kernel
 *       needed — the header is pure arithmetic.
 * Target platforms: host (any).
 * Interface: exercises HkIdtReconstructHandler / HkLstarExpected /
 *       HkKeepaliveStale / HkEtwProviderSuppressed.
 */

#include <gtest/gtest.h>

#include "syscall_etw_logic.h"

// ---- Signal 214: IDT handler reconstruction --------------------------------

TEST(SyscallEtwLogic, IdtReconstructFullAddress)
{
    // Handler 0xFFFFF80312345678: low=0x5678, middle=0x1234, high=0xFFFFF803.
    uint64_t h = HkIdtReconstructHandler(0x5678, 0x1234, 0xFFFFF803u);
    EXPECT_EQ(h, 0xFFFFF80312345678ull);
}

TEST(SyscallEtwLogic, IdtReconstructZeroIsZero)
{
    EXPECT_EQ(HkIdtReconstructHandler(0, 0, 0), 0ull);
}

TEST(SyscallEtwLogic, IdtReconstructHighHalfOnly)
{
    // Only the high dword set => address in the top 32 bits.
    EXPECT_EQ(HkIdtReconstructHandler(0, 0, 0x00000001u), 0x0000000100000000ull);
}

// ---- Signal 210: LSTAR expected-value selection ----------------------------

TEST(SyscallEtwLogic, LstarPicksShadowUnderKvaShadow)
{
    const uint64_t normal = 0xFFFFF80300010000ull;
    const uint64_t shadow = 0xFFFFF80300020000ull;
    EXPECT_EQ(HkLstarExpected(normal, shadow, /*kva*/ 1), shadow);
    EXPECT_EQ(HkLstarExpected(normal, shadow, /*kva*/ 0), normal);
}

TEST(SyscallEtwLogic, LstarUnresolvedCandidateIsZero)
{
    // Unresolved => 0; the caller must treat 0 as UNVERIFIABLE, not a mismatch.
    EXPECT_EQ(HkLstarExpected(0, 0xDEAD, /*kva*/ 0), 0ull);
    EXPECT_EQ(HkLstarExpected(0xBEEF, 0, /*kva*/ 1), 0ull);
}

// ---- Signal 212: keepalive staleness ---------------------------------------

TEST(SyscallEtwLogic, KeepaliveNoAdvanceIsStale)
{
    EXPECT_EQ(HkKeepaliveStale(100, 100, /*min*/ 0), 1);
}

TEST(SyscallEtwLogic, KeepaliveAnyAdvanceWithZeroFloorIsAlive)
{
    EXPECT_EQ(HkKeepaliveStale(100, 101, /*min*/ 0), 0);
}

TEST(SyscallEtwLogic, KeepaliveBelowFloorIsStale)
{
    // Advanced by 2 but floor is 5 => stale.
    EXPECT_EQ(HkKeepaliveStale(100, 102, /*min*/ 5), 1);
    // Advanced by 5 meeting the floor => alive.
    EXPECT_EQ(HkKeepaliveStale(100, 105, /*min*/ 5), 0);
}

TEST(SyscallEtwLogic, KeepaliveWrapIsTreatedAsAdvance)
{
    // Counter wrapped across UINT64_MAX: now < last but the unsigned delta is
    // positive (== 5), so with floor 0 it is alive, not stale.
    const uint64_t last = 0xFFFFFFFFFFFFFFFEull;
    const uint64_t now = 0x0000000000000003ull; // wrapped, delta == 5
    EXPECT_EQ(HkKeepaliveStale(last, now, /*min*/ 0), 0);
    EXPECT_EQ(HkKeepaliveStale(last, now, /*min*/ 10), 1); // below floor 10
}

// ---- Signal 215: provider-suppression diff + FP gate -----------------------

namespace {
constexpr uint32_t NT_KERNEL = 0x00000001u;
constexpr uint32_t THREAT_INTEL = 0x00000002u;
constexpr uint32_t DEP_MASK = NT_KERNEL | THREAT_INTEL;
} // namespace

TEST(SyscallEtwLogic, SuppressedDependencyProviderIsReported)
{
    // Both enabled at boot; ETW-TI now disabled => suppressed bit == THREAT_INTEL.
    uint32_t s = HkEtwProviderSuppressed(DEP_MASK, NT_KERNEL, DEP_MASK);
    EXPECT_EQ(s, THREAT_INTEL);
}

TEST(SyscallEtwLogic, NonDependencyDisableDoesNotAlert)
{
    // A profiling provider (bit 0x10) was enabled at boot and is now off, but it is
    // NOT in the dependency set => the diff must be empty (the FP gate).
    constexpr uint32_t PROFILING = 0x00000010u;
    uint32_t baseline = DEP_MASK | PROFILING;
    uint32_t current = DEP_MASK; // profiling stopped, deps still up
    EXPECT_EQ(HkEtwProviderSuppressed(baseline, current, DEP_MASK), 0u);
}

TEST(SyscallEtwLogic, NoChangeYieldsNoSuppression)
{
    EXPECT_EQ(HkEtwProviderSuppressed(DEP_MASK, DEP_MASK, DEP_MASK), 0u);
}

TEST(SyscallEtwLogic, NewlyEnabledProviderIsNotSuppression)
{
    // current has MORE than baseline (a provider came up) => nothing suppressed.
    uint32_t baseline = NT_KERNEL;
    uint32_t current = DEP_MASK;
    EXPECT_EQ(HkEtwProviderSuppressed(baseline, current, DEP_MASK), 0u);
}
