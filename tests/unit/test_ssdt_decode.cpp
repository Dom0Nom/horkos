/*
 * Role: Host-buildable unit tests for the pure x64 SSDT packed-offset decoder
 *       (kernel/win/include/ssdt_decode.h, signal 35). Proves the encoding math
 *       against known-encoded values: positive offset, negative (sign-extended)
 *       offset, the arg-count nibble is stripped from the address, and a target
 *       round-trips back to its raw entry. No WDK / kernel needed — the decoder is
 *       pure arithmetic.
 * Target platforms: host (any).
 * Interface: exercises HkSsdtDecodeTarget / HkSsdtArgCount.
 */

#include <gtest/gtest.h>

#include "ssdt_decode.h"

namespace {

// Encode a target back to its raw x64 KiServiceTable entry form, given the table
// base and an argument-count nibble. Inverse of HkSsdtDecodeTarget; used to build
// fixtures from intended targets.
uint32_t EncodeEntry(uint64_t target, uint64_t table_base, uint32_t arg_nibble)
{
    int64_t offset = static_cast<int64_t>(target) - static_cast<int64_t>(table_base);
    uint32_t raw = (static_cast<uint32_t>(static_cast<int32_t>(offset)) << 4) |
                   (arg_nibble & 0xFu);
    return raw;
}

} // namespace

TEST(SsdtDecode, PositiveOffsetResolvesAbove)
{
    const uint64_t base = 0xFFFFF80000000000ull;
    const uint64_t target = base + 0x10000; // 64KB above the table base
    uint32_t raw = EncodeEntry(target, base, 4);
    EXPECT_EQ(HkSsdtDecodeTarget(raw, base), target);
    EXPECT_EQ(HkSsdtArgCount(raw), 4u);
}

TEST(SsdtDecode, NegativeOffsetIsSignExtended)
{
    const uint64_t base = 0xFFFFF80000100000ull;
    const uint64_t target = base - 0x8000; // 32KB BELOW the table base
    uint32_t raw = EncodeEntry(target, base, 2);
    // The decode must sign-extend the 28-bit offset so a below-base target
    // resolves correctly (arithmetic shift on the signed value).
    EXPECT_EQ(HkSsdtDecodeTarget(raw, base), target);
}

TEST(SsdtDecode, ArgNibbleDoesNotAffectAddress)
{
    const uint64_t base = 0xFFFFF80000000000ull;
    const uint64_t target = base + 0x2000;
    // Same offset, two different arg-count nibbles => identical decoded target.
    uint32_t raw0 = EncodeEntry(target, base, 0);
    uint32_t rawF = EncodeEntry(target, base, 0xF);
    EXPECT_EQ(HkSsdtDecodeTarget(raw0, base), target);
    EXPECT_EQ(HkSsdtDecodeTarget(rawF, base), target);
    EXPECT_EQ(HkSsdtArgCount(raw0), 0u);
    EXPECT_EQ(HkSsdtArgCount(rawF), 0xFu);
}

TEST(SsdtDecode, ZeroOffsetResolvesToBase)
{
    const uint64_t base = 0xFFFFF80012345670ull;
    uint32_t raw = EncodeEntry(base, base, 3);
    EXPECT_EQ(HkSsdtDecodeTarget(raw, base), base);
    EXPECT_EQ(HkSsdtArgCount(raw), 3u);
}

TEST(SsdtDecode, KnownEncodedValue)
{
    // A concrete known entry: offset 0x12340 (>>4 of 0x123400), 4 args.
    // raw = (0x12340 << 4) | 4 = 0x123404.
    const uint64_t base = 0xFFFFF80000000000ull;
    uint32_t raw = 0x00123404u;
    EXPECT_EQ(HkSsdtArgCount(raw), 4u);
    EXPECT_EQ(HkSsdtDecodeTarget(raw, base), base + 0x12340);
}
