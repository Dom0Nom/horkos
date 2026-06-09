/*
 * tests/unit/test_module_map_resolve.cpp
 * Role: Host-buildable unit tests for the pure loaded-module address-range
 *       resolver (kernel/win/include/module_map_resolve.h, shared by integrity
 *       signals 29/31/32/34/35). Proves the lookup math: address inside one
 *       range, address in a gap, the half-open base+size EXCLUSIVE boundary, an
 *       empty map, the signed-module gate, and overflow safety at the top of the
 *       address space. No WDK / kernel needed — the resolver is plain C99.
 * Target platforms: host (any).
 * Interface: exercises HkModuleRangeResolve / HkModuleRangeContains /
 *       HkModuleRangeContainsSigned against fixture ranges.
 */

#include <gtest/gtest.h>

#include "module_map_resolve.h"

namespace {

hk_module_range MakeRange(uint64_t base, uint64_t size, uint32_t index,
                          uint32_t flags)
{
    hk_module_range r{};
    r.base = base;
    r.size = size;
    r.index = index;
    r.flags = flags;
    return r;
}

} // namespace

TEST(ModuleMapResolve, AddressInsideSingleRange)
{
    hk_module_range ranges[] = {MakeRange(0x1000, 0x2000, 0, 0)};
    EXPECT_EQ(HkModuleRangeResolve(ranges, 1, 0x1000), 0u); // at base
    EXPECT_EQ(HkModuleRangeResolve(ranges, 1, 0x2FFF), 0u); // last byte
    EXPECT_TRUE(HkModuleRangeContains(ranges, 1, 0x1500));
}

TEST(ModuleMapResolve, BasePlusSizeIsExclusive)
{
    hk_module_range ranges[] = {MakeRange(0x1000, 0x1000, 0, 0)};
    // 0x2000 == base+size is the first byte NOT in the range (half-open).
    EXPECT_EQ(HkModuleRangeResolve(ranges, 1, 0x2000), HK_MODRANGE_NONE);
    EXPECT_EQ(HkModuleRangeResolve(ranges, 1, 0x1FFF), 0u);
}

TEST(ModuleMapResolve, AddressInGapResolvesNone)
{
    hk_module_range ranges[] = {
        MakeRange(0x1000, 0x1000, 0, 0),
        MakeRange(0x5000, 0x1000, 1, 0),
    };
    EXPECT_EQ(HkModuleRangeResolve(ranges, 2, 0x3000), HK_MODRANGE_NONE);
    EXPECT_FALSE(HkModuleRangeContains(ranges, 2, 0x0FFF)); // below first
    EXPECT_EQ(HkModuleRangeResolve(ranges, 2, 0x5500), 1u); // in second
}

TEST(ModuleMapResolve, EmptyMapResolvesNone)
{
    EXPECT_EQ(HkModuleRangeResolve(nullptr, 0, 0x1000), HK_MODRANGE_NONE);
    hk_module_range ranges[] = {MakeRange(0x1000, 0x1000, 0, 0)};
    EXPECT_EQ(HkModuleRangeResolve(ranges, 0, 0x1500), HK_MODRANGE_NONE);
}

TEST(ModuleMapResolve, ZeroSizeRangeContainsNothing)
{
    hk_module_range ranges[] = {MakeRange(0x1000, 0, 0, 0)};
    EXPECT_EQ(HkModuleRangeResolve(ranges, 1, 0x1000), HK_MODRANGE_NONE);
}

TEST(ModuleMapResolve, SignedGateOnlyMatchesSignedModule)
{
    hk_module_range ranges[] = {
        MakeRange(0x1000, 0x1000, 0, 0),                          // unsigned
        MakeRange(0x5000, 0x1000, 1, HK_MODRANGE_FLAG_SIGNED),    // signed
    };
    // In the unsigned range: contained, but not signed-contained.
    EXPECT_TRUE(HkModuleRangeContains(ranges, 2, 0x1500));
    EXPECT_FALSE(HkModuleRangeContainsSigned(ranges, 2, 0x1500));
    // In the signed range: both.
    EXPECT_TRUE(HkModuleRangeContainsSigned(ranges, 2, 0x5500));
    // In a gap: neither.
    EXPECT_FALSE(HkModuleRangeContainsSigned(ranges, 2, 0x3000));
}

TEST(ModuleMapResolve, OverflowAtTopOfAddressSpace)
{
    // A module mapped near UINT64_MAX whose base+size would wrap. The resolver
    // must still resolve its own bytes (it compares addr-base < size, never
    // forming base+size).
    const uint64_t base = 0xFFFFFFFFFFFFF000ull;
    hk_module_range ranges[] = {MakeRange(base, 0x1000, 0, 0)};
    EXPECT_EQ(HkModuleRangeResolve(ranges, 1, base), 0u);
    EXPECT_EQ(HkModuleRangeResolve(ranges, 1, 0xFFFFFFFFFFFFFFFFull), 0u);
}

TEST(ModuleMapResolve, FirstMatchWinsOnOverlap)
{
    // Overlapping ranges [0x1000,0x3000) and [0x2000,0x4000): 0x2500 falls in
    // BOTH; the resolver returns the FIRST matching index (0). 0x3500 is only in
    // the second.
    hk_module_range ranges[] = {
        MakeRange(0x1000, 0x2000, 0, 0),
        MakeRange(0x2000, 0x2000, 1, 0),
    };
    EXPECT_EQ(HkModuleRangeResolve(ranges, 2, 0x2500), 0u); // in both -> first wins
    EXPECT_EQ(HkModuleRangeResolve(ranges, 2, 0x3500), 1u); // only in second
    EXPECT_EQ(HkModuleRangeResolve(ranges, 2, 0x1500), 0u); // only in first
}
