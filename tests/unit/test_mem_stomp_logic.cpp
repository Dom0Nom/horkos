/*
 * Role: Host-buildable unit tests for the module-stomp section-diff core
 *       (kernel/win/include/mem_logic_stomp.h, signal 12). Drives the
 *       reloc/IAT-normalized comparison with synthetic section buffers — no WDK,
 *       no mapped module, no OS API. Proves the central FP guard (a section whose
 *       only differences are at relocation + IAT sites diffs CLEAN) and that a
 *       single stomped code byte outside those spans yields the correct
 *       first-diff RVA, plus the defined no-signal result on degenerate input.
 * Target platforms: host (any).
 * Interface: exercises hk_mem_first_diff_rva / hk_mem_offset_excluded.
 */

#include <gtest/gtest.h>

#include <vector>

#include "mem_logic_stomp.h"

namespace {

std::vector<uint8_t> Section(uint32_t len, uint8_t fill)
{
    return std::vector<uint8_t>(len, fill);
}

} // namespace

TEST(MemStompLogic, IdenticalSectionIsClean)
{
    auto disk = Section(256, 0x90);
    auto live = disk;
    EXPECT_EQ(hk_mem_first_diff_rva(disk.data(), live.data(), 256,
                                    nullptr, 0, nullptr, 0),
              -1);
}

TEST(MemStompLogic, RelocAndIatOnlyDiffsAreClean)
{
    auto disk = Section(256, 0xCC);
    auto live = disk;
    /* The loader rewrote an 8-byte relocation at RVA 32 and an IAT thunk range at
     * RVA 100..116. Make those bytes differ; everything else identical. */
    for (uint32_t i = 32; i < 40; ++i) live[i] = 0x11;
    for (uint32_t i = 100; i < 116; ++i) live[i] = 0x22;
    hk_byte_span reloc[] = {{32, 8}};
    hk_byte_span iat[] = {{100, 16}};
    EXPECT_EQ(hk_mem_first_diff_rva(disk.data(), live.data(), 256,
                                    reloc, 1, iat, 1),
              -1);
}

TEST(MemStompLogic, SingleStompedByteYieldsRva)
{
    auto disk = Section(256, 0xCC);
    auto live = disk;
    /* Legit reloc diff at 32 (excluded) AND a stomp at 200 (not excluded). */
    for (uint32_t i = 32; i < 40; ++i) live[i] = 0x11;
    live[200] = 0xE9; /* a planted jmp opcode outside any excluded span. */
    hk_byte_span reloc[] = {{32, 8}};
    EXPECT_EQ(hk_mem_first_diff_rva(disk.data(), live.data(), 256,
                                    reloc, 1, nullptr, 0),
              200);
}

TEST(MemStompLogic, FirstOfMultipleDiffsIsReported)
{
    auto disk = Section(256, 0x00);
    auto live = disk;
    live[150] = 0x01;
    live[60] = 0x02;
    EXPECT_EQ(hk_mem_first_diff_rva(disk.data(), live.data(), 256,
                                    nullptr, 0, nullptr, 0),
              60);
}

TEST(MemStompLogic, DegenerateInputIsNoSignal)
{
    auto buf = Section(16, 0xAA);
    EXPECT_EQ(hk_mem_first_diff_rva(nullptr, buf.data(), 16, nullptr, 0, nullptr, 0), -1);
    EXPECT_EQ(hk_mem_first_diff_rva(buf.data(), nullptr, 16, nullptr, 0, nullptr, 0), -1);
    EXPECT_EQ(hk_mem_first_diff_rva(buf.data(), buf.data(), 0, nullptr, 0, nullptr, 0), -1);
}

TEST(MemStompLogic, OffsetExcludedHelper)
{
    hk_byte_span spans[] = {{10, 4}, {100, 0} /* zero-len span ignored */};
    EXPECT_EQ(hk_mem_offset_excluded(10, spans, 2), 1);
    EXPECT_EQ(hk_mem_offset_excluded(13, spans, 2), 1);
    EXPECT_EQ(hk_mem_offset_excluded(14, spans, 2), 0); /* past the span. */
    EXPECT_EQ(hk_mem_offset_excluded(100, spans, 2), 0); /* zero-len excludes nothing. */
    EXPECT_EQ(hk_mem_offset_excluded(5, nullptr, 0), 0);
}
