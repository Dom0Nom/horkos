/*
 * Role: Host-buildable unit tests for the loader/image pure decision cores
 *       (kernel/win/include/mem_logic_image.h, signals 13/16/17). Exercises the
 *       ghost-image cross-check, the hollow-backing combination gate, and the
 *       exec-origin anon classifier with synthetic inputs — no WDK, no PEB, no OS
 *       API. Proves the FP guards (a normally-loaded module is not a ghost; a
 *       single backing anomaly does not flag hollow; a JIT origin is suppressed).
 * Target platforms: host (any).
 * Interface: exercises hk_mem_is_ghost / hk_mem_is_hollow / hk_mem_origin_is_anon.
 */

#include <gtest/gtest.h>

#include "mem_logic_image.h"

TEST(MemImageLogic, GhostWhenAbsentFromAllLists)
{
    uint64_t load[] = {0x1000, 0x2000};
    uint64_t mem[] = {0x1000, 0x2000};
    uint64_t init[] = {0x1000, 0x2000};
    EXPECT_EQ(hk_mem_is_ghost(0x9000, load, 2, mem, 2, init, 2), 1);
}

TEST(MemImageLogic, NotGhostWhenPresentInAnyList)
{
    uint64_t load[] = {0x1000};
    uint64_t mem[] = {0x2000};
    uint64_t init[] = {0x9000}; /* present here only — still not a ghost. */
    EXPECT_EQ(hk_mem_is_ghost(0x9000, load, 1, mem, 1, init, 1), 0);
}

TEST(MemImageLogic, GhostWithEmptyListsIsFlagged)
{
    /* All lists empty (e.g. a freshly torn-down view): a present base cannot be
     * matched, so it reads as ghost — the caller is required to skip exiting
     * processes before calling, which is where teardown races are excluded. */
    EXPECT_EQ(hk_mem_is_ghost(0x9000, nullptr, 0, nullptr, 0, nullptr, 0), 1);
}

TEST(MemImageLogic, HollowRequiresExecEntryAndAnomaly)
{
    /* exec + entry-point region + name mismatch => hollow. */
    EXPECT_EQ(hk_mem_is_hollow(/*exec=*/1, /*entry=*/1, /*del=*/0, /*tx=*/0, /*nm=*/1), 1);
    /* exec + entry + delete-pending => hollow. */
    EXPECT_EQ(hk_mem_is_hollow(1, 1, 1, 0, 0), 1);
    /* exec + entry + transacted => hollow. */
    EXPECT_EQ(hk_mem_is_hollow(1, 1, 0, 1, 0), 1);
}

TEST(MemImageLogic, HollowSingleSignalIsNotFlagged)
{
    /* A backing anomaly with no executable entry-point region is benign
     * (transacted installers, name quirks). */
    EXPECT_EQ(hk_mem_is_hollow(/*exec=*/0, /*entry=*/0, /*del=*/0, /*tx=*/1, /*nm=*/0), 0);
    /* Executable entry-point region with NO backing anomaly is a normal module. */
    EXPECT_EQ(hk_mem_is_hollow(1, 1, 0, 0, 0), 0);
    /* Name mismatch but not the entry-point region: not the hollow shape. */
    EXPECT_EQ(hk_mem_is_hollow(1, 0, 0, 0, 1), 0);
}

TEST(MemImageLogic, HollowFlagsMaskIsComplete)
{
    uint32_t f = hk_mem_hollow_flags(/*exec=*/1, /*entry=*/1, /*del=*/1, /*tx=*/0,
                                     /*nm=*/1, /*jit=*/0);
    EXPECT_TRUE(f & HK_MEM_IMG_FLAG_HOLLOW);
    EXPECT_TRUE(f & HK_MEM_IMG_FLAG_EXEC);
    EXPECT_TRUE(f & HK_MEM_IMG_FLAG_ENTRY_REGION);
    EXPECT_TRUE(f & HK_MEM_IMG_FLAG_DELETE_PENDING);
    EXPECT_TRUE(f & HK_MEM_IMG_FLAG_NAME_MISMATCH);
    EXPECT_FALSE(f & HK_MEM_IMG_FLAG_TRANSACTED);
    EXPECT_FALSE(f & HK_MEM_IMG_FLAG_HAS_JIT_OWNER);
}

TEST(MemImageLogic, OriginAnonWhenPrivate)
{
    EXPECT_EQ(hk_mem_origin_is_anon(HK_MEM_VAD_NONE, /*has_jit_owner=*/0), 1);
}

TEST(MemImageLogic, OriginNotAnonWhenImageBacked)
{
    EXPECT_EQ(hk_mem_origin_is_anon(HK_MEM_VAD_IMAGE, 0), 0);
}

TEST(MemImageLogic, OriginJitOwnerSuppressed)
{
    /* A JIT legitimately starts a thread in generated private code. */
    EXPECT_EQ(hk_mem_origin_is_anon(HK_MEM_VAD_NONE, /*has_jit_owner=*/1), 0);
}
