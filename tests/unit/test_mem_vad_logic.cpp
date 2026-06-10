/*
 * tests/unit/test_mem_vad_logic.cpp
 * Role: Host-buildable unit tests for the VAD-walk pure decision cores
 *       (kernel/win/include/mem_logic_vad.h, signals 10/14/15). Exercises the
 *       structural classifiers with synthetic HK_VAD_NODE fixtures — no WDK, no
 *       live process, no VAD tree, no OS API. Proves the unbacked-+X match, the
 *       private-exec commit sum, the exotic-VadType branch, the JIT-owner
 *       suppression, and the region-flags mapping.
 * Target platforms: host (any).
 * Interface: exercises hk_mem_is_unbacked_exec / hk_mem_sum_private_exec_bytes /
 *            hk_mem_is_exotic_exec / hk_mem_region_flags.
 */

#include <gtest/gtest.h>

#include "mem_logic_vad.h"

namespace {

HK_VAD_NODE MakeNode(uint32_t vad_type, uint32_t protection,
                     uint32_t has_control_area, uint32_t large_page,
                     uint32_t has_jit_owner, uint64_t size)
{
    HK_VAD_NODE n;
    n.region_base = 0x10000;
    n.region_size = size;
    n.vad_type = vad_type;
    n.protection = protection;
    n.has_control_area = has_control_area;
    n.large_page = large_page;
    n.has_jit_owner = has_jit_owner;
    n.reserved = 0;
    return n;
}

} // namespace

TEST(MemVadLogic, UnbackedExecIsFlagged)
{
    HK_VAD_NODE n = MakeNode(HK_MEM_VAD_NONE, HK_MEM_PROT_EXECUTE | HK_MEM_PROT_READ,
                             /*has_control_area=*/0, 0, 0, 0x1000);
    EXPECT_EQ(hk_mem_is_unbacked_exec(&n), 1);
}

TEST(MemVadLogic, FileBackedExecIsNotFlagged)
{
    /* A real module: executable but file-backed (has a ControlArea). */
    HK_VAD_NODE n = MakeNode(HK_MEM_VAD_IMAGE, HK_MEM_PROT_EXECUTE | HK_MEM_PROT_READ,
                             /*has_control_area=*/1, 0, 0, 0x4000);
    EXPECT_EQ(hk_mem_is_unbacked_exec(&n), 0);
}

TEST(MemVadLogic, NonExecUnbackedIsNotFlagged)
{
    HK_VAD_NODE n = MakeNode(HK_MEM_VAD_NONE, HK_MEM_PROT_READ | HK_MEM_PROT_WRITE,
                             /*has_control_area=*/0, 0, 0, 0x1000);
    EXPECT_EQ(hk_mem_is_unbacked_exec(&n), 0);
}

TEST(MemVadLogic, PrivateExecBytesSummedAcrossArray)
{
    HK_VAD_NODE nodes[4] = {
        MakeNode(HK_MEM_VAD_NONE, HK_MEM_PROT_EXECUTE, 0, 0, 0, 0x1000), /* counts */
        MakeNode(HK_MEM_VAD_NONE, HK_MEM_PROT_READ, 0, 0, 0, 0x8000),    /* not +X */
        MakeNode(HK_MEM_VAD_IMAGE, HK_MEM_PROT_EXECUTE, 1, 0, 0, 0x9000),/* not private */
        MakeNode(HK_MEM_VAD_NONE, HK_MEM_PROT_EXECUTE, 0, 0, 0, 0x2000), /* counts */
    };
    EXPECT_EQ(hk_mem_sum_private_exec_bytes(nodes, 4), 0x3000u);
}

TEST(MemVadLogic, PrivateExecSumEmptyIsZero)
{
    EXPECT_EQ(hk_mem_sum_private_exec_bytes(nullptr, 0), 0u);
    HK_VAD_NODE none = MakeNode(HK_MEM_VAD_NONE, HK_MEM_PROT_READ, 0, 0, 0, 0x1000);
    EXPECT_EQ(hk_mem_sum_private_exec_bytes(&none, 1), 0u);
}

TEST(MemVadLogic, ExoticExecByVadType)
{
    HK_VAD_NODE awe = MakeNode(HK_MEM_VAD_AWE, HK_MEM_PROT_EXECUTE, 0, 0, 0, 0x1000);
    HK_VAD_NODE rot = MakeNode(HK_MEM_VAD_ROTATE, HK_MEM_PROT_EXECUTE, 0, 0, 0, 0x1000);
    HK_VAD_NODE lp = MakeNode(HK_MEM_VAD_LARGE_PAGES, HK_MEM_PROT_EXECUTE, 0, 0, 0, 0x1000);
    EXPECT_EQ(hk_mem_is_exotic_exec(&awe), 1);
    EXPECT_EQ(hk_mem_is_exotic_exec(&rot), 1);
    EXPECT_EQ(hk_mem_is_exotic_exec(&lp), 1);
}

TEST(MemVadLogic, ExoticExecByLargePageFlag)
{
    HK_VAD_NODE n = MakeNode(HK_MEM_VAD_NONE, HK_MEM_PROT_EXECUTE,
                             0, /*large_page=*/1, 0, 0x200000);
    EXPECT_EQ(hk_mem_is_exotic_exec(&n), 1);
}

TEST(MemVadLogic, JitOwnerSuppressesExotic)
{
    /* A V8/CLR large-page +X region: annotated has_jit_owner, must NOT be flagged
     * exotic (the legitimate FP the catalog calls out). */
    HK_VAD_NODE n = MakeNode(HK_MEM_VAD_LARGE_PAGES, HK_MEM_PROT_EXECUTE,
                             0, 1, /*has_jit_owner=*/1, 0x200000);
    EXPECT_EQ(hk_mem_is_exotic_exec(&n), 0);
}

TEST(MemVadLogic, NonExecExoticIsNotFlagged)
{
    HK_VAD_NODE n = MakeNode(HK_MEM_VAD_LARGE_PAGES, HK_MEM_PROT_READ, 0, 1, 0, 0x200000);
    EXPECT_EQ(hk_mem_is_exotic_exec(&n), 0);
}

TEST(MemVadLogic, RegionFlagsMapsAnnotations)
{
    HK_VAD_NODE n = MakeNode(HK_MEM_VAD_NONE, HK_MEM_PROT_EXECUTE,
                             /*has_control_area=*/0, /*large_page=*/1,
                             /*has_jit_owner=*/1, 0x1000);
    uint32_t f = hk_mem_region_flags(&n);
    EXPECT_TRUE(f & HK_MEM_REGION_FLAG_UNBACKED);
    EXPECT_TRUE(f & HK_MEM_REGION_FLAG_LARGE_PAGE);
    EXPECT_TRUE(f & HK_MEM_REGION_FLAG_HAS_JIT_OWNER);
}

TEST(MemVadLogic, NullNodeIsNoSignal)
{
    EXPECT_EQ(hk_mem_is_unbacked_exec(nullptr), 0);
    EXPECT_EQ(hk_mem_is_exotic_exec(nullptr), 0);
    EXPECT_EQ(hk_mem_region_flags(nullptr), 0u);
}
