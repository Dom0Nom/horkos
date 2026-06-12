/*
 * Role: Pure, platform-free classifiers for the VAD-walk memory signals 10
 *       (unbacked executable region), 14 (oversized private executable commit),
 *       and 15 (exotic VadType / large-page executable). Each is structural
 *       arithmetic over an already-normalized HK_VAD_NODE; no kernel/Win32 API,
 *       so the decision logic is unit-tested on the host build
 *       (tests/unit/test_mem_vad_logic.cpp) without a WDK — the plan's "factor
 *       the FP-free decision logic out of the kernel TUs into pure functions"
 *       requirement. The kernel sampler (MemScanVad.c) feeds these the nodes from
 *       VadWalk.c and emits the raw classification; NONE of these decide a ban —
 *       the client emits, the server fuses and decides.
 *       READ-ONLY: classifies observed state; mutates nothing.
 * Target platforms: all (decision math; the VAD walk that fills the nodes is
 *       Win-kernel-only).
 * Interface: consumed by kernel/win/src/MemScanVad.c.
 */

#pragma once

#include <stdint.h>

#include "mem_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* True if the leaf is executable. */
static inline int hk_mem_node_is_exec(const HK_VAD_NODE *node)
{
    if (node == 0) {
        return 0;
    }
    return (node->protection & HK_MEM_PROT_EXECUTE) != 0u ? 1 : 0;
}

/*
 * Signal 10 — unbacked executable region: executable AND no ControlArea/
 * FilePointer backing it. A file/section-backed executable mapping (a real
 * module) is normal; an executable region with no backing is the manual-map /
 * private-shellcode shape the catalog targets. Raw structural match only.
 */
static inline int hk_mem_is_unbacked_exec(const HK_VAD_NODE *node)
{
    if (node == 0) {
        return 0;
    }
    return (hk_mem_node_is_exec(node) && node->has_control_area == 0u) ? 1 : 0;
}

/*
 * Signal 14 helper — a single private (VadNone) executable region. The sampler
 * emits each such region's size and the process-wide aggregate; no hard kernel
 * threshold (the server baselines per title).
 */
static inline int hk_mem_is_private_exec(const HK_VAD_NODE *node)
{
    if (node == 0) {
        return 0;
    }
    return (node->vad_type == HK_MEM_VAD_NONE && hk_mem_node_is_exec(node)) ? 1 : 0;
}

/*
 * Signal 14 — sum committed bytes across all private executable regions in the
 * node array. Bounded loop; a NULL/empty array yields 0 (defined no-signal).
 */
static inline uint64_t hk_mem_sum_private_exec_bytes(const HK_VAD_NODE *nodes,
                                                     uint32_t count)
{
    uint64_t total = 0;
    uint32_t i;
    if (nodes == 0) {
        return 0;
    }
    for (i = 0; i < count; ++i) {
        if (hk_mem_is_private_exec(&nodes[i])) {
            total += nodes[i].region_size;
        }
    }
    return total;
}

/*
 * Signal 15 — exotic executable region: an AWE / rotate-physical / large-page
 * region (by normalized VadType or the large-page flag) that is executable and
 * NOT owned by a known JIT module. Games lack SeLockMemoryPrivilege, so an
 * executable large-page/AWE region is a strong structural anomaly. has_jit_owner
 * suppresses it (the legitimate FP); the server still gets the raw annotation.
 */
static inline int hk_mem_is_exotic_exec(const HK_VAD_NODE *node)
{
    int exotic_type;
    if (node == 0) {
        return 0;
    }
    if (!hk_mem_node_is_exec(node)) {
        return 0;
    }
    if (node->has_jit_owner != 0u) {
        return 0;
    }
    exotic_type = (node->vad_type == HK_MEM_VAD_AWE ||
                   node->vad_type == HK_MEM_VAD_ROTATE ||
                   node->vad_type == HK_MEM_VAD_LARGE_PAGES ||
                   node->large_page != 0u)
                      ? 1
                      : 0;
    return exotic_type;
}

/*
 * Build the hk_mem_region.flags wire mask for a node. Pure mapping; the sampler
 * copies this into the emitted region descriptor so the server sees the raw
 * structural annotations (unbacked / large-page / JIT-owned).
 */
static inline uint32_t hk_mem_region_flags(const HK_VAD_NODE *node)
{
    uint32_t flags = 0u;
    if (node == 0) {
        return 0u;
    }
    if (hk_mem_is_unbacked_exec(node)) {
        flags |= HK_MEM_REGION_FLAG_UNBACKED;
    }
    if (node->large_page != 0u || node->vad_type == HK_MEM_VAD_LARGE_PAGES) {
        flags |= HK_MEM_REGION_FLAG_LARGE_PAGE;
    }
    if (node->has_jit_owner != 0u) {
        flags |= HK_MEM_REGION_FLAG_HAS_JIT_OWNER;
    }
    return flags;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
